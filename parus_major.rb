require 'buggery'
require 'thread'
require 'bindata'
require 'hexdump'
require 'trollop'
require 'pp'

require 'alpc'

include Buggery::Structs
include Buggery::Raw

# http://www.retrojunkie.com/asciiart/animals/greattit.htm
# gt = <<'eos'

#     ______  ___  ______ _   _ _____  ___  ___  ___     ___  ___________
#     | ___ \/ _ \ | ___ \ | | /  ___| |  \/  | / _ \   |_  ||  _  | ___ \
#     | |_/ / /_\ \| |_/ / | | \ `--.  | .  . |/ /_\ \    | || | | | |_/ /
#     |  __/|  _  ||    /| | | |`--. \ | |\/| ||  _  |    | || | | |    /
#     | |   | | | || |\ \| |_| /\__/ / | |  | || | | |/\__/ /\ \_/ / |\ \
#     \_|   \_| |_/\_| \_|\___/\____/  \_|  |_/\_| |_/\____/  \___/\_| \_|

#                          (c) @rantyben 2014



#                                                             ,-,
#                                                           ,',' `,
#               Great Tit                                 ,' , ,','
#                           or                          ,' ,'  ,'
#                                                     ,' ,', ,'
#                 Parus Major                       ,'  , ,,'
#                                                 ,' ,', ,'
#                                               ,' , , ,'
#                                           __,',___','
#                        __,,,,,,,------""""_    __,-"""""_`=--
#         _..---.____.--'''''''''''_,---'  _; --'  ___,-'___
#       ,':::::,--.::'''''' ''''''' ___,--'   __,-';    __,-""""
#      ;:::::,'   |::'' '''' '===)-' __; _,--'    ;---''
#     |:: @,'    ;:;\ ''''==== =),--'_,-'   ` )) ;
#     `:::'    _;:/  `._=== ===)_,-,-' `  )  `  ;
#      | ;--.;:::; `    `-._=_)_.-'   `  `  )  /`-._
#      '/       `-:.  `         `    `  ) )  ,'`-.. \
#                  `:_ `    `        )    _,'     | :
#                     `-._    `  _--  _,-'        | :
#                         `----..\  \'            | |
#                                _\  \            | :
#     _____  jrei           _,--'__,-'            : :      _______
#    ()___ '-------.....__,'_ --'___________ _,--'--\\-''''  _____
#         `-------.....______\\______ _________,--._-'---''''
#                         `=='
# eos

OPTS=Trollop::options do
  opt :port, "only fuzz messages on this ALPC port", type: :strings
  opt :src, "source pid ( fuzz messages arriving from this pid )", type: :integer
  opt :dst, "destination pid ( fuzz messages inside this pid )", type: :integer, required: true
  opt :fuzzfactor, "millerfuzz fuzzfactor ( bigger numbers less fuzzy)", type: :float, default: 20.0
  opt :barrier, "number of bytes after the PORT_MESSAGE header NOT to fuzz", type: :integer, default: 0
  opt :monitor, "monitor mode - don't fuzz, just dump traffic", type: :boolean
end

debugger = Buggery::Debugger.new
debugger.extend ALPC
target_hid = nil
target_port = OPTS[:port].join(' ') if OPTS[:port]
# Used to track per-thread which HID started the call to NtAlpcSendReceivePort
last_hid = {}

# purely for readability
HEADERSIZE = ALPC::PORT_MESSAGE_SIZE

def mark_changes hexdump, changes
  return hexdump if changes.empty?
  lines = hexdump.lines
  changes.each {|idx|
    #012345678 <- nine byte leadin
    #00000000  00 00 00 00 00 00 00 00 00 00 00 00 9f 00 00 00  |................|
    line = idx / 16
    pos = idx % 16
    lines[line][9 + pos*3] = '<'
    lines[line][9 + (pos+1)*3] = '>'
  }
  lines.join
end

# Output thread
mut = Mutex.new
logger = Queue.new
Thread.new do
  loop do

    begin
      s, changes = logger.pop
      m = ALPC::PORT_MESSAGE.read(s)
      payload = ""
      Hexdump.dump s[ALPC::PORT_MESSAGE_SIZE..-1], output: payload
      payload = mark_changes payload, changes

      mut.synchronize {
        puts '='*80
        puts
        puts "Type:     0x%x" % m.type
        puts "Process:  #{m.process}"
        puts "Thread:   #{m.thread}"
        puts "Id:       #{m.message_id}"
        puts
        puts payload
        puts
        $stdout.flush
      }
    rescue
      puts $!
      puts $@.join("\n")
    end
  end
end

def millerfuzz data

  # You could optimise slightly by corrupting the caller's data directly, but I
  # have been burnt too many times in the past.
  working_copy = data.clone

  fuzzed_bytes = (data.bytesize / OPTS[:fuzzfactor]).ceil
  fuzzed_bytes = 1 if fuzzed_bytes.zero?
  changed = []
  while working_copy == data
    changed.clear
    rand(1..fuzzed_bytes).times do
      idx = rand(data.bytesize)
      working_copy[idx] = rand(256).chr
      changed << idx
    end
  end

  if working_copy.bytesize != data.bytesize
    fail "Internal error: data size changed while fuzzing"
  end

  [working_copy, changed]

end

# shared, because the debugger itself is single threaded
pulong = FFI::MemoryPointer.new :ulong

# our callback, invoked at every breakpoint event
bp_proc = lambda {|args|

  begin

    bp = DebugBreakpoint3.new args[:breakpoint]
    bp.GetId pulong
    bpid = pulong.read_ulong

    debugger.raw.DebugSystemObjects.GetCurrentThreadId pulong
    tid = pulong.read_ulong

    # You could optimise this whole thing a bit by defining a different
    # callback for when no specific target port is given. In that case,
    # there's no need to parse the DebugBreakpoint3 struct, and no need to
    # break on the function entry.
    case bpid
    when 1 # NtAlpcSendWaitReceivePort entry

      last_hid[tid] = debugger.registers['rcx']

    when 2 # NtAlpcSendWaitReceivePort exit

      if OPTS[:port]
        return DebugControl::DEBUG_STATUS_GO unless last_hid[tid] == target_hid
      end

      p_msg = debugger.read_pointers( debugger.registers['rsp']+0x28 ).first
      return DebugControl::DEBUG_STATUS_GO if p_msg.null? # no receive buffer

      # get total length field at offset 2
      msg_offset = p_msg.address
      msg_len = debugger.read_virtual( msg_offset+2, 2 ).unpack('s').first

      if msg_len > HEADERSIZE + OPTS[:barrier]

        raw_msg = debugger.read_virtual msg_offset, msg_len
        pm = ALPC::PORT_MESSAGE.read(raw_msg)

        if OPTS[:src].nil? || pm.process == OPTS[:src]

          if OPTS[:monitor]
            logger.push [raw_msg,[]]
            return DebugControl::DEBUG_STATUS_GO
          end

          header   = raw_msg[0, HEADERSIZE]
          barrier  = raw_msg[HEADERSIZE, OPTS[:barrier]]
          fuzzable = raw_msg[HEADERSIZE+OPTS[:barrier] .. -1]
          fuzz, changed = millerfuzz(fuzzable)
          fuzzed = header << barrier << fuzz

          if fuzzed.bytesize != msg_len
            fail "Internal error: data size changed while fuzzing"
          end

          logger.push [fuzzed, changed]
          debugger.write_virtual msg_offset, fuzzed

        end

      end
    end

  rescue
    mut.synchronize {
      warn $!
      warn $@.join("\n")
    }
    sleep 1
  ensure
    return DebugControl::DEBUG_STATUS_GO
  end

}

# Callback for exception events
exception_proc = lambda {|args|

  exr = ExceptionRecord64.new args[:exception_record]

  if args[:first_chance].zero?

    mut.synchronize {
      puts "#{"%8.8x" % exr[:code]} - Second chance"
      puts "\n#{debugger.execute '!exploitable'}\n"
      puts debugger.execute "ub @$ip"
      puts debugger.execute "u @$ip"
      puts debugger.execute "r"
      puts debugger.execute "~* kc"
    }
    abort.push true
    return DebugControl::DEBUG_STATUS_BREAK

  else

    mut.synchronize{
      puts '-'*80
      puts "0x#{exr.code} @ 0x#{exr.address} - First chance"
      pp debugger.exception_record
      $stdout.flush
    }

  end
  DebugControl::DEBUG_STATUS_NO_CHANGE
}

begin
  debugger.execute "!load winext\\msec.dll" # will not break if msec isn't there
  debugger.event_callbacks.add breakpoint: bp_proc, exception: exception_proc
  debugger.attach OPTS[:dst]
  debugger.break
  debugger.wait_for_event # post attach
rescue
  fail "Unable to attach: #{$!}\n#{$@.join("\n")}"
end


# These are simple syscall gates, so they all look more or less the same.
# We're breaking at the function entry and exit.
#
# ntdll!ZwAlpcSendWaitReceivePort:
# 00000000`77041b60 4c8bd1          mov     r10,rcx <-- bp1
# 00000000`77041b63 b882000000      mov     eax,82h
# 00000000`77041b68 0f05            syscall
# 00000000`77041b6a c3              ret <--- bp2
debugger.execute "bp1 ntdll!NtAlpcSendWaitReceivePort"
debugger.execute "bp2 ntdll!NtAlpcSendWaitReceivePort+0xa"

# Because we're fuzzing in the receiving process, we don't need to grope about
# in the kernel - the userland handle has a name element. All ALPC messages
# for a given port ( from EVERY client ) arrive on the connection port ( the
# one with the name ). Only the responses are sent via the server
# communication port.
if OPTS[:port]
  handleout = debugger.execute("!handle 0 5").lines.map(&:chomp)
  # Handle 3c0
  #   Type          Event
  #   Name          <none>
  # Handle 3d0
  #   Type          File
  # Handle 3d4
  #   Type          Event
  #   Name          \BaseNamedObjects\TermSrvReadyEvent
  handleout.each.with_index {|l, i|
    if l.split(' ',2).last == target_port
      target_hid = handleout[i-2].split(' ',2).last.to_i(16)
      break
    end
  }
  unless target_hid
    debugger.detach_process
    fail "No handle to #{target_port} in #{OPTS[:dst]}"
  end
end

#puts gt
puts "Breakpoint set, starting processing loop."
puts "Hit ^C to exit...\n\n"

# This may seem convoluted, but JRuby is kind of weird about threads, so it's
# best to be extra nice to it.
abort = Queue.new
Signal.trap "INT" do
  abort.push true
end

debugger.go

# main event loop
loop do

  begin

    debugger.wait_for_event 200 # ms

    break unless debugger.has_target?

    unless abort.empty?
      puts "Caught abort, trying a clean exit..."
      debugger.detach_process
      puts "Detatched!"
      break
    end

  rescue

    puts "Caught error, exiting: #{$!}"
    break

  end

end

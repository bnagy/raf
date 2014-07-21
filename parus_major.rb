require 'buggery'
require 'thread'
require 'bindata'
require 'hexdump'
require 'pp'

include Buggery::Structs
include Buggery::Raw

# http://www.retrojunkie.com/asciiart/animals/greattit.htm
gt = <<'eos'

    ______  ___  ______ _   _ _____  ___  ___  ___     ___  ___________
    | ___ \/ _ \ | ___ \ | | /  ___| |  \/  | / _ \   |_  ||  _  | ___ \
    | |_/ / /_\ \| |_/ / | | \ `--.  | .  . |/ /_\ \    | || | | | |_/ /
    |  __/|  _  ||    /| | | |`--. \ | |\/| ||  _  |    | || | | |    /
    | |   | | | || |\ \| |_| /\__/ / | |  | || | | |/\__/ /\ \_/ / |\ \
    \_|   \_| |_/\_| \_|\___/\____/  \_|  |_/\_| |_/\____/  \___/\_| \_|

                         (c) @rantyben 2014



                                                            ,-,
                                                          ,',' `,
              Great Tit                                 ,' , ,','
                          or                          ,' ,'  ,'
                                                    ,' ,', ,'
                Parus Major                       ,'  , ,,'
                                                ,' ,', ,'
                                              ,' , , ,'
                                          __,',___','
                       __,,,,,,,------""""_    __,-"""""_`=--
        _..---.____.--'''''''''''_,---'  _; --'  ___,-'___
      ,':::::,--.::'''''' ''''''' ___,--'   __,-';    __,-""""
     ;:::::,'   |::'' '''' '===)-' __; _,--'    ;---''
    |:: @,'    ;:;\ ''''==== =),--'_,-'   ` )) ;
    `:::'    _;:/  `._=== ===)_,-,-' `  )  `  ;
     | ;--.;:::; `    `-._=_)_.-'   `  `  )  /`-._
     '        `-:.  `         `    `  ) )  ,'`-.. \
                 `:_ `    `        )    _,'     | :
                    `-._    `  _--  _,-'        | :
                        `----..\  \'            | |
                               _\  \            | :
    _____  jrei           _,--'__,-'            : :      _______
   ()___ '-------.....__,'_ --'___________ _,--'--\\-''''  _____
        `-------.....______\\______ _________,--._-'---''''
                        `=='
eos

def usage
  "#{gt}\n Fuzz received ALPC messages in the memory of <dest> iff \n" <<
  " they are from <source> (0 for any)\n" <<
  " Usage: #{$0} <source> <dest> [fuzzfactor]\n" <<
  " (did not run, try again)\n"
end

fail usage unless ARGV[0] && ARGV[1]
begin
  source = Integer(ARGV[0])
  dest = Integer(ARGV[1])
rescue
  fail usage
end


debugger = Buggery::Debugger.new

# I untangled a lot of unions here, see ntlpcapi.h for details
class PORT_MESSAGE < BinData::Record
  endian :little
  uint16 :data_length
  uint16 :total_length
  uint16 :type
  uint16 :data_info_offset
  uint64 :process
  uint64 :thread
  uint32 :message_id
  uint32 :pad
  uint64 :client_view_size # or callback id
end

PORT_MESSAGE_SIZE = 0x28

# Do parsing and display in a separate thread so that the callback proc can be
# as speedy as possible
mut = Mutex.new
logger = Queue.new
Thread.new do
  loop do

    s = logger.pop
    m = PORT_MESSAGE.read(s)
    mut.synchronize {
      puts '='*80
      puts
      puts "Type:     0x%x" % m.type
      puts "Process:  #{m.process}"
      puts "Thread:   #{m.thread}"
      puts "Id:       #{m.message_id}"
      puts
      puts Hexdump.dump s[PORT_MESSAGE_SIZE..-1]
      puts
      $stdout.flush
    }

  end
end

if ARGV[1]
  MILLER_FACTOR = Float(ARGV[1])
else
  MILLER_FACTOR = 20.0
end

def millerfuzz data, fuzzfactor

  # You could optimise slightly by corrupting the caller's data directly, but I
  # have been burnt too many times in the past.
  working_copy = data.clone

  fuzzed_bytes = (data.bytesize / fuzzfactor).ceil
  fuzzed_bytes = 1 if fuzzed_bytes.zero?
  while working_copy == data
    rand(1..fuzzed_bytes).times do
      working_copy[rand(data.bytesize)] = rand(256).chr
    end
  end

  working_copy

end

# Callback for breakpoint events
bp_proc = lambda {|_|

  begin

    p_msg = debugger.read_pointers( debugger.registers['rsp']+0x28 ).first
    return 1 if p_msg.null? # no receive buffer

    # hackily (quickly) get total length
    msg_offset = p_msg.address
    msg_len = debugger.read_virtual( msg_offset+2, 2 ).unpack('s').first

    if msg_len > PORT_MESSAGE_SIZE

      # Could be optimized for speed, but this version is readable
      msg = debugger.read_virtual msg_offset, msg_len

      if source.zero? || PORT_MESSAGE.read(msg).process == source
        logger.push msg
        fuzzed = msg[0,PORT_MESSAGE_SIZE] << millerfuzz(msg[PORT_MESSAGE_SIZE..-1], MILLER_FACTOR)
        logger.push fuzzed # before and after...
        debugger.write_virtual msg_offset, fuzzed
      end

    end

  rescue
    mut.synchronize { warn $! }
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
      puts debugger.execute "kb"
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
  debugger.attach dest
  debugger.break
  debugger.wait_for_event # post attach
rescue
  fail "Unable to attach: #{$!}\n#{$@.join("\n")}"
end

# ntdll!ZwAlpcSendWaitReceivePort:
# 00000000`77041b60 4c8bd1          mov     r10,rcx
# 00000000`77041b63 b882000000      mov     eax,82h
# 00000000`77041b68 0f05            syscall
# 00000000`77041b6a c3              ret <--- BREAK
#
# We break after the syscall, which is when the kernel has filled in the
# receive buffer
debugger.execute "bp8008 ntdll!NtAlpcSendWaitReceivePort+0xa"

puts gt
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

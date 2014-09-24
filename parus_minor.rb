require 'buggery'
require 'thread'
require 'bindata'
require 'hexdump'
require 'trollop'
require 'pp'

require 'alpc'

include Buggery::Structs
include Buggery::Raw

minor = <<-EOS                  
                              _             
 ___ ___ ___ _ _ ___    _____|_|___ ___ ___ 
| . | .'|  _| | |_ -|  |     | |   | . |  _|
|  _|__,|_| |___|___|  |_|_|_|_|_|_|___|_|  
|_| (c) 2014 @rantyben
 
EOS

OPTS=Trollop::options do
  banner minor
  opt :port, "only fuzz messages to this ALPC port", type: :strings, required: true
  opt :src, "source pid ( fuzz messages arriving from this pid )", type: :integer, required: true
  opt :fuzzfactor, "millerfuzz fuzzfactor ( bigger numbers less fuzzy)", type: :float, default: 20.0
  opt :barrier, "number of bytes after the PORT_MESSAGE header NOT to fuzz", type: :integer, default: 0
  opt :monitor, "monitor mode - don't fuzz, just dump traffic", type: :boolean
end

debugger = Buggery::Debugger.new
debugger.extend ALPC

target_hid = nil
target_port = OPTS[:port].join(' ') if OPTS[:port]

# Used to track per-thread the new HID pointer that will be filled in by
# NtAlpcConnectPort, so it can be read out at the ret breakpoint
last_hidptr = {}



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
    lines[line][9 + pos*3] = '!'
    lines[line][9 + pos*3 + 3] = '!'
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
  changes = []
  while working_copy == data
    changes.clear
    rand(1..fuzzed_bytes).times do
      idx = rand(data.bytesize)
      working_copy[idx] = rand(256).chr
      changes << idx
    end
  end

  if working_copy.bytesize != data.bytesize
    fail "Internal error: data size changed while fuzzing"
  end

  [working_copy, changes]

end


# Relevant:
# NTSYSCALLAPI
# NTSTATUS
# NTAPI
# NtAlpcSendWaitReceivePort(
#     __in HANDLE PortHandle, <-- rcx
#     __in ULONG Flags,
#     __in_opt PPORT_MESSAGE SendMessage, <-- r8
#     __in_opt PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
#     __inout_opt PPORT_MESSAGE ReceiveMessage,
#     __inout_opt PULONG BufferLength,
#     __inout_opt PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
#     __in_opt PLARGE_INTEGER Timeout
#     );

# shared / reusable pointer, because the debugger itself is single threaded
pulong = FFI::MemoryPointer.new :ulong

# our callback, invoked at every breakpoint event
bp_proc = lambda {|args|

  begin

    bp = DebugBreakpoint3.new args[:breakpoint]
    bp.GetId pulong
    bpid = pulong.read_ulong

    debugger.raw.DebugSystemObjects.GetCurrentThreadId pulong
    tid = pulong.read_ulong

    case bpid
    when 1 # NtAlpcSendWaitReceivePort entry

      unless debugger.registers['rcx'] == target_hid
        return DebugControl::DEBUG_STATUS_GO
      end

      # get total length field at offset 2
      msg_offset = debugger.registers['r8']
      msg_len = debugger.read_virtual( msg_offset+2, 2 ).unpack('s').first
      if msg_len > HEADERSIZE + OPTS[:barrier]

        raw_msg = debugger.read_virtual msg_offset, msg_len

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

      # NTSYSCALLAPI
      # NTSTATUS
      # NTAPI
      # NtAlpcConnectPort(
      #     __out PHANDLE PortHandle,
      #     __in PUNICODE_STRING PortName, <-- rdx
      #     __in POBJECT_ATTRIBUTES ObjectAttributes,
      # [...]
    when 3 # NtAlpcConnectPort entry
      # A UNICODE_STRING structure starts with a two-entry length header
      # instead of just being a pointer to a null terminated wstr. Here we're
      # using windbg commands instead of messing around following two layers
      # of pointers - this way if an address is invalid we'll just get ??????
      # as the name instead of a read AV
      output = debugger.execute "du poi(@rdx+8)"
      name = output.lines.map {|l| l.split(' ', 2).last.chomp }.join.delete('"')
      # save the handle pointer - rcx is volatile
      last_hidptr[tid] = [debugger.registers['rcx'], name]

    when 4 # NtAlpcConnectPort exit

      # TODO if the call failed I think the hid is zero? Deal with that? If so, how?
      ptr, name = last_hidptr[tid]
      hid = debugger.read_virtual( ptr, 8 ).unpack('Q').first
      if name == target_port
        target_hid = hid
        mut.synchronize {
          warn "NEW HID: #{hid} for #{name}\n"
        }
      end
    end

  rescue
    mut.synchronize {
      warn $!
      warn $@.join("\n")
      warn debugger.execute('r')
    }
    sleep 1
  ensure
    return DebugControl::DEBUG_STATUS_GO
  end

}

# Callback for exception events
exception_proc = lambda {|args|

  exr = ExceptionRecord64.new args[:exception_record]

  # We're fuzzing the source, here, so second chance exceptions aren't
  # expected.
  if args[:first_chance].zero?

    mut.synchronize {
      puts "#{"%8.8x" % exr[:code]} - Second chance"
      puts "\n#{debugger.execute '!exploitable -m'}\n"
      puts debugger.execute "ub @$ip"
      puts debugger.execute "u @$ip"
      puts debugger.execute "r"
      puts debugger.execute "~* kc"
    }
    # let it die
    abort.push true
    return DebugControl::DEBUG_STATUS_GO

  else

    # It's common to receive LRPC exceptions. Hopefully they come _after_ the
    # receiving process has tried and failed to process our fuzzed message. My
    # initial tests suggest that all fuzz AFTER the ALPC PORT_MESSAGE header
    # arrives at the destination, even invalid ncalrpc message types etc, but
    # more extensive monitoring might be required.
    mut.synchronize{
      puts '-'*80
      puts "0x#{exr.code} @ 0x#{exr.address} - First chance"
      pp debugger.exception_record
      $stdout.flush
    }

  end
  DebugControl::DEBUG_STATUS_NO_CHANGE
}

# Before we start, we need to know which external ALPC ports the existing
# userland handles are connected to. There's no way to find this out from
# userland or the ALPC API, so we're going to use the local kernel connection
# support.

puts "Connecting to local kernel to track existing ALPC handles"
puts "(allow several seconds)"
debugger.attach_local_kernel
debugger.wait_for_event

# Get a list of processes from the kernel side
procs = debugger.get_processes_k
_, target_proc = procs.find {|k,v| v[:pid] == OPTS[:src] }
unless target_proc
  warn "Unable to find target #{OPTS[:src]}"
  debugger.detach_process
  exit
end

# Existing ALPC connections
conns = debugger.get_alpc_connections target_proc[:object]
# Map of handle IDs to object IDs
hids = debugger.get_handles_k target_proc[:object]

puts "Existing external ALPC Port handles:"
conns.each {|src,dst|
  dst_proc_info = procs[dst[:proc]]
  hid = hids[src]
  unless dst_proc_info
    fail "Unable to find dest process information for port #{src}"
  end
  puts "HID: #{hid} -> #{dst_proc_info[:image]} : #{dst[:name]}"
}

src, dst = conns.find {|s, d| d[:name] == target_port}
target_hid = hids[src]

unless target_hid
  # So, we're not connected to that ALPC port yet. That's cool. Once the
  # process connects we'll grab the HID via the NtAlpcCreatePort hook and then
  # start fuzzing. Same goes for when we get booted from some services - the
  # process will reconnect, and we'll pick up the new HID.
  warn "Unable to find connection to #{target_port}, waiting..."
end

puts "Detaching from local kernel."

debugger.detach_process # farewell kernel - hello userland!

begin
  debugger.execute "!load winext\\msec.dll" # will not break if msec isn't there
  debugger.event_callbacks.add breakpoint: bp_proc, exception: exception_proc
  debugger.attach OPTS[:src]
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
debugger.execute "bp3 ntdll!NtAlpcConnectPort"
debugger.execute "bp4 ntdll!NtAlpcConnectPort+0xa"

puts minor
sleep 3
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

# Part of a series of PoC tools for ALPC fuzzing
# Original source at:
# https://github.com/bnagy/raf
# https://github.com/bnagy/rBuggery
# (c) Ben Nagy, 2014, provided under the BSD License

require 'buggery'

v = Buggery::VERSION
unless v >= '1.1.1'
  fail "Sorry, need rBuggery 1.1.1 or greater for lazy breakpoints, found #{v}"
end

require 'thread'
require 'hexdump'
require 'csv'

require_relative 'alpc'

include Buggery::Raw
include Buggery::Structs

target = ARGV[0]
fail "Usage: #{$0} <target pid>" unless Integer(target)

debugger = Buggery::Debugger.new
debugger.extend ALPC

# Used to track per-thread which HID started the call to NtAlpcSendReceivePort
last_hid = {}

# Used to track per-thread the new HID pointer that will be filled in by
# NtAlpcConnectPort, so it can be read out at the ret breakpoint
last_hidptr = {}

# Connections that we're tracking
live_conns = Hash.new {|h,k| h[k] = {name: nil, pid: nil, count: 0, last_count: 0}}
conn_mtx = Mutex.new
conn_q = Queue.new

def refresh_pids
  @pids ||= {}
  CSV.parse(`tasklist /v /fo csv`, headers: true) {|row|
    @pids[row["PID"].to_i] = row
  }
end

refresh_pids

# Parsing thread
output_q = Queue.new
Thread.new do
  loop do
    begin

      hid, raw = output_q.pop
      name = conn_mtx.synchronize { live_conns[hid][:name] }
      # We'll also receive messages on our own OLE ports, or whatever other
      # ALPC ports we might have, but they're not interesting for this
      # purpose, so we didn't record their names in the kernel phase
      next unless name

      m = ALPC::PORT_MESSAGE.read(raw)

      if m.process.nonzero?
        conn_mtx.synchronize {
          live_conns[hid][:count] += 1
          # bindata returns some crazy type under MRI that needs to be
          # converted to an integer
          live_conns[hid][:pid] = Integer(m.process)
        }
      end

    rescue
      puts $!
      puts $@.join("\n")
      sleep 1
    end

  end
end

# shared, because the debugger itself is single threaded
pulong = FFI::MemoryPointer.new :ulong

# our callback, invoked at every breakpoint event
bp_proc = lambda {|args|

  begin

    # Use the new lazy breakpoint from rBuggery 1.1.1, this saves a lot of
    # work for callbacks like this where we're hitting breakpoints fairly
    # heavily.
    @bp ||= LazyBreakpoint.new args[:breakpoint]
    @bp.ptr = args[:breakpoint] # update pointer for existing bp obj

    @bp.GetId pulong
    bpid = pulong.read_ulong

    debugger.raw.DebugSystemObjects.GetCurrentThreadId pulong
    tid = pulong.read_ulong

    case bpid
    when 1 # NtAlpcSendWaitReceivePort entry

      last_hid[tid] = debugger.registers['rcx']

    when 2 # NtAlpcSendWaitReceivePort exit

      p_msg = debugger.read_pointers( debugger.registers['rsp']+0x28 ).first
      # Don't continue unless there's a receive buffer
      return 1 if p_msg.null?

      # hackily get total length
      msg_offset = p_msg.address
      total_length = debugger.read_virtual( msg_offset+2, 2 ).unpack('s').first

      if total_length >= ALPC::PORT_MESSAGE_SIZE
        hid = last_hid[tid]
        raw_msg = debugger.read_virtual(msg_offset, total_length)
        output_q.push [hid, raw_msg]
      end

    when 3 # NtAlpcConnectPort entry
      # Arg 2 ( in rdx ) is a pointer to a UNICODE_STRING structure. It starts
      # with a two-entry length header instead of just being a pointer to a
      # null terminated wstr. We're using windbg commands instead of messing
      # around following two layers of pointers. This way if that address is
      # invalid we'll just get ?????? as the name instead of an AV
      output = debugger.execute "du poi(@rdx+8)"
      name = output.lines.map {|l| l.split(' ', 2).last.chomp }.join.delete('"')
      # save the handle pointer address - rcx is volatile
      last_hidptr[tid] = [debugger.registers['rcx'], name]

    when 4 # NtAlpcConnectPort exit

      ptr, name = last_hidptr[tid]
      hid = debugger.read_virtual( ptr, 8 ).unpack('Q').first
      conn_q.push "New connection: HID: #{hid} -> #{name}"
      conn_mtx.synchronize {
        # FIXME should live_conns just be name -> conn ?
        carry = 0
        old_conns = live_conns.select {|hid,c| c[:name] == name}
        old_conns.each {|old_hid,old_conn|
          carry += old_conn[:count]
          live_conns.delete old_hid
        }
        live_conns[hid][:name] = name
        live_conns[hid][:count] = carry
      }

    end
  rescue
    puts $!
    puts $@.join("\n")
  ensure
    return 1 # DEBUG_STATUS_GO
  end

}

debugger.event_callbacks.add breakpoint: bp_proc

# Before we start, we need to know which external ALPC ports the existing
# userland handles are connected to. There's no way to find this out from
# userland or the ALPC API, so we're going to use the local kernel connection
# support.

puts "Connecting to local kernel to track existing ALPC handles"
puts "(allow several seconds)"
debugger.attach_local_kernel
debugger.wait_for_event

begin

  # Get a list of processes from the kernel side
  procs = debugger.get_processes_k
  _, target_proc = procs.find {|k,v| v[:pid] == target.to_i }
  unless target_proc
    warn "Unable to find target #{target}"
    fail "Usage: #{$0} <target pid>"
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
    unless hid
      raise "Unable to find #{src}, retrying (^C to exit)"
    end

    puts "HID: #{hid} -> #{dst_proc_info[:image]} : #{dst[:name]}"

    live_conns[hid][:name] = dst[:name]
    live_conns[hid][:pid] = dst_proc_info[:pid]
  }

rescue
  warn $!
  sleep 1
  retry
end
puts "Detaching from local kernel."

# Now we have a map of userland handles to kernel objects, and we have details
# on all the kernel objects that back handles to ALPC ports in other
# processes. From here, new connections can be tracked via userland breakpoint
# hooks.
debugger.detach_process

puts "Starting userland stuff now..."

begin
  debugger.attach target
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

debugger.execute "bp3 ntdll!NtAlpcConnectPort"
debugger.execute "bp4 ntdll!NtAlpcConnectPort+0xa"

puts "Breakpoints set, starting processing loop."
puts "Hit ^C to exit...\n\n"


abort = Queue.new
Signal.trap "INT" do
  if RbConfig::CONFIG['RUBY_INSTALL_NAME']=='jruby'
    # This seems convoluted, but JRuby is kind of weird about threads, so it's
    # best to be extra nice to it.
    abort.push true
  else
    # This will detach the debugger under MRI
    debugger.detach_process
    exit
  end
end


# Display ticker thread
Thread.new do
  loop do
    begin
      sleep 5

      # drain the notification queue of recent connections
      puts unless conn_q.empty?
      until conn_q.empty?
        puts conn_q.pop
      end
      puts

      # TODO - we retain traffic counters to dead processes / ports by design,
      # but maybe we should remove it after a while, or add a gets option to
      # prune it?

      conn_mtx.synchronize {
        live_conns.each {|hid, c|

          next unless c[:count] > 0 || c[:name]

          unless @pids[c[:pid]]
            refresh_pids
            next
          end

          user = @pids[c[:pid]]["User Name"]
          img = @pids[c[:pid]]["Image Name"]
          # Add a slight visual cue for ports that received this tick
          recv = "recv:"
          if c[:count] > c[:last_count]
            recv = "RECV>"
            c[:last_count] = c[:count]
          end

          puts "%-50s %s %-3d [%-4d] %s (%s)" % [c[:name], recv, c[:count], c[:pid], img, user]

        }
        puts "\n#{'=' * 40}\n"

      }
    rescue
      puts $!
      puts $@.join("\n")
    end
  end
end

debugger.go

# Main thread, simple event loop with dead-target check
loop do

  begin

    debugger.wait_for_event(200) # ms

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

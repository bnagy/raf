require 'buggery'
require 'thread'
require 'bindata'
require 'hexdump'
require 'csv'

include Buggery::Raw
include Buggery::Structs

target = ARGV[0]
fail "Usage: #{$0} <target pid>" unless Integer(target)

debugger = Buggery::Debugger.new

# Used to track per-thread which HID started the call to NtAlpcSendReceivePort
last_hid = {}

# Used to track per-thread the new HID pointer that will be filled in by
# NtAlpcConnectPort, so it can be read out at the ret breakpoint
last_hidptr = {}

# Connections that we're tracking
conn = Hash.new {|h,k| h[k] = {name: nil, pid: nil, count: 0, last_count: 0}}
conn_mtx = Mutex.new
conn_q = Queue.new

def refresh_pids
  @pids = {}
  CSV.parse(`tasklist /v /fo csv`, headers: true) {|row|
    @pids[row["PID"].to_i] = row
  }
end

refresh_pids

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

# Parsing thread
output_q = Queue.new
Thread.new do
  loop do
    begin

      hid, raw = output_q.pop
      name = conn_mtx.synchronize { conn[hid][:name] }
      # We'll also receive messages on our own OLE ports, or whatever other
      # ALPC ports we might have, but they're not interesting for this
      # purpose, so we didn't record their names in the kernel phase
      next unless name

      m = PORT_MESSAGE.read(raw)

      if m.process.nonzero?
        conn_mtx.synchronize {
          conn[hid][:count] += 1
          conn[hid][:pid] = m.process
        }
      end

    rescue
      puts $!
      puts $@.join("\n")
    end

  end
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

      if total_length >= PORT_MESSAGE_SIZE
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
        conn[hid][:name] = name
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

puts "Connecting to local kernel to track existing ALPC handles"
puts "(allow several seconds)"
debugger.attach_local_kernel
debugger.wait_for_event

# Get a list of processes from the kernel side
processes = debugger.execute("!process 0 0")
processes.sub! "**** NT ACTIVE PROCESS DUMP ****\n", ''
# PROCESS fffffa8030cc6040
#   SessionID: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
#   DirBase: 00187000  ObjectTable: fffff8a0000017e0  HandleCount: 496.
#   Image: System
#
chunks = processes.split("\n\n")
# Slurp them into a hash
proc_entries = chunks.map {|chunk| Hash[*chunk.delete(":\n").squeeze(' ').split(' ')]}

# Find our target process
proc = proc_entries.find {|p| p['Cid'].to_i(16) == target.to_i}
unless proc
  warn "Unable to find target #{target}"
  fail "Usage: #{$0} <target pid>"
end

# Get all the ALPC ports this process is connected to
lpp = debugger.execute("!alpc /lpp #{proc["PROCESS"]}").lines.map(&:chomp)
#
#  Ports created by the process fffffa80353c3060:
#
#  fffffa8032129590('OLE16E02A5AAD974222920005479E7C') 0, 1 connections
#    fffffa8033c6fb80 0 -> fffffa803262f900 0 fffffa80321ac580('svchost.exe')
#
# Ports the process fffffa80353c3060 is connected to:
#
#  fffffa8035261e60 0 -> fffffa8032059e60('ApiPort') 0 fffffa8032e68b30('csrss.exe')
#  fffffa80353ce070 0 -> fffffa8033c2a6b0('ThemeApiPort') 0 fffffa8032fd2b30('svchost.exe')
#  fffffa80365bb8c0 0 -> fffffa803211a5a0('lsasspirpc') 0 fffffa80320a3440('lsass.exe')
#  fffffa80365b2e60 0 -> fffffa8032174cf0('ntsvcs') 19 fffffa803207fb30('services.exe')
lpp.shift until lpp.first =~ /Ports the process .* is connected to/
lpp.shift 2

port_obj = {}
lpp.each {|l|
  break if l.empty?
  src, dst, dest_proc = l.scan(/ffff[a-f0-9]{8,}/)
  port_obj[src] = [dst, dest_proc]
}

# Map userland handle ids to kernel object ids - this is the slowest part,
# because we walk the whole handle list
handles = debugger.execute("!handle 0 1 #{proc['Cid']}")
# lkd> !handle 0 1 8d0
#
# Searching for Process with Cid == 8d0
# PROCESS fffffa803213e060
#     SessionId: 1  Cid: 08d0    Peb: 7fffffde000  ParentCid: 05c8
#     DirBase: 2547e000  ObjectTable: fffff8a002ebedc0  HandleCount: 285.
#     Image: notepad.exe
#
# Handle table at fffff8a002ebedc0 with 285 entries in use
#
# 0004: Object: fffff8a00305d520  GrantedAccess: 00000009
#
# 0008: Object: fffff8a005c7a120  GrantedAccess: 00000003
#
# 000c: Object: fffffa8032122f20  GrantedAccess: 00100020
chunks = handles.split("\n\n")
hids = {}
chunks.each {|chunk|
  next unless chunk =~ /^[0-9a-f]+: /
  hid, _, object, _ = chunk.split(/[ :]+/)
  hids[object] = hid
}
# make it a two-way lookup, hids and object ids can't collide.
hids.update hids.invert

# Follow each ALPC Port object back to the root of the Object Directory so we
# get the "absolute" ALPC Port name.
# Working backwards to the root, like this:
# lkd> !object fffffa80352ea740 3
#  Object: fffffa80352ea740  Type: (fffffa8030d11080) ALPC Port
#     ObjectHeader: fffffa80352ea710 (new version)
#     HandleCount: 1  PointerCount: 4
#     Directory Object: fffff8a000a4c450  Name: OLE8F8B8C095131496BB200263FA52C
# lkd> !object fffff8a000a4c450 3
# Object: fffff8a000a4c450  Type: (fffffa8030c64f30) Directory
#     ObjectHeader: fffff8a000a4c420 (new version)
#     HandleCount: 0  PointerCount: 72
#     Directory Object: fffff8a0000046c0  Name: RPC Control
# lkd> !object fffff8a0000046c0 3
# Object: fffff8a0000046c0  Type: (fffffa8030c64f30) Directory
#     ObjectHeader: fffff8a000004690 (new version)
#     HandleCount: 0  PointerCount: 44
#     Directory Object: 00000000  Name: \
port_names = {}
port_obj.each {|src,(dst,dest_proc)|

  name = []
  next_obj = dst
  sane_depth = 5
  loop do

    lines = debugger.execute("!object #{next_obj} 3").lines.map(&:chomp)
    toks = lines[3].split(' ',5)
    break if toks.last == '\\' || name.length > sane_depth
    name.unshift toks.last
    next_obj = toks[2]

  end

  port_names[dst] = "\\#{name.join('\\')}"
}

puts "Existing external ALPC Port handles:"
port_obj.each {|src,(dst,dst_proc_obj)|

  dst_proc = proc_entries.find{|p| p['PROCESS']==dst_proc_obj}

  unless dst_proc
    p dst_proc_obj
    p proc_entries
    fail "Unable to find dest process for port #{src} in kernel phase"
  end
  fail "Unable to find #{src} in:\n#{hids}" unless hids[src]

  puts "HID: #{hids[src]} -> #{dst_proc['Image']} : #{port_names[dst]}"

  hid = hids[src].to_i 16
  conn[hid][:name] = port_names[dst]
  conn[hid][:pid] = dst_proc['Cid'].to_i 16
}

puts "trying to detach"

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

# This seems convoluted, but JRuby is kind of weird about threads, so it's
# best to be extra nice to it.
abort = Queue.new
Signal.trap "INT" do
  abort.push true
end


# Display ticker thread
Thread.new do
  loop do
    begin
      sleep 5

      # drain the notification queue of recent connections
      puts
      until conn_q.empty?
        puts conn_q.pop
      end
      puts

      conn_mtx.synchronize {
        conn.each {|hid, c|

          next unless c[:count] > 0 || c[:name]

          refresh_pids unless @pids[c[:pid]]

          user = @pids[c[:pid]]["User Name"]
          img = @pids[c[:pid]]["Image Name"]
          # Add a slight visual cue for ports that received this tick
          recv = "Recv:"
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

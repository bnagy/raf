# Part of a series of PoC tools for ALPC fuzzing
# Original source at:
# https://github.com/bnagy/raf
# https://github.com/bnagy/rBuggery
# (c) Ben Nagy, 2014, provided under the BSD License

require 'bindata'

# Extend this module into an rBuggery Debugger instance:
#   require 'buggery'
#   require 'alpc'
#
#   debugger = Buggery::Debugger.new
#   debugger.extend ALPC

module ALPC

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

  def local_kernel_target?
    @p_target_class      ||= p_ulong
    @p_target_qualifier  ||= p_ulong
    retval = self.debug_client.DebugControl.GetDebuggeeType( @p_target_class, @p_target_qualifier )
    self.raise_errorcode( retval, __method__ ) unless retval.zero? # S_OK

    @p_target_class.read_int == DebugControl::DEBUG_CLASS_KERNEL &&
      @p_target_qualifier.read_int == DebugControl::DEBUG_KERNEL_LOCAL
  end

  def get_processes_k

    raise "No local kernel target" unless local_kernel_target?

    # Get a list of processes from the kernel side
    processes = self.execute("!process 0 0")
    processes.sub! "**** NT ACTIVE PROCESS DUMP ****\n", ''
    # PROCESS fffffa8030cc6040
    #   SessionID: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    #   DirBase: 00187000  ObjectTable: fffff8a0000017e0  HandleCount: 496.
    #   Image: System
    #
    chunks = processes.split("\n\n")
    
    # Slurp them into a hash
    p_ary = chunks.map {|chunk| Hash[*chunk.delete(":\n").squeeze(' ').split(' ')]}
    
    # clean up
    final = {}
    p_ary.each {|p|
      p_obj = p['PROCESS'].to_i(16)
      final[p_obj] = {
        object:       p_obj,
        session_id:   (Integer(p['SessionID']) rescue 'none'),
        pid:          p['Cid'].to_i(16),
        peb:          p['Peb'].to_i(16),
        ppid:         p['ParentCid'].to_i(16),
        dir_base:     p['DirBase'].to_i(16),
        object_table: p['ObjectTable'].to_i(16),
        handle_count: p['HandleCount'][0..-2].to_i(10), # remove trailing '.'
        image:        p['Image']
      }

    }
    final
  end

  def get_alpc_connections proc_obj

    raise "No local kernel target" unless local_kernel_target?

    # Get all the ALPC ports this process is connected to
    lpp = self.execute("!alpc /lpp 0n#{proc_obj}").lines.map(&:chomp)
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

    connections = {}
    lpp.each {|l|
      break if l.empty?
      src, dst, dest_proc = l.scan(/ffff[a-f0-9]{8,}/)
      connections[src.to_i(16)] = {
        port: dst.to_i(16),
        name: get_absolute_port_name(dst.to_i(16)),
        proc: dest_proc.to_i(16)
      }
    }
    connections

  end

  def get_alpc_ports proc_obj

    raise "No local kernel target" unless local_kernel_target?

    # Get all the ALPC ports this process hosts
    lpp = self.execute("!alpc /lpp 0n#{proc_obj}")
    unless lpp =~ /Ports created by the process/
      raise "Parsing failed. Perhaps #{proc_obj.to_s(16)} is not a process object?"
    end
    lpp = lpp.lines.map(&:chomp)
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

    ports = {}
    while line = lpp.shift
      break if line =~ /Ports the process .* is connected to/
      if line =~ /^ffff.*connections$/
        obj = l.split('(').first
        ports[obj.to_i(16)] = get_absolute_port_name obj
      end
    end
    ports

  end

  def get_handles_k proc_obj


    raise "No local kernel target" unless local_kernel_target?
    # Map userland handle ids to kernel object ids - this is the slowest part,
    # because we walk the whole handle list
    handles = self.execute("!handle 0 1 0n#{Integer(proc_obj)}")
    unless handles =~ /PROCESS/
      raise "Parsing failed. Perhaps #{proc_obj.to_s(16)} is not a process object?"
    end
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
      hids[object.to_i(16)] = hid.to_i(16)
    }
    # make it a two-way lookup, hids and object ids can't collide.
    hids.update hids.invert
    hids

  end

  def get_absolute_port_name port_obj

    raise "No local kernel target" unless local_kernel_target?

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

    name = []
    next_obj = port_obj.to_s(16)
    sane_depth = 5
    loop do
      lines = self.execute("!object #{next_obj} 3").lines.map(&:chomp)
      toks = lines[3].split(' ',5)
      break if toks.last == '\\' || name.length > sane_depth || toks[-3] == '00000000'
      name.unshift toks.last
      next_obj = toks[2]
    end

    "\\#{name.join('\\')}"
    
  end

end

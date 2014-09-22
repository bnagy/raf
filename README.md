Overview
======

RAF - Ruby ALPC Fuzzer

This is a PoC. It _will_ send real traffic to real ALPC ports and produce lots
of output on screen, but is highly unlikely to find real bugs. You are
encouraged to write an actual fuzzer.

Test cases are generated by using ~3000 verses and notes from the works of
Chaucer and feeding them through radamsa.

```
raf.rb - Ruby ALPC Fuzzer - Friday Afternoon Joke Version

Usage:

1. Extract Chaucer:

tar -zxvf [install dir]/chaucer.tar.bz2

1a. Read Chaucer (optional, but recommended)

awk 'FNR==1{print ""}{print}' chaucer/* | less

2. Run Radamsa as a TCP server:

radamsa chaucer/*.txt -n inf -o :9999

3. Run alpcrest on the target

( see https://github.com/bnagy/alpcgo/tree/master/cmd/alpcrest )

4. Run raf.rb

ruby raf.rb [host] [ALPC Port]

Example:
ruby raf.rb 172.16.216.100 "\\RPC Control\\DNS Resolver"
```

Parus Major - PoC ALPC MitM 
======

Don't get excited! 

- The access you need to fuzz this way is more than you'd get from a bug
- The bugs might be completely unreachable

Parus Major is more of an rBuggery demonstration
(https://github.com/bnagy/rBuggery). It uses a simple breakpoint callback and
then corrupts received ALPC messages in memory using the DebugDataSpaces API
and the eponymous Millerfuzz algorithm. Fuzzing via memory injection this way
is both lame and slow.

Get a tiny, tiny bit excited?

- This is a very quick way to poke interesting processes without extensive
  reverse engineering 
- Most ALPC ports are completely unprotected by DACLs, even ones owned by
  SYSTEM processes

I apologise for the name. I have a mental age of 12.

Depends on:
* rBuggery ( next branch )
* hexdump
* bindata
* trollop

```
> ruby parus_major.rb --help
Options:
       --port, -p <s+>:   only fuzz messages on this ALPC port
         --src, -s <i>:   source pid ( fuzz messages arriving from this pid )
         --dst, -d <i>:   destination pid ( fuzz messages inside this pid )
  --fuzzfactor, -f <f>:   millerfuzz fuzzfactor ( bigger numbers less fuzzy)
                          (default: 20.0)
     --barrier, -b <i>:   number of bytes after the PORT_MESSAGE header NOT to
                          fuzz (default: 0)
         --monitor, -m:   monitor mode - don't fuzz, just dump traffic
            --help, -h:   Show this message
```

ALPC Live
======

Monitor a given PID for active ALPC connections to other processes. Use this
to find interesting targets for Parus Major. Choose a non-privileged app you
have bugs in, then exercise it to watch the ALPC ports it talks to.

Depends on:
* rBuggery ( next branch ) with local kernel support ( README_LOCAL_KERNEL )
* hexdump
* bindata

```
> ruby alpclive.rb 3000
Connecting to local kernel to track existing ALPC handles
(allow several seconds)
Existing external ALPC Port handles:
HID: 0018 -> csrss.exe : \Sessions\1\Windows\ApiPort
HID: 00b4 -> svchost.exe : \ThemeApiPort
HID: 0284 -> dwm.exe : \Sessions\1\BaseNamedObjects\Dwm-2BC0-ApiPort-6AF7
HID: 02fc -> svchost.exe : \RPC Control\epmapper
HID: 03dc -> svchost.exe : \RPC Control\plugplay
trying to detach
Starting userland stuff now...
Breakpoints set, starting processing loop.
Hit ^C to exit...

\Sessions\1\Windows\ApiPort                        Recv: 0   [428 ] csrss.exe (NT AUTHORITY\SYSTEM)
\ThemeApiPort                                      Recv: 0   [960 ] svchost.exe (NT AUTHORITY\SYSTEM)
\Sessions\1\BaseNamedObjects\Dwm-2BC0-ApiPort-6AF7 Recv: 0   [1632] dwm.exe (WIN-5E72NJ6H2JO\ben)
\RPC Control\epmapper                              Recv: 0   [748 ] svchost.exe (NT AUTHORITY\NETWORK SERVICE)
\RPC Control\plugplay                              Recv: 0   [672 ] svchost.exe (NT AUTHORITY\SYSTEM)

========================================

New connection: HID: 1420 -> \RPC Control\lsapolicylookup
New connection: HID: 1388 -> \RPC Control\OLE31DFF995C9C34A5FB1FF49539367

\Sessions\1\Windows\ApiPort                        Recv: 0   [428 ] csrss.exe (NT AUTHORITY\SYSTEM)
\ThemeApiPort                                      Recv: 0   [960 ] svchost.exe (NT AUTHORITY\SYSTEM)
\Sessions\1\BaseNamedObjects\Dwm-2BC0-ApiPort-6AF7 Recv: 0   [1632] dwm.exe (WIN-5E72NJ6H2JO\ben)
\RPC Control\epmapper                              RECV> 5   [748 ] svchost.exe (NT AUTHORITY\NETWORK SERVICE)
\RPC Control\plugplay                              Recv: 0   [672 ] svchost.exe (NT AUTHORITY\SYSTEM)
\RPC Control\lsapolicylookup                       RECV> 4   [552 ] lsass.exe (NT AUTHORITY\SYSTEM)
\RPC Control\OLE31DFF995C9C34A5FB1FF49539367       RECV> 5   [904 ] svchost.exe (NT AUTHORITY\SYSTEM)

========================================

\Sessions\1\Windows\ApiPort                        Recv: 0   [428 ] csrss.exe (NT AUTHORITY\SYSTEM)
\ThemeApiPort                                      Recv: 0   [960 ] svchost.exe (NT AUTHORITY\SYSTEM)
\Sessions\1\BaseNamedObjects\Dwm-2BC0-ApiPort-6AF7 Recv: 0   [1632] dwm.exe (WIN-5E72NJ6H2JO\ben)
\RPC Control\epmapper                              RECV> 20  [748 ] svchost.exe (NT AUTHORITY\NETWORK SERVICE)
\RPC Control\plugplay                              RECV> 5   [672 ] svchost.exe (NT AUTHORITY\SYSTEM)
\RPC Control\lsapolicylookup                       RECV> 71  [552 ] lsass.exe (NT AUTHORITY\SYSTEM)
\RPC Control\OLE31DFF995C9C34A5FB1FF49539367       RECV> 11  [904 ] svchost.exe (NT AUTHORITY\SYSTEM)

========================================

\Sessions\1\Windows\ApiPort                        Recv: 0   [428 ] csrss.exe (NT AUTHORITY\SYSTEM)
\ThemeApiPort                                      Recv: 0   [960 ] svchost.exe (NT AUTHORITY\SYSTEM)
\Sessions\1\BaseNamedObjects\Dwm-2BC0-ApiPort-6AF7 Recv: 0   [1632] dwm.exe (WIN-5E72NJ6H2JO\ben)
\RPC Control\epmapper                              Recv: 20  [748 ] svchost.exe (NT AUTHORITY\NETWORK SERVICE)
\RPC Control\plugplay                              Recv: 5   [672 ] svchost.exe (NT AUTHORITY\SYSTEM)
\RPC Control\lsapolicylookup                       Recv: 71  [552 ] lsass.exe (NT AUTHORITY\SYSTEM)
\RPC Control\OLE31DFF995C9C34A5FB1FF49539367       Recv: 11  [904 ] svchost.exe (NT AUTHORITY\SYSTEM)

========================================
```

BUGS
=======

Kidding, LOL! ᕕ(ᐛ)ᕗ

None of this works. It won't even run, let alone find bugs. 

Contributing
=======

Fork & pullreq

License
=======

BSD Style, See LICENSE file for details




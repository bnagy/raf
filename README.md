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

(see https://github.com/bnagy/alpcgo/cmd/alpcrest)

4. Run raf.rb

ruby raf.rb [host] [ALPC Port]

Example:
ruby raf.rb 172.16.216.100 "\\RPC Control\\DNS Resolver"
```

BUGS
=======

- Does not find bugs

Contributing
=======

Fork & pullreq

License
=======

BSD Style, See LICENSE file for details




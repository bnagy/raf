# Part of a series of PoC tools for ALPC fuzzing
# Original source at:
# https://github.com/bnagy/raf
# https://github.com/bnagy/rBuggery
# (c) Ben Nagy, 2014, provided under the BSD License

require 'jimson'
require 'base64'
require 'socket'

unless ARGV.length == 2
  warn <<-EOS

#{$0} - Ruby ALPC Fuzzer - Friday Afternoon Joke Version

Usage:

1. Extract chaucer:

tar -zxvf [install dir]/chaucer.tar.bz2

2. Run Radamsa as a TCP server:

radamsa chaucer/*.txt -n inf -o :9999

3. Run alpcrest on the target

(see https://github.com/bnagy/alpcgo/cmd/alpcrest)

4. Run #{$0}

ruby #{$0} [host] [ALPC Port]

Example:
ruby #{$0} 172.16.216.100 "\\RPC Control\\DNS Resolver"

EOS

  exit
end

ip = ARGV[0]
warn "Connecting to alpcrest at #{ip}:1234/rpc..."
client = Jimson::Client.new("http://#{ip}:1234/rpc", {}, "ALPC.")

begin
  warn "Connecting to radamsa at localhost:9999..."
  test = TCPSocket.new('localhost', 9999).read
rescue
  fail $!
end

loop do
  begin

    begin
      h = client.Connect(
        {
          "Port" => ARGV[1],
          "Msg" => Base64.encode64(TCPSocket.new('localhost', 9999).read)
        }
      )
    rescue
      puts $!
      sleep 1
      retry
    end

    print "Connected: 0x#{"%X" % h} "

    100.times do
      begin
        msg = {
          Handle: h,
          Flags: 0x2,
          Payload: Base64.encode64(TCPSocket.new('localhost', 9999).read)
        }

        if client.Send(msg)
          print '.'
        end
      rescue Jimson::Client::Error::ServerError
        print '!'
        next
      end
    end


  rescue

    puts $!
    client.Close(h)
    sleep 5
    retry

  ensure

    print " Closing 0x#{"%X" % h}\n"
    client.Close(h)

  end
end

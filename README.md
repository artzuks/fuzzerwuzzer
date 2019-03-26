# fuzzerwuzzer
Fuzz testing IP/TCP/App

## Table of Contents

- [Setup](#setup)
  * [Configuring OS](#OS)
  * [High Level Usage](#high-level-usage)
- [Fuzzing IP Layer](#fip)
- [Fuzzing Application Layer](#fapp)
  * [General Commands](#gcomm)
  * [Random Payloads](#randompayloads)
  * [Payloads From a File](#payloadsfromafile)
- [Included Server](#server)
  * [Validation of Pattern](#validationpattern)
- [About](#about)

## Setup
### Configuring OS
All testings and developing was done on Ubuntu 18.04 so the code is not guaranteed
to run on other environments. All testing was done with Python 3.6.7 and lower version have not 
been tested.  

Since scapy functions not within the kernel, for it to be able to establish TCP connections we must disable the kernel from sending RST packets.
To do this, we can modify iptables to drop RST packets.

```shell
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
iptables -L
```
### High Level Usage
```
sudo python3 main.py [--sourceIP SOURCEIP] [--targetPort TARGETPORT]
                    [--defaultPayloadPath DEFAULTPAYLOADPATH]
                    targetIP  {app-rand-fixed,app-rand-range,app-file,ip}
```
The command line arguments are broken up into general parameters and positional arguments 
that are used to fuzz the IP and application layers. Note that you must run the fuzzer with
sudo since the underlying scapy library needs root access to manipulate and send packets on the 
network without relying on the kernel to construct packets.

`--sourceIP` argument is optional and by default 
the fuzzer will use the IP of the machine that it is running on. 

`--targetPort` is an optional argument to specify the port of the server you are fuzzing. 
By default this value is set to 80 unless specified otherwise

`targetIP` is a required argument of the target server that will be fuzzed.

The positional arguments are described in the sections below.
## Fuzzing IP Layer
### IP Commands
### TTL
The TTL field in practice is used as a counter to prevent packets from getting stuck in a network by being decremented when it is processed by a router in the network.
The fuzzing for the ttl field starts at the highest value of 255 and decrements until a request is sent out but a response is not returned.
This signifies that ttl is decremented to 0 prior to arriving at the server.
At this point the fuzzing test is concluded since a packet with a lower ttl will also not be able to make it through the network.
## Fuzzing Application Layer
Application layer fuzzing is done by first establishing a TCP connection with the target server,
and then sending payloads to the server and observing the responses. The fuzzer expects to receive
either a x00 (valid) or xFF (invalid) response from the server and counts the occurrences of both. After all of the payloads have
been sent to the server, the TCP connection is closed and the number of valid, invalid and other responses
is printed to stdout. Payloads can either be generated randomly by the fuzzer or specified
via arguments and their usage is detailed below. 
### Random Payloads
```
usage: FuzzerWuzzer targetIP app-rand-fixed [-h] numTests payloadSize

positional arguments:
  numTests     Number of tests to run
  payloadSize  The size of the fixed payload to include in each packet


usage: FuzzerWuzzer targetIP app-rand-range [-h] 
                                         numTests payloadMinSize 
                                         payloadMaxSize
positional arguments:
  numTests        Number of tests to run
  payloadMinSize  The min size of the fixed payload to include in each packet
  payloadMaxSize  The max size of the fixed payload to include in each packet

```

Random payload testing is provided by 2 positional arguments `app-rand-fixed` and `app-rand-range`
to send either fixed size random payloads or a range of sizes respectively. Both require 
the user to provide the number of random payloads to send and depending on 
### Payloads From a File
## Server
The included server serves as an endpoint for the client to connect to and send packets.
It uses a higher level socket library that takes care of the TCP connection and is primarily used to read payloads from the socket.
The maximum number of bytes that the server will read from the pipe 1024 so any payload larger than this will not be parsed correctly for matching.
### Validation of Pattern
The server reads the _matched_pattern_ file for pattern to match against the bytes that it receives from the socket.
The bytes are specified in the file by human readable HEX, i.e. a file containing the characters DEADC0DE will translate to the byte values 0xDEADCODE inside the server.
The number of bytes that this pattern can be is 1024 which is the same as the size of the maximum payload that the server will process.
A payload is considered valid if the initial bytes of the payload are the same as the pattern specified in the file. Else the payload is considered invalid.
Note that the payload must match the entire pattern, if the payload is shorter than the pattern it is considered invalid.

The server keeps count of the number of valid and invalid payloads and will print out the accumulate counts when the server is terminated.
## About
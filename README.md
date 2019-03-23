# fuzzerwuzzer
Fuzz testing IP/TCP/App

## Table of Contents

- [Setup](#setup)
  * [Configuring OS](#OS)
- [Fuzzing IP Layer](#fip)
- [Fuzzing Application Layer](#fapp)
- [Included Server](#server)
  # [Validation of Pattern](#validationpattern)
- [About](#about)

## Setup
### Configuring OS
Since scapy functions not within the kernel, for it to be able to establish TCP connections we must disable the kernel from sending RST packets.
To do this, we can modify iptables to drop RST packets.

```shell
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
iptables -L
```

## Fuzzing IP Layer
### TTL
The TTL field in practice is used as a counter to prevent packets from getting stuck in a network by being decremented when it is processed by a router in the network.
The fuzzing for the ttl field starts at the highest value of 255 and decrements until a request is sent out but a response is not returned.
This signifies that ttl is decremented to 0 prior to arriving at the server.
At this point the fuzzing test is concluded since a packet with a lower ttl will also not be able to make it through the network.
## Fuzzing Application Layer
### Default Tests
### Tests from a File
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
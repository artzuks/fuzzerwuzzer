# fuzzerwuzzer
Fuzz testing IP/TCP/App


## Setup
### Configuring OS
Since scapy functions not within the kernel, for it to be able to establish TCP connections we must disable the kernel from sending RST packets.
To do this, we can modify iptables to drop RST packets.

```shell
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
iptables -L
```


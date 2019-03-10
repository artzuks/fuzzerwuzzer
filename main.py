from scapy.layers.inet import *
from scapy.sendrecv import *

if __name__ == '__main__':

    packet = IP(dst="127.0.0.1") / TCP(dport=3000) / "Hi"
    sr1(packet)



from scapy.layers.inet import *
from scapy.sendrecv import *



if __name__ == '__main__':
    ip = IP(dst="45.55.124.203")
    mes = "Hello from scapy"
    dport = 3002
    sport = 3000
    SYN =  TCP(dport=dport, sport=sport, flags='S')
    print ("Sending SYN")
    SYNACK = sr1(ip/SYN)
    ACK = TCP(dport=dport, sport=sport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    print ("Sending ACK")
    R = send(ip / ACK)
    DATA = TCP(dport=dport, sport=sport, flags="PA", seq=SYNACK.ack, ack=SYNACK.seq + 1)
    print ("Sending Data")
    DATASENT = sr1(ip/DATA/mes)
    DATASENT.summary()
    FIN = TCP(sport=sport, dport=dport, flags="FA", seq=SYNACK.ack + 2, ack=SYNACK.seq + 2)
    print ("Sending FIN")
    FINACK = sr1(ip/FIN)
    LASTACK = TCP(sport=sport, dport=dport, flags="A", seq=FINACK.ack, ack=FINACK.seq + 1)
    print ("Sending FINACK")
    send(ip/LASTACK)

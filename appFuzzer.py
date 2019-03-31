from scapy.layers.inet import * # done purely for IDE automplete to work properly
from scapy.all import *

# the class is used to fuzz the application layer
# It establishes a TCP connection which it uses to send payloads to the server
# Each byte from the server is stored in a list which can later be used to tie back responses to payloads
# Since sometimes the server will send an ACK without data and sometimes the response to 2 previous payloads
# payloads are checked during the closing of the connection
class AppFuzzer:
    def __init__(self,destinationIP,destinationPort,sourceIP=None):
        self.destinationPort = destinationPort
        self.ip = IP(dst=destinationIP, src=sourceIP)
        self.sport = 3002
        self.closed = True
        self.responseBytes = []
        self.reInit()

    #Establish a TCP connection
    def reInit(self):
        if not self.closed:
            return
        SYN = TCP(dport=self.destinationPort, sport=self.sport, flags='S')
        print ("Sending SYN")
        SYNACK = sr1(self.ip/SYN)
        self.seq = SYNACK.seq + 1
        self.ack = SYNACK.ack
        ACK = TCP(  dport=self.destinationPort, sport=self.sport, flags='A'
                  , seq=self.ack, ack=self.seq)
        print ("Sending ACK")
        send(self.ip / ACK)
        self.closed = False

    # Sends all of the payloads in the given list.
    # Keeps track of all of the responses and stores them  for later retrieval
    def sendPayloads(self,payloads):
        self.reInit()
        for payload in payloads:
            ans = self._sr1(payload)
            for res in ans.res:
                if res[1].payload:
                    for b in res[1].payload.payload.original:
                        self.responseBytes.append(b)
        self.closeConnection()

    # Send a payload and wait for a response with a 1.5 second timeout
    # Update seq and ack from the response for next time the function is called
    def _sr1(self,msg):
        REQ = self.ip / TCP(  dport=self.destinationPort, sport=self.sport, flags='PA'
                  , seq=self.ack , ack=self.seq) / msg

        ans, unans = sr(REQ, timeout=1.5)
        if len(ans.res):
            self.seq = ans.res[0][1].seq
            self.ack = ans.res[0][1].ack
        return ans

    # Close the TCP connection if one is open
    def closeConnection(self):
        if self.closed:
            return
        FIN = TCP(  sport=self.sport, dport=self.destinationPort, flags="FA"
                  , seq=self.ack, ack=self.seq)
        print ("Sending FIN")
        FINACK = sr1(self.ip/FIN)
        nextAck = FINACK.seq+1
        #Cleanup if there is a PSH inside the finack
        if FINACK.payload:
            for b in FINACK.payload.payload.original:
                self.responseBytes.append(b)
                nextAck += 1
        LASTACK = TCP(  sport=self.sport, dport=self.destinationPort, flags="A"
                      , seq=FINACK.ack, ack=nextAck)
        print ("Sending FINACK")
        send(self.ip / LASTACK)
        self.closed = True
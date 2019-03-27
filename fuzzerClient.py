from scapy.layers.inet import * # done purely for IDE automplete to work properly
from scapy.sendrecv import *
from scapy.all import *
from utils import generateRandomInts
from ipFileReader import IPHeader


class Fuzz:
    def __init__(self,destinationIP,destinationPort,defaultMessage,sourceIP=None):
        self.destinationPort = destinationPort
        self.ip = IP(dst=destinationIP, src=sourceIP)
        self.sport = 3002
        self.msg = defaultMessage
        self.closed = True
        self.responseBytes = []
        self.reInit()

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

    def fuzzTTL(self):
        self.reInit()
        originalTTL = self.ip.ttl
        for i in reversed(range(255)):
            self.ip.ttl = i
            print("Sending ttl=",i)
            ans = self._sr1('hi' + str(i))
            if not ans.res:
                break
        self.ip.ttl = originalTTL
        self.closeConnection()


    def sendPayloads(self,payloads):
        self.reInit()
        for payload in payloads:
            ans = self._sr1(payload)
            for res in ans.res:
                if res[1].payload:
                    for b in res[1].payload.payload.original:
                        self.responseBytes.append(b)
        self.closeConnection()



    def _sr1(self,msg):
        REQ = self.ip / TCP(  dport=self.destinationPort, sport=self.sport, flags='PA'
                  , seq=self.ack , ack=self.seq) / msg

        ans, unans = sr(REQ, timeout=1.5)
        if len(ans.res):
            self.seq = ans.res[0][1].seq
            self.ack = ans.res[0][1].ack
        return ans

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


class IPFuzz:
    def __init__(self,destinationIP,destinationPort,defaultMessage,sourceIP=None):
        self.destinationPort = destinationPort
        self.destinationIP = destinationIP
        self.sourceIP = sourceIP
        self.ip = IP(dst=destinationIP, src=sourceIP)
        self.sport = 3002
        self.msg = defaultMessage
        self.responseBytes = []
        self.ttlValues = range(256)
        self.versionValues = range(16)
        self.ihlValues = range(16)
        self.dscpValues = range(62)
        self.ecnValues = range(4)
        self.lengthValues = generateRandomInts(65536,256)
        self.flagsValues = range(8)
        self.idValues = generateRandomInts(65536,256) # scapy only supports that max
        self.fragValues = generateRandomInts(8192,256)
        self.protoValues = range(256)


    def trySyn(self):
        SYN = TCP(dport=self.destinationPort, sport=self.sport, flags='S')
        print ("Sending SYN")
        send(self.ip/SYN/self.msg)

    def sendPacket(self,parsedPacket):
        pack = IP(dst=self.destinationIP,
           src=self.sourceIP,
           version=parsedPacket.version,
           ihl=parsedPacket.ihl,
           tos= (parsedPacket.dscp << 2) + parsedPacket.ecn,
           id=parsedPacket.id,
           flags=parsedPacket.flags,
           frag=parsedPacket.frag,
           ttl=parsedPacket.ttl,
           proto=parsedPacket.proto)
        #pack.len = parsedPacket.len
        SYN = TCP(dport=self.destinationPort, sport=self.sport, flags='S')
        print("Sending SYN")
        finalPacket = pack/SYN/self.msg
        send(finalPacket)

    def fuzzVersion(self):
        for i in self.versionValues:
            self.ip.version = i
            print("Sending version=", i)
            self.trySyn()
        self.ip.version = 4

    def fuzzIHL(self):
        originalIHL = self.ip.ihl
        for i in self.ihlValues:
            self.ip.ihl = i
            print("Sending ihl=", i)
            self.trySyn()
        self.ip.ihl = originalIHL

    def fuzzDSCP(self):
        originalDSCP = self.ip.tos
        for i in self.dscpValues:
            self.ip.tos = i << 2
            print("Sending dscp=", i)
            self.trySyn()
        self.ip.tos = originalDSCP

    def fuzzECN(self):
        originalDSCP = self.ip.tos
        for i in self.ecnValues:
            self.ip.tos = i
            print("Sending ecn=", i)
            self.trySyn()
        self.ip.tos = originalDSCP

    def fuzzLength(self):
        originalLen = self.ip.len
        for i in self.lengthValues:
            self.ip.len = i
            print("Sending length=", i)
            self.trySyn()
        self.ip.len = originalLen

    def fuzzID(self):
        originalID = self.ip.id
        for i in self.idValues:
            self.ip.id = i
            print("Sending id=", i)
            self.trySyn()
        self.ip.id = originalID

    def fuzzFlags(self):
        originalflag = self.ip.flags
        for i in self.flagsValues:
            self.ip.flags = i
            print("Sending flag=", i)
            self.trySyn()
        self.ip.flags = originalflag

    def fuzzFrag(self):
        originalfrag = self.ip.frag
        for i in self.fragValues:
            self.ip.frag = i
            print("Sending frag=", i)
            self.trySyn()
        self.ip.frag = originalfrag

    def fuzzTTL(self):
        originalTTL = self.ip.ttl
        for i in self.ttlValues:
            self.ip.ttl = i
            print("Sending ttl=",i)
            self.trySyn()
        self.ip.ttl = originalTTL

    def fuzzProto(self):
        originalproto = self.ip.proto
        for i in self.protoValues:
            self.ip.proto = i
            print("Sending proto=", i)
            self.trySyn()
        self.ip.proto = originalproto
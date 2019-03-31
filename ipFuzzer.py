from scapy.layers.inet import * # done purely for IDE autocomplete to work properly
from scapy.all import *
from utils import generateRandomInts

class IPFuzzer:
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
           proto=parsedPacket.proto,
           len=parsedPacket.len)
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

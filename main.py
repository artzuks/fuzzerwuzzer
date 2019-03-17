from scapy.layers.inet import * # done purely for IDE automplete to work properly
from scapy.sendrecv import *
from scapy.all import *
import argparse
import secrets

parser = argparse.ArgumentParser(
    prog="FuzzerWuzzer",
    description="General fuzzer that can be used to fuzz IP layer and Application layer of a server"
)

genGroup = parser.add_argument_group("General")
genGroup.add_argument('targetIP',
                      help='IP of the server to send packets to')
genGroup.add_argument('--sourceIP',
                      help='IP which will be specified as src in IP layer. Default uses the IP of the current machine',
                      default=None)
genGroup.add_argument('--targetPort',
                      help='Port on which the client will create a TCP connection',
                      default=80,
                      type=int)

ipGroup = parser.add_argument_group('IP','Arguments for fuzzing IP layer')
ipGroup.add_argument('--defaultPayloadPath',
                     help='Path to the payload that will be sent to the server with each request',
                     default='./IP Settings/default_payload')
ipGroup.add_argument("--fversion", help="Will fuzz the version field in IP header",
                    action="store_true")
ipGroup.add_argument("--fihl", help="Will fuzz the IHL field in IP header",
                    action="store_true")
ipGroup.add_argument("--fdscp", help="Will fuzz the DSCP field in IP header",
                    action="store_true")
ipGroup.add_argument("--fflags", help="Will fuzz the Flags flags in IP header",
                    action="store_true")
ipGroup.add_argument("--ffrags", help="Will fuzz the Frags field in IP header",
                    action="store_true")
ipGroup.add_argument("--fttl", help="Will fuzz the TTL field in IP header",
                    action="store_true")
ipGroup.add_argument("--flen", help="Will fuzz the Length field in IP header",
                    action="store_true")

appGroup = parser.add_argument_group('Application','Arguments for fuzzing Application layer')
subparsers = parser.add_subparsers(dest="command")

parser_app_rand_fixed = subparsers.add_parser('app-rand-fixed', help='Used to do random fuzz testing of application of fixed packet size')
parser_app_rand_fixed.add_argument("numTests", help="Number of tests to run",type=int)
parser_app_rand_fixed.add_argument("payloadSize", help="The size of the fixed payload to include in each packet", type=int)

parser_app_rand_range = subparsers.add_parser('app-rand-range', help='Used to do random fuzz testing of application of variable packet size')
parser_app_rand_range.add_argument("numTests", help="Number of tests to run",type=int)
parser_app_rand_range.add_argument("payloadMinSize", help="The min size of the fixed payload to include in each packet",type=int)
parser_app_rand_range.add_argument("payloadMaxSize", help="The max size of the fixed payload to include in each packet",type=int)

parser_app_file = subparsers.add_parser('app-file', help='Used to do random fuzz testing of application of fixed packet size')
parser_app_file.add_argument("path", help="Path to the file which contains tests to run. Each line should contain the hex string representing bytes to send in a packet")

args = parser.parse_args()

class IPFuzz:
    def __init__(self,destinationIP,destinationPort,defaultMessage,sourceIP=None):
        self.destinationPort = destinationPort
        self.ip = IP(dst=destinationIP, src=sourceIP)
        self.sport = 3000
        self.msg = defaultMessage
        SYN = TCP(dport=self.destinationPort, sport=self.sport, flags='S')
        print ("Sending SYN")
        SYNACK = sr1(self.ip/SYN)
        self.seq = SYNACK.seq + 1
        self.ack = SYNACK.ack
        ACK = TCP(  dport=self.destinationPort, sport=self.sport, flags='A'
                  , seq=self.ack, ack=self.seq)
        print ("Sending ACK")
        send(self.ip / ACK)

    def fuzzTTL(self):
        for i in range(256):
            #self.ip.ttl = i
            print("Sending ttl=",i)
            pkt = self._sr1('hi' + str(i))

    def sendPayloads(self,payloads):
        for payload in payloads:
            self._sr1(payload)


    def _sr1(self,msg):
        REQ = self.ip / TCP(  dport=self.destinationPort, sport=self.sport, flags='PA'
                  , seq=self.ack , ack=self.seq) / msg

        ans, unans = sr(REQ, timeout=1.5)
        if len(ans.res):
            self.seq = ans.res[0][1].seq
            self.ack = ans.res[0][1].ack
        return ans

    def closeConnection(self):
        FIN = TCP(  sport=self.sport, dport=self.destinationPort, flags="FA"
                  , seq=self.ack, ack=self.seq)
        print ("Sending FIN")
        FINACK = sr1(self.ip/FIN)
        LASTACK = TCP(  sport=self.sport, dport=self.destinationPort, flags="A"
                      , seq=FINACK.ack, ack=FINACK.seq + 1)
        print ("Sending FINACK")
        send(self.ip/LASTACK)

def generateRandomPayloads(minLength,maxLength,numOfPayloads):
    ret = []
    for i in range(numOfPayloads):
        size = secrets.choice(range(minLength,maxLength+1))
        ret.append(hex_bytes(secrets.token_hex(size)))
    return ret

if __name__ == '__main__':
    f = open(args.defaultPayloadPath, "r")
    defaultPayload = f.read()
    try:
        ipFuzz = IPFuzz(destinationIP=args.targetIP,
                        destinationPort=args.targetPort,
                        defaultMessage=defaultPayload,
                        sourceIP=args.sourceIP)

        if args.command == 'app-rand-fixed':
            payloads = generateRandomPayloads(args.payloadSize, args.payloadSize, args.numTests)
            ipFuzz.sendPayloads(payloads)

        elif args.command == 'app-rand-range':
            payloads = generateRandomPayloads(args.payloadMinSize, args.payloadMaxSize, args.numTests)
            ipFuzz.sendPayloads(payloads)
    finally:
        ipFuzz.closeConnection()
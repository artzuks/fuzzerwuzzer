from inputParser import getParser
from fuzzerClient import Fuzz, IPFuzz
from utils import generateRandomPayloads
from ipFileReader import IPFile
from scapy.utils import hex_bytes

import time
import os




def readPayloadsFromFile(path):
    ret = []
    with open(path,'r') as f:
        for line in f:
            ret.append(hex_bytes(line.rstrip()))
    return ret

def savePayloadsToFile(payloads):
    path = 'fuzz_tests/' + str(time.time())
    dirname = os.path.dirname(path)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    with open(path,'w') as f:
        for payload in payloads:
            f.write(payload.hex() + '\n')

def sendAppPayloads(fuzz, payloads):
    fuzz.sendPayloads(payloads)
    validOutput = bytearray.fromhex("00")
    invalidOutput = bytearray.fromhex("ff")
    valid = 0
    invalid = 0
    other = 0

    for response in fuzz.responseBytes:
        if response == validOutput[0]:
            valid += 1
        elif response == invalidOutput[0]:
            invalid += 1
        else:
            other += 1

    print("Application testing done. Valid responses={} ; Invalid responses={} ; Unknown responses={}".format(valid,invalid,other))


def processIPFile(fuzz,path):
    parsedFile = IPFile(path)
    for packet in parsedFile.packets:
        fuzz.sendPacket(packet)

def processIPFuzz(fuzz,args):

    if args.fttl or args.fall:
        fuzz.fuzzTTL()
    if args.fversion or args.fall:
        fuzz.fuzzVersion()
    if args.fihl or args.fall:
        fuzz.fuzzIHL()
    if args.fdscp or args.fall:
        fuzz.fuzzDSCP()
    if args.fecn or args.fall:
        fuzz.fuzzECN()
    if args.flen or args.fall:
        fuzz.fuzzLength()
    if args.fid or args.fall:
        fuzz.fuzzID()
    if args.fflags or args.fall:
        fuzz.fuzzFlags()
    if args.ffrag or args.fall:
        fuzz.fuzzFrag()
    if args.fproto or args.fall:
        fuzz.fuzzProto()


if __name__ == '__main__':
    args = getParser().parse_args()



    if args.command == 'ip':
        with open(args.defaultPayloadPath, "r") as f:
            defaultPayload = f.read()
        ipfuzz = IPFuzz(destinationIP=args.targetIP,
                        destinationPort=args.targetPort,
                        defaultMessage=defaultPayload,
                        sourceIP=args.sourceIP)
        processIPFuzz(ipfuzz, args)
    elif args.command == 'ip-file':
        with open(args.defaultPayloadPath, "r") as f:
            defaultPayload = f.read()
        ipfuzz = IPFuzz(destinationIP=args.targetIP,
                        destinationPort=args.targetPort,
                        defaultMessage=defaultPayload,
                        sourceIP=args.sourceIP)
        processIPFile(ipfuzz, args.path)
    else:
        try:
            fuzz = Fuzz(destinationIP=args.targetIP,
                            destinationPort=args.targetPort,
                            sourceIP=args.sourceIP)
            if args.command == 'app-rand-fixed':
                payloads = generateRandomPayloads(args.payloadSize, args.payloadSize, args.numTests)
                savePayloadsToFile(payloads)
                fuzz.sendPayloads(payloads)

            elif args.command == 'app-rand-range':
                payloads = generateRandomPayloads(args.payloadMinSize, args.payloadMaxSize, args.numTests)
                savePayloadsToFile(payloads)
                fuzz.sendPayloads(payloads)
            elif args.command == 'app-file':
                payloads = readPayloadsFromFile(args.path)
                savePayloadsToFile(payloads)
                sendAppPayloads(fuzz,payloads)

        finally:
            fuzz.closeConnection()
from inputParser import getParser
from appFuzzer import AppFuzzer
from ipFuzzer import IPFuzzer
from utils import generateRandomPayloads
from ipFileReader import IPFile
from scapy.utils import hex_bytes

import time
import os



## App fuzzing

# Reads the payloads for app fuzzing
def readPayloadsFromFile(path):
    ret = []
    try:
        with open(path,'r') as f:
            for line in f:
                try:
                    ret.append(hex_bytes(line.rstrip()))
                except Exception as e:
                    print('Issue with the payload {}. Erorr: {}'.format(line,e))
    except Exception as e:
        print ('\nError opening file {}. Error: {}'.format(path,e))
        exit(1)
    return ret

# Saves random payloads to a file for future use/inspection
def savePayloadsToFile(payloads):
    path = 'fuzz_tests/' + str(time.time())
    dirname = os.path.dirname(path)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    with open(path,'w') as f:
        for payload in payloads:
            f.write(payload.hex() + '\n')

# Used for sending app payloads to the server
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



## IP fuzzing wrappers

# Processing of IP fuzzing based on file
def processIPFile(fuzz,path):
    parsedFile = IPFile(path)
    for packet in parsedFile.packets:
        fuzz.sendPacket(packet)

# Default IP testing
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



# Argument parsing and delegating to the appropriate fuzzer
if __name__ == '__main__':

    args = getParser().parse_args()

    if args.command == 'ip': # IP default Tests
        with open(args.defaultPayloadPath, "r") as f:
            defaultPayload = f.read()
        ipfuzz = IPFuzzer(destinationIP=args.targetIP,
                        destinationPort=args.targetPort,
                        defaultMessage=defaultPayload,
                        sourceIP=args.sourceIP)
        processIPFuzz(ipfuzz, args)
    elif args.command == 'ip-file': # IP tests from a file
        with open(args.defaultPayloadPath, "r") as f:
            defaultPayload = f.read()
        ipfuzz = IPFuzzer(destinationIP=args.targetIP,
                        destinationPort=args.targetPort,
                        defaultMessage=defaultPayload,
                        sourceIP=args.sourceIP)
        processIPFile(ipfuzz, args.path)
    else:
        # app fuzzing
        # General flow is to generate payloads, save them to a file, and send them to the server
        # If file is provided just read file and send to server
        try:
            fuzz = AppFuzzer(destinationIP=args.targetIP,
                            destinationPort=args.targetPort,
                            sourceIP=args.sourceIP)
            if args.command == 'app-rand-fixed': # App all payloads same size
                payloads = generateRandomPayloads(args.payloadSize, args.payloadSize, args.numTests)
                savePayloadsToFile(payloads)
                fuzz.sendPayloads(payloads)
            elif args.command == 'app-rand-range': # App variable payload size
                payloads = generateRandomPayloads(args.payloadMinSize, args.payloadMaxSize, args.numTests)
                savePayloadsToFile(payloads)
                fuzz.sendPayloads(payloads)
            elif args.command == 'app-file': # App payloads from file
                payloads = readPayloadsFromFile(args.path)
                savePayloadsToFile(payloads)
                sendAppPayloads(fuzz,payloads)
        finally:
            fuzz.closeConnection() # Close TCP connection with FIN in case it wasn't closed
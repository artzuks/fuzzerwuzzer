from scapy.all import *
import secrets

# Generates a list of random payloads given a min,max size of radnom values
def generateRandomPayloads(minLength,maxLength,numOfPayloads):
    ret = []
    for i in range(numOfPayloads):
        size = secrets.choice(range(minLength,maxLength+1))
        ret.append(hex_bytes(secrets.token_hex(size)))
    return ret

# Generates count random ints [0-max) and returns in a list
def generateRandomInts(max,count):
    ret = []
    for i in range(count):
        size = secrets.randbelow(max)
        ret.append(size)
    return ret

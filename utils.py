from scapy.utils import hex_bytes
import secrets

def generateRandomPayloads(minLength,maxLength,numOfPayloads):
    ret = []
    for i in range(numOfPayloads):
        size = secrets.choice(range(minLength,maxLength+1))
        ret.append(hex_bytes(secrets.token_hex(size)))
    return ret

def generateRandomInts(max,count):
    ret = []
    for i in range(count):
        size = secrets.randbelow(max)
        ret.append(size)
    return ret
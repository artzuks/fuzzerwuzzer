import socket
import sys
import signal
import binascii

MAX_PAYLOAD_LIMIT = 1024
matchedPayloads = 0
totalPayloads = 0

def readMatchPatternFromFile(path):
    """
    The function reads the given file and sets the matchPattern
    to that value for the duration of the service uptime. 

    If the pattern exceeds the MAX_PAYLOAD_LIMIT the function will
    throw an exception.
    """
    with open(path,'r') as fp:
        matchPattern = bytearray.fromhex(fp.read().strip())
        print("Pattern to match is {} and {} bytes long".format(binascii.hexlify(matchPattern),len(matchPattern)))
        if len(matchPattern) > MAX_PAYLOAD_LIMIT:
            raise Exception('Pattern for matching exceeds {}'.format(MAX_PAYLOAD_LIMIT))
        elif len(matchPattern) == 0:
            raise Exception('Pattern for matching cannot be 0 in length')
        return matchPattern

def checkPayloadForPattern(b,matchPattern):
    if len(b) < len(matchPattern):
        return False
  
    for i in range(len(matchPattern)):
        if matchPattern[i] != b[i]:
            return False

    return True
     


patternToMatch = readMatchPatternFromFile('./match_pattern')
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Bind the socket to the port
server_address = ('0.0.0.0', 3003)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)


def sigterm_handler(_signo, _stack_frame):
    # Raises SystemExit(0):
    print('{} valid payloads'.format(matchedPayloads))
    print('{} invalid payloads'.format(totalPayloads-matchedPayloads))
    sock.close()
    sys.exit(0)



signal.signal(signal.SIGINT, sigterm_handler)
signal.signal(signal.SIGTERM, sigterm_handler)       
    



while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        print('connection from', client_address)

        # Receive the data in small chunks and retransmit it
        buff = memoryview(bytearray(MAX_PAYLOAD_LIMIT))
        while True:
            
            numRecv = connection.recv_into(buff,MAX_PAYLOAD_LIMIT)
            if numRecv:
                print(bytes(buff[0:numRecv]))
                totalPayloads += 1
                if checkPayloadForPattern(bytes(buff[0:numRecv]),patternToMatch):
                    matchedPayloads += 1
                    connection.send(bytearray.fromhex("00"))
                else:
                    connection.send(bytearray.fromhex("ff"))
            else:
                print('no data from', client_address)
                break

    finally:
        # Clean up the connection
        connection.close()

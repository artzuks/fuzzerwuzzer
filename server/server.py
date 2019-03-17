import socket
import sys
import signal


def sigterm_handler(_signo, _stack_frame):
    # Raises SystemExit(0):
    sock.close()
    sys.exit(0)

matchPattern = ''
MAX_PAYLOAD_LIMIT = 1024
def readMatchPatternFromFile(path):
    """
    The function reads the first line of the given file
    and sets the matchPattern to that value for the duration of 
    the service uptime. 

    If the pattern exceeds the MAX_PAYLOAD_LIMIT the function will
    throw an exception.
    """
    with open(path,'r') as fp:
        matchPattern = fp.readline()
        if len(matchPattern) > MAX_PAYLOAD_LIMIT:
            raise Exception('Pattern for matching exceeds {}'.format(MAX_PAYLOAD_LIMIT))
        elif len(matchPattern) == 0:
            raise Exception('Pattern for matching cannot be 0 in length')


readMatchPatternFromFile('./match_pattern')
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('0.0.0.0', 3000)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)

# Listen for incoming connections
sock.listen(3)
signal.signal(signal.SIGINT, sigterm_handler)
signal.signal(signal.SIGTERM, sigterm_handler)       
    



while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    signal.signal(signal.SIGINT, connection.close)
    signal.signal(signal.SIGTERM, connection.close)       
    try:
        print('connection from', client_address)

        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(1024)
            print('received {!r}'.format(data))
            if data:
                print('sending data back to the client')
                #connection.sendall(data)
            else:
                print('no data from', client_address)
                break

    finally:
        # Clean up the connection
        connection.close()

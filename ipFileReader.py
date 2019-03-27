
class IPHeader:
    def __init__(self):
        self.version = 4
        self.ihl = 0
        self.dscp = 1
        self.ecn = 0
        self.len = 50
        self.id = 1
        self.flags = 0
        self.frag = 0
        self.ttl = 54
        self.proto = 6

class IPFile():
    def __init__(self,path):
        self.path = path
        self.packets = []
        self.parse()

    def parse(self):
        with open(self.path, "r") as f:
            for line in f:
                ipHeader = IPHeader()
                params = line.rstrip().split()
                for param in params:
                    splitParam = param.split(":")
                    if len(splitParam) != 2:
                        print("Invalid Param:", param)
                        continue
                    paramName = splitParam[0]
                    try:
                        paramValue = int(splitParam[1])
                    except:
                        print("Value must be an integer > 0", paramValue)
                    
                    if paramName == 'version':
                        if paramValue >= 0 and paramValue <= 15:
                            ipHeader.version = paramValue
                        else:
                            print('Value of version needs to be between 0 and 15')
                    elif paramName == 'ihl':
                        if paramValue >= 0 and paramValue <= 15:
                            ipHeader.ihl = paramValue
                        else:
                            print('Value of ihl needs to be between 0 and 15')
                    elif paramName == 'dscp':
                        if paramValue >= 0 and paramValue <= 63:
                            ipHeader.dscp = paramValue
                        else:
                            print('Value of ihl needs to be between 0 and 63')
                    elif paramName == 'ecn':
                        if paramValue >= 0 and paramValue <= 3:
                            ipHeader.ecn = paramValue
                        else:
                            print('Value of ecn needs to be between 0 and 3')
                    elif paramName == 'len':
                        if paramValue >= 0 and paramValue <= 65535:
                            ipHeader.len = paramValue
                        else:
                            print('Value of len needs to be between 0 and 65535')
                    elif paramName == 'id':
                        if paramValue >= 0 and paramValue <= 65535:
                            ipHeader.id = paramValue
                        else:
                            print('Value of id needs to be between 0 and 65535')
                    elif paramName == 'flags':
                        if paramValue >= 0 and paramValue <= 7:
                            ipHeader.flags = paramValue
                        else:
                            print('Value of flags needs to be between 0 and 7')
                    elif paramName == 'frag':
                        if paramValue >= 0 and paramValue <= 8191:
                            ipHeader.frag = paramValue
                        else:
                            print('Value of frag needs to be between 0 and 8191')
                    elif paramName == 'ttl':
                        if paramValue >= 0 and paramValue <= 255:
                            ipHeader.ttl = paramValue
                        else:
                            print('Value of ttl needs to be between 0 and 255')
                    elif paramName == 'proto':
                        if paramValue >= 0 and paramValue <= 255:
                            ipHeader.proto = paramValue
                        else:
                            print('Value of proto needs to be between 0 and 255')
                    else:
                        print("Unknown header field {} with value {} provided".format(paramName,paramValue))
                self.packets.append(ipHeader)

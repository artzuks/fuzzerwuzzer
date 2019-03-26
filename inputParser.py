import argparse

def getParser():

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

    subparsers = parser.add_subparsers(dest="command")
    #Parser for application fuzz - random fixed size inputs
    parser_app_rand_fixed = subparsers.add_parser('app-rand-fixed', help='Used to do random fuzz testing of application of fixed packet size')
    parser_app_rand_fixed.add_argument("numTests", help="Number of tests to run",type=int)
    parser_app_rand_fixed.add_argument("payloadSize", help="The size of the fixed payload to include in each packet", type=int)

    #Parser for application fuzz - random range size inputs
    parser_app_rand_range = subparsers.add_parser('app-rand-range', help='Used to do random fuzz testing of application of variable packet size')
    parser_app_rand_range.add_argument("numTests", help="Number of tests to run",type=int)
    parser_app_rand_range.add_argument("payloadMinSize", help="The min size of the fixed payload to include in each packet",type=int)
    parser_app_rand_range.add_argument("payloadMaxSize", help="The max size of the fixed payload to include in each packet",type=int)

    #Parser for application fuzz - input file
    parser_app_file = subparsers.add_parser('app-file', help='Used to do random fuzz testing of application of fixed packet size')
    parser_app_file.add_argument("path", help="Path to the file which contains tests to run. Each line should contain the hex string representing bytes to send in a packet")

    #Parser for IP layer fuzz
    parser_app_ip = subparsers.add_parser('ip', help='Used to fuzz the IP later of the packet')

    parser_app_ip.add_argument('--defaultPayloadPath',
                          help='Path to the payload that will be sent to the server with each request',
                          default='./IP Settings/default_payload')

    parser_app_ip.add_argument("--fversion", help="Will fuzz the version field in IP header",
                         action="store_true")
    parser_app_ip.add_argument("--fihl", help="Will fuzz the IHL field in IP header",
                         action="store_true")
    parser_app_ip.add_argument("--fdscp", help="Will fuzz the DSCP field in IP header",
                         action="store_true")
    parser_app_ip.add_argument("--fecn", help="Will fuzz the ECN field in IP header",
                               action="store_true")
    parser_app_ip.add_argument("--flen", help="Will fuzz the Length field in IP header",
                               action="store_true")
    parser_app_ip.add_argument("--fid", help="Will fuzz the ID field in IP header",
                               action="store_true")
    parser_app_ip.add_argument("--fflags", help="Will fuzz the Flags flags in IP header",
                         action="store_true")
    parser_app_ip.add_argument("--ffrags", help="Will fuzz the Frags field in IP header",
                         action="store_true")
    parser_app_ip.add_argument("--fttl", help="Will fuzz the TTL field in IP header",
                         action="store_true")


    return parser


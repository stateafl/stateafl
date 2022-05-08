#!/usr/bin/python3

import sys
import os
import argparse
import pyshark

parser = argparse.ArgumentParser()
parser.add_argument('--input', help="Input file (PCAP)", required=True)
parser.add_argument('--server-port', type=int, help="Server port number", required=True)
parser.add_argument('--output', help="Output file (AFLnet replay format)")

args = parser.parse_args()


PCAP = args.input
SERVER_PORT=args.server_port

cap = None

try:
    cap = pyshark.FileCapture(PCAP)
except Exception as e:
    print("Error: Unable to parse PCAP file")
    print(e)
    sys.exit(1)

if (SERVER_PORT < 0 or 
    SERVER_PORT > 65353):
    print("Error: Invalid server port number")
    sys.exit(1)



if args.output is not None:
    OUTPUT = args.output
else:
    OUTPUT = os.path.splitext(os.path.basename(PCAP))[0] + ".out"


total_messages = 0
request_msg = bytearray()
ports = {}

try:
    with open(OUTPUT,"wb") as output:

        for pkt in cap:

            try:
                if 'TCP' or 'UDP' in pkt:

                    srcport = int.from_bytes(pkt.tcp.srcport.binary_value, "big")
                    dstport = int.from_bytes(pkt.tcp.dstport.binary_value, "big")

                    ports[srcport] = 1
                    ports[dstport] = 1

                    if srcport != SERVER_PORT and dstport != SERVER_PORT:
                        print("Error: Extraneous TCP/IP flow detected")
                        print("Please check that the PCAP file only contains traffic from/to SERVER_PORT")
                        sys.exit(1)

                    if len(ports) > 2:
                        print("Error: Multiple client/server flows detected")
                        print("Please check that the PCAP file only contains traffic for only one client")
                        sys.exit(1)

                    if dstport == SERVER_PORT:
                        request_msg.extend(pkt.data.data.binary_value)

                    if (('TCP' in pkt and dstport != SERVER_PORT) or
                       ('UDP' in pkt)) and len(request_msg) > 0:

                        print(f'Writing {len(request_msg)} bytes...')
                        output.write(int.to_bytes(len(request_msg), 4, "little"))
                        output.write(request_msg)

                        request_msg = bytearray()
                        total_messages += 1

            except AttributeError:
                pass

except IOError as e:
    print("Error: Unable to write output file")
    print(e)
    sys.exit(1)

if total_messages == 0:
    print("Error: No messages found")
    sys.exit(1)

print(f"Converted PCAP saved to {OUTPUT}")

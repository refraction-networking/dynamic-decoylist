#!/usr/bin/python
from client_conf_pb2 import ClientConf, AES_GCM_128, PubKey, TLSDecoySpec, DecoyList
import argparse
import sys
import csv
import netaddr

parser = argparse.ArgumentParser(description='Create a protobuf blob ClientConfig')
parser.add_argument("-k", "--key", help="default decoy public key", required=True, nargs=1)
parser.add_argument("-d", "--decoys", help="CSV of decoys", default='-', nargs='?')
parser.add_argument('-g', '--generation', help='set the generation number', default=1, type=int)
parser.add_argument('-p', '--pretty', help='pretty-print the output', dest='pretty', action='store_true')
parser.add_argument("-a", "--asn", help="CSV of asn,keyfilename for non-default keyed ASes", default='', nargs='?')

parser.set_defaults(pretty=False)
args = parser.parse_args()

message = ClientConf()
message.generation = args.generation
message.default_pubkey.type = AES_GCM_128
with open(args.key[0], 'rb') as f:
     message.default_pubkey.key = f.read()

asMap = {}
if args.asn != '':
    with open(args.asn, 'r') as csvfile:
        reader  = csv.reader(csvfile)
        for row in reader:
            assert(len(row) == 2)
            with open(row[1], 'rb') as f:
                asMap[int(row[0])] = f.read()

csvfile = sys.stdin
if args.decoys != '-':
    csvfile = open(args.decoys, 'r')

for line in csvfile:
    if len(line) < 1 or '#' == line[0]:
        continue
    current = message.decoy_list.tls_decoys.add()
    fields = [x.strip() for x in line.split(',')]
    current.hostname = fields[1]
    current.ipv4addr =  int(netaddr.IPAddress(fields[0]))
    asNum = int(fields[2])
    if asNum in asMap:
        current.pubkey.type = AES_GCM_128
        current.pubkey.key = asMap[asNum]
    else:
        current.pubkey.type = message.default_pubkey.type
        current.pubkey.key = message.default_pubkey.key
    current.timeout = int(fields[3])
    current.tcpwin = int(fields[4])
if args.pretty:
    print(message)
else:
    outFile = open('../list/' + args.decoys + '.blob', 'wb')
    outFile.write(message.SerializeToString())
    # sys.stdout.write(message.SerializeToString())

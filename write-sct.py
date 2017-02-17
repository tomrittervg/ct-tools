#!/usr/bin/env python

import struct
import base64
import argparse

LOGS = {
	'aviator' : base64.b64decode("aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q="),
	'pilot' : base64.b64decode("pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA="),
	'rocketeer' : base64.b64decode("7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs="),
	'digicert' : base64.b64decode("VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0="),
	'izenpen' : base64.b64decode("dGG0oJz7PUHXUVlXWy52SaRFqNJ3CbDMVkpkgrfrQaM="),
	'certly' : base64.b64decode("zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA="),
	'venafi' : base64.b64decode("rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0="),
        'digicert' : base64.b64decode("VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0="),
        'skydiver' : base64.b64decode("u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU="),
        'icarus' : base64.b64decode("KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg="),
        'vega' : base64.b64decode("vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU="),
        'wosign' : base64.b64decode("QbLcLonmPOSvG6e7Kb9oxt7m+fHMBH4w3/rjs7olkmM="),
        'cnnic' : base64.b64decode("pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg="),
        'startssl' : base64.b64decode("NLtq1sPfnAPuqKSZ/3iRSGydXlysktAfe/0bzhnbSO8="),
        'certificatetransparency.cn' : base64.b64decode("4BJ2KekEllZOPQFHmESYqkj4rbFmAOt5AqHvmQmQYnM="),
        'venafigen2' : base64.b64decode("AwGd8/2FppqOvR+sxtqbpz5Gl3T+d/V5/FoIuDKMHWs="),
}

parser = argparse.ArgumentParser(description='Write a SCT')
parser.add_argument("--out", type=argparse.FileType('w'), help="file to write out to")
parser.add_argument("--stdout", action="store_true", help="write to stdout, to be used in echo \"...\" | base64 -d > file")
parser.add_argument("--log", type=str, required=True)
parser.add_argument("--time", "--timestamp", type=int, required=True, help="Timestamp from the JSON response.")
parser.add_argument("--sig", type=str, required=True, help="Signature value from the JSON response, base64 encoded")

args = parser.parse_args()
if not args.out and not args.stdout:
    parser.print_usage()
    print "\nError: Either --out or --stdout must be specified"
    exit(-1)
if args.log not in LOGS:
    print "Error: log not known. Choose one of", str(LOGS.keys())
    exit(-1)

sct = ""

#SCT Version 1 (1 Byte, 0x00)
sct += "\x00"

#SCT Log ID (32 Bytes)
sct += LOGS[args.log]

if len(sct) != 33:
    raise Exception("SCT Building has gone wrong.")

#Timestamp (8 Bytes)
sct += struct.pack(">Q", args.time)

#Extensions Length (No extensions, 2 bytes)
sct += "\x00\x00"

if len(sct) != 43:
    raise Exception("SCT Building has gone wrong..")

#Signature (Includes the Hash, Signature, SigLength, and SigData)
sct += base64.b64decode(args.sig)

#Write it all out to a file
if args.stdout:
    print base64.b64encode(sct)
elif args.out:
    args.out.write(sct)
else:
    raise Exception("Unexpected program mode")

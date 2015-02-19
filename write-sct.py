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
	'certly' : base64.b64decode("zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA=")
}

parser = argparse.ArgumentParser(description='Write a SCT')
parser.add_argument("--out", type=argparse.FileType('w'), help="file to write out to")
parser.add_argument("--stdout", action="store_true", help="write to stdout, to be used in echo \"...\" | base64 -d > file")
parser.add_argument("--log", choices=['aviator', 'pilot', 'rocketeer', 'certly', 'digicert', 'izenpen'], required=True)
parser.add_argument("--time", "--timestamp", type=int, required=True, help="Timestamp from the JSON response.")
parser.add_argument("--sig", type=str, required=True, help="Signature value from the JSON response, base64 encoded")

args = parser.parse_args()
if not args.out and not args.stdout:
    parser.print_usage()
    print "\nError: Either --out or --stdout must be specified"
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

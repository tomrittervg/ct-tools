#!/usr/bin/env python

import struct
import base64
import argparse
import datetime

LOGS = {
	'aviator' : base64.b64decode("aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q="),
	'pilot' : base64.b64decode("pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA="),
	'rocketeer' : base64.b64decode("7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs="),
	'digicert' : base64.b64decode("VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0="),
	'izenpen' : base64.b64decode("dGG0oJz7PUHXUVlXWy52SaRFqNJ3CbDMVkpkgrfrQaM="),
	'certly' : base64.b64decode("zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA="),
	'venafi' : base64.b64decode("rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0="),
        'digicert' : base64.b64decode("VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0="),
        'skydiver' : base64.b64decode("u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=")
}

parser = argparse.ArgumentParser(description='Read a SCT')
parser.add_argument("--sct", type=str, required=False, help="The SCT to Read, in base64")
parser.add_argument("--file", type=str, required=False, help="The SCT File to Read")

args = parser.parse_args()

if args.sct:
    sct = base64.b64decode(args.sct)
elif args.file:
    sct = "".join(open(args.file).readlines())
else:
    raise Exception("Must specify sct on command line or file")

#Version
print "SCT Version: " + str(ord(sct[0]))

#Log ID
log = sct[1:33]
found_log = False
for l in LOGS:
    if LOGS[l] == log:
        print "Log: " + l
        found_log = True
if not found_log:
    print "Log: Unknown (" + base64.b64encode(log) + ")"
    
#Timestamp (8 Bytes)
timestamp = struct.unpack(">Q", sct[33:41])[0]
print "Timestamp: " + str(datetime.datetime.fromtimestamp(timestamp / 1000))


#Extensions
if ord(sct[41]) == 0 and ord(sct[42]) == 0:
    print "No extensions"
else:
    print "Extensions?!?!?!"

#Signature (Includes the Hash, Signature, SigLength, and SigData)
print "Signature: " + base64.b64encode(sct[43:])

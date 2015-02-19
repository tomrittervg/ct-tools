#!/usr/bin/env python

import json
import argparse
import requests


LOGS = {
	'aviator' : "http://ct.googleapis.com/aviator",
	'pilot' : "http://ct.googleapis.com/pilot",
	'rocketeer' : "http://ct.googleapis.com/rocketeer",
	"digicert" : "http://ct1.digicert-ct.com/log",
	"izenpen" :"http://ct.izenpe.com",
	"certly" : "http://log.certly.io"
}

parser = argparse.ArgumentParser(description='Submit a certificate to logs')
parser.add_argument("--cert", type=argparse.FileType('r'), action="append", required=True, 
	help="Certificate chain. Specify multiple times, start with the leaf, continuing to the root.")
parser.add_argument("--log", action='append', 
	choices=['aviator', 'pilot', 'rocketeer', 'digicert', 'izenpen', 'certly'], 
	help="logs to submit the cert to. Specify multiple times for explicit choice, or leave blank for all.")

args = parser.parse_args()

certdata = []
for c in args.cert:
	lines = ''.join(c.readlines())
	lines = lines.replace("-----BEGIN CERTIFICATE-----", "")
	lines = lines.replace("-----END CERTIFICATE-----", "")
	lines = lines.replace("\r", "")
	lines = lines.replace("\n", "")
	certdata.append(lines)

	
data =  '{"chain" : ["' + '", "'.join(certdata) + '"]}'
for l in LOGS:
	if not args.log or l in args.log:
		try:
			r = requests.post(LOGS[l] + "/ct/v1/add-chain", data)
			if r.status_code != 200:
				print "Error while submitting to", l
				print r.text
			else:
				r = json.loads(r.text)
				print l
				print "\tTimestamp", r['timestamp']
				print "\tSignature", r['signature']
		except:
			print "Error communicating with", l
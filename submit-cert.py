#!/usr/bin/env python

import sys
import json
import argparse
import requests

try:
	from requests.packages.urllib3.exceptions import InsecureRequestWarning
	requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
	pass

LOGS = {
	'pilot' : 'https://ct.googleapis.com/pilot',
	'aviator' : 'https://ct.googleapis.com/aviator',
	'rocketeer' : 'https://ct.googleapis.com/rocketeer',
	'icarus' : 'https://ct.googleapis.com/icarus',
	'skydiver' : 'https://ct.googleapis.com/skydiver',
#	'certly Log Server' : 'https://log.certly.io',
	'symantec' : 'https://ct.ws.symantec.com',
	'digicert' : 'https://ct1.digicert-ct.com/log',
	#'Google \'Submariner\' log' : 'https://ct.googleapis.com/submariner',
#	'Izenpe Log Server' :'https://ct.izenpe.com',
	'venafi' : 'https://ctlog.api.venafi.com',
	'vega' : 'https://vega.ws.symantec.com',
	'cnnic' : 'https://ctserver.cnnic.cn',
	'startssl' : 'https://ct.startssl.com',
	#'GDCA CT Log Server' : 'https://ct.gdca.com.cn',
	'wosign' : 'https://ct.wosign.com',
	#'Akamai Log' : 'https://ct.akamai.com',
	'certificatetransparency.cn' : 'https://www.certificatetransparency.cn/ct',
	'venafigen2' : 'http://ctlog-gen2.api.venafi.com',
}

parser = argparse.ArgumentParser(description='Submit a certificate to logs')
parser.add_argument("--cert", type=argparse.FileType('r'), action="append", required=True, 
	help="Certificate chain. Specify multiple times, start with the leaf, continuing to the root.")
parser.add_argument("--log", action='append', type=str,
	help="logs to submit the cert to. Specify multiple times for explicit choice, or leave blank for all.")

args = parser.parse_args()

certdata = []
num_certs = 0
for c in args.cert:
	lines = ''.join(c.readlines())
	if lines.count('-----BEGIN CERTIFICATE-----') > 1:
		print "Error: Specify one certificate per file, with multiple --cert arguments, in the order of leaf, intermediate, root"
		sys.exit(-1)
	lines = lines.replace("-----BEGIN CERTIFICATE-----", "")
	lines = lines.replace("-----END CERTIFICATE-----", "")
	lines = lines.replace("\r", "")
	lines = lines.replace("\n", "")
	certdata.append(lines)

	
data =  '{"chain" : ["' + '", "'.join(certdata) + '"]}'

for l in LOGS:
	if not args.log or [x for x in args.log if x in l.lower()]:
		try:
			r = requests.post(LOGS[l] + "/ct/v1/add-chain", data=data, verify=False, timeout=2)
			if r.status_code != 200:
				print("Error {0} while submitting to {1}".format(r.status_code, l))
				print(r.text)
			else:
				r = json.loads(r.text)
				print(l)
				print("\tTimestamp", r['timestamp'])
				print("\tSignature", r['signature'])
				print("\tCommand: ./write-sct.py --stdout --time " + str(r['timestamp']) + " --sig " + str(r['signature']) + " --log " + l)
		except Exception as e:
			print("Error communicating with", l)
			print(e)

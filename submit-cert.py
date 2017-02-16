#!/usr/bin/env python

import json
import argparse
import requests


LOGS = {
	'Google \'Pilot\' log' : 'https://ct.googleapis.com/pilot',
	'Google \'Aviator\' log' : 'https://ct.googleapis.com/aviator',
	'Google \'Rocketeer\' log' : 'https://ct.googleapis.com/rocketeer',
	'Google\'Icarus\' Log' : 'https://ct.googleapis.com/icarus',
	'Google \'Skydiver\' Log' : 'https://ct.googleapis.com/skydiver',
#	'Certly Log Server' : 'https://log.certly.io',
	'Symantec Log Server' : 'https://ct.ws.symantec.com',
	'DigiCert Log Server' : 'https://ct1.digicert-ct.com/log',
	#'Google \'Submariner\' log' : 'https://ct.googleapis.com/submariner',
#	'Izenpe Log Server' :'https://ct.izenpe.com',
	'Venafi CT Log Server' : 'https://ctlog.api.venafi.com',
	'Symantec VEGA Log Server' : 'https://vega.ws.symantec.com',
#	'CNNIC CT Log Server' : 'https://ctserver.cnnic.cn',
#	'StartSSL' : 'http://ct.startssl.com',
	#'GDCA CT Log Server' : 'https://ct.gdca.com.cn',
	#'WoSign CT Log Server' : 'https://ct.wosign.com',
	#'Akamai Log' : 'https://ct.akamai.com',
}

parser = argparse.ArgumentParser(description='Submit a certificate to logs')
parser.add_argument("--cert", type=argparse.FileType('r'), action="append", required=True, 
	help="Certificate chain. Specify multiple times, start with the leaf, continuing to the root.")
parser.add_argument("--log", action='append', 
	choices=['aviator', 'pilot', 'rocketeer', 'digicert', 'izenpen', 'certly', 'venafi', 'skydiver', 'icarus'], 
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
	if not args.log or [x for x in args.log if x in l.lower()]:
		try:
			r = requests.post(LOGS[l] + "/ct/v1/add-chain", data=data, verify=requests.certs.where(), timeout=2)
			if r.status_code != 200:
				print("Error {0} while submitting to {1}".format(r.status_code, l))
				print(r.text)
			else:
				r = json.loads(r.text)
				print(l)
				print("\tTimestamp", r['timestamp'])
				print("\tSignature", r['signature'])
				print("\tID", r['id'])
				print("\tExtensions", r['extensions'])
				print("\tSCT Version", r['sct_version'])
		except Exception as e:
			print("Error communicating with", l)
			print(e)

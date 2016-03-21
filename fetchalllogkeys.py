#!/usr/bin/python

import os
import sys
import json
import requests
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fetch log keys from Google\'s CT Page')
    parser.add_argument("--out", help="Directory to store keys to", required=True)
    args = parser.parse_args()
    if os.path.exists(args.out) and not os.path.isdir(args.out):
        print "Error: Output directory is not a directory!"
        sys.exit(-1)
    elif not os.path.exists(args.out):
        os.mkdir(args.out)

    logs = requests.get("https://www.certificate-transparency.org/known-logs/all_logs_list.json?attredirects=0&d=1")
    logs = json.loads(logs.text)
    for l in logs['logs']:
        name = l['description'].replace(" ", "_").replace("'", "")
        url = "https://" + l['url'] + "/"
        key = l['key']
       
        keyout = os.path.join(args.out, name + ".pem")
        print "Writing", keyout
        keyout = open(keyout, "w")
        keyout.write("-----BEGIN PUBLIC KEY-----\n")
        keyout.write(key + "\n")
        keyout.write("-----END PUBLIC KEY-----\n")
        keyout.write(url)

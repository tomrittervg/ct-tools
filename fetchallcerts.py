#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014, NORDUnet A/S.
# See LICENSE for licensing information.

import argparse
import urllib2
import urllib
import json
import base64
import sys
import struct
import hashlib
import itertools
from certtools import *
import zipfile
import os
import time

parser = argparse.ArgumentParser(description='')
parser.add_argument('baseurl', help="Base URL for CT server")
parser.add_argument('--store', default=None, metavar="dir", help='Store certificates in directory dir')
parser.add_argument('--write-sth', action='store_true', help='Write STH')
parser.add_argument('--no-check-signature', action='store_true', help='Don\'t check signature')
parser.add_argument('--publickey', default=None, metavar="file", help='Public key for the CT log')
parser.add_argument('--cafile', default=None, metavar="file", help='File containing the CA cert')
args = parser.parse_args()

create_ssl_context(cafile=args.cafile)

def get_entries_wrapper(baseurl, start, end):
    fetched_entries = 0
    while start + fetched_entries < (end + 1):
        print "fetching from", start + fetched_entries
        entries = get_entries(baseurl, start + fetched_entries, end)["entries"]
        if len(entries) == 0:
            break
        for entry in entries:
            fetched_entries += 1
            yield entry

def print_layer(layer):
    for entry in layer:
        print base64.b16encode(entry)

logpublickey = get_public_key_from_file(args.publickey) if args.publickey else None

sth = get_sth(args.baseurl)
if not args.no_check_signature:
    check_sth_signature(args.baseurl, sth, publickey=logpublickey)
tree_size = sth["tree_size"]
root_hash = base64.decodestring(sth["sha256_root_hash"])

try:
    if args.store:
        oldsth = json.load(open(args.store + "/currentsth"))
    else:
        oldsth = None
except IOError:
    oldsth = None

sth_timestamp = datetime.datetime.fromtimestamp(sth["timestamp"]/1000)
since_timestamp = time.time() - sth["timestamp"]/1000

print "Log last updated %s, %d seconds ago" % (sth_timestamp.ctime(), since_timestamp)

print "tree size", tree_size
print "root hash", base64.b16encode(root_hash)

if oldsth:
    if oldsth["tree_size"] == tree_size:
        print "Tree size has not changed"
        if oldsth["sha256_root_hash"] != sth["sha256_root_hash"]:
            print "Root hash is different even though tree size is the same."
            print "Log has violated the append-only property."
            print "Old hash:", oldsth["sha256_root_hash"]
            print "New hash:", sth["sha256_root_hash"]
            sys.exit(1)
        if oldsth["timestamp"] == sth["timestamp"]:
            print "Timestamp has not changed"
    else:
        print "Tree size changed, old tree size was", oldsth["tree_size"]

merkle_64klayer = []

if args.store:
    ncerts = None
    for blocknumber in range(0, (tree_size / 65536) + 1):
        (resulttype, result) = get_merkle_hash_64k(args.store, blocknumber, write_to_cache=True)
        if resulttype == "incomplete":
            (incompletelength, hash) = result
            ncerts = blocknumber * 65536 + incompletelength
            break
        assert resulttype == "hash"
        hash = result
        merkle_64klayer.append(hash)
        print blocknumber * 65536,
        sys.stdout.flush()
    print
    print "ncerts", ncerts
else:
    ncerts = 0

entries = get_entries_wrapper(args.baseurl, ncerts, tree_size - 1)

if not args.store:
    layer0 = [get_leaf_hash(base64.decodestring(entry["leaf_input"])) for entry in entries]

    tree = build_merkle_tree(layer0)

    calculated_root_hash = tree[-1][0]

else:
    currentfilename = None
    zf = None
    for entry, i in itertools.izip(entries, itertools.count(ncerts)):
        try:
            (chain, timestamp, issuer_key_hash) = extract_original_entry(entry)
            zipfilename = args.store + "/" + ("%04d.zip" % (i / 10000))
            if zipfilename != currentfilename:
                if zf:
                    zf.close()
                zf = zipfile.ZipFile(zipfilename, "a",
                                     compression=zipfile.ZIP_DEFLATED)
                currentfilename = zipfilename
            s = ""
            s += "Timestamp: %s\n" % timestamp
            leaf_input = base64.decodestring(entry["leaf_input"])
            leaf_hash = get_leaf_hash(leaf_input)
            s += "Leafhash: %s\n" % base64.b16encode(leaf_hash)
            if issuer_key_hash:
                s += "-----BEGIN PRECERTIFICATE-----\n"
                s += base64.encodestring(chain[0]).rstrip() + "\n"
                s += "-----END PRECERTIFICATE-----\n"
                s += "\n"
                chain = chain[1:]
            for cert in chain:
                s += "-----BEGIN CERTIFICATE-----\n"
                s += base64.encodestring(cert).rstrip() + "\n"
                s += "-----END CERTIFICATE-----\n"
                s += "\n"
            zf.writestr("%08d" % i, s)
        except AssertionError, e:
            print "error for cert", i, e
    if zf:
        zf.close()

    for blocknumber in range(ncerts / 65536, (tree_size / 65536) + 1):
        (resulttype, result) = get_merkle_hash_64k(args.store, blocknumber, write_to_cache=True)
        if resulttype == "incomplete":
            (incompletelength, hash) = result
            ncerts = blocknumber * 65536 + incompletelength
            merkle_64klayer.append(hash)
            break
        assert resulttype == "hash"
        hash = result
        merkle_64klayer.append(hash)
        print blocknumber * 65536, base64.b16encode(hash)

    tree = build_merkle_tree(merkle_64klayer)

    calculated_root_hash = tree[-1][0]

    assert ncerts == tree_size

print "calculated root hash", base64.b16encode(calculated_root_hash)

if oldsth and oldsth["tree_size"] > 0 and oldsth["tree_size"] != tree_size:
    consistency_proof = [base64.decodestring(entry) for entry in get_consistency_proof(args.baseurl, oldsth["tree_size"], tree_size)]
    (old_treehead, new_treehead) = verify_consistency_proof(consistency_proof, oldsth["tree_size"], tree_size, base64.b64decode(oldsth["sha256_root_hash"]))
    assert old_treehead == base64.b64decode(oldsth["sha256_root_hash"])
    assert new_treehead == base64.b64decode(sth["sha256_root_hash"])

if calculated_root_hash != root_hash:
    print "fetched root hash and calculated root hash different"
    sys.exit(1)

if args.store and args.write_sth:
    f = open(args.store + "/currentsth", "w")
    f.write(json.dumps(sth))
    f.close()

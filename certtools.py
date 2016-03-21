# Copyright (c) 2014, NORDUnet A/S.
# See LICENSE for licensing information.

import subprocess
import json
import base64
import urllib
import urllib2
import ssl
import urlparse
import struct
import sys
import hashlib
import ecdsa
import datetime
import cStringIO
import zipfile
import shutil
from certkeys import publickeys

def get_cert_info(s):
    p = subprocess.Popen(
        ["openssl", "x509", "-noout", "-subject", "-issuer", "-inform", "der"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    parsed = p.communicate(s)
    if parsed[1]:
        print "ERROR:", parsed[1]
        sys.exit(1)
    result = {}
    for line in parsed[0].split("\n"):
        (key, sep, value) = line.partition("=")
        if sep == "=":
            result[key] = value
    return result


def get_pemlike(filename, marker):
    return get_pemlike_from_file(open(filename), marker)

def get_pemlike_from_file(f, marker):
    entries = []
    entry = ""
    inentry = False

    for line in f:
        line = line.strip()
        if line == "-----BEGIN " + marker + "-----":
            entry = ""
            inentry = True
        elif line == "-----END " + marker + "-----":
            entries.append(base64.decodestring(entry))
            inentry = False
        elif inentry:
            entry += line
    return entries

def get_certs_from_file(certfile):
    return get_pemlike(certfile, "CERTIFICATE")

def get_certs_from_string(s):
    f = cStringIO.StringIO(s)
    return get_pemlike_from_file(f, "CERTIFICATE")

def get_precerts_from_string(s):
    f = cStringIO.StringIO(s)
    return get_pemlike_from_file(f, "PRECERTIFICATE")

def get_eckey_from_file(keyfile):
    keys = get_pemlike(keyfile, "EC PRIVATE KEY")
    assert len(keys) == 1
    return keys[0]

def get_public_key_from_file(keyfile):
    keys = get_pemlike(keyfile, "PUBLIC KEY")
    assert len(keys) == 1
    return keys[0]

def get_root_cert(issuer):
    accepted_certs = \
        json.loads(open("googlelog-accepted-certs.txt").read())["certificates"]

    root_cert = None

    for accepted_cert in accepted_certs:
        subject = get_cert_info(base64.decodestring(accepted_cert))["subject"]
        if subject == issuer:
            root_cert = base64.decodestring(accepted_cert)

    return root_cert

class sslparameters:
    sslcontext = None

def create_ssl_context(cafile=None):
    try:
        sslparameters.sslcontext = ssl.create_default_context(cafile=cafile)
    except AttributeError:
        sslparameters.sslcontext = None

def get_opener():
    try:
        opener = urllib2.build_opener(urllib2.HTTPSHandler(context=sslparameters.sslcontext))
    except TypeError:
        opener = urllib2.build_opener(urllib2.HTTPSHandler())
    return opener

def urlopen(url, data=None):
    return get_opener().open(url, data)

def pyopenssl_https_get(url):
    """
    HTTPS GET-function to use when running old Python < 2.7
    """
    from OpenSSL import SSL
    import socket

    # TLSv1 is the best we can get on Python 2.6
    context = SSL.Context(SSL.TLSv1_METHOD)
    sock = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    url_without_scheme = url.split('https://')[-1]
    host = url_without_scheme.split('/')[0]
    path = url_without_scheme.split('/', 1)[1]
    http_get_request = ("GET /{path} HTTP/1.1\r\n"
                        "Host: {host}\r\n"
                        "\r\n"
                        ).format(path=path, host=host)

    sock.connect((host, 443))
    sock.write(http_get_request)
    response = sock.recv(1024)
    response_lines = response.rsplit('\n')

    # We are only interested in the actual response,
    # without headers, contained in the last line.
    return response_lines[len(response_lines) - 1]

def get_sth(baseurl):
    result = urlopen(baseurl + "ct/v1/get-sth").read()
    return json.loads(result)

def get_proof_by_hash(baseurl, hash, tree_size):
    try:
        params = urllib.urlencode({"hash":base64.b64encode(hash),
                                   "tree_size":tree_size})
        result = \
          urlopen(baseurl + "ct/v1/get-proof-by-hash?" + params).read()
        return json.loads(result)
    except urllib2.HTTPError, e:
        print "ERROR:", e.read()
        sys.exit(1)

def get_consistency_proof(baseurl, tree_size1, tree_size2):
    try:
        params = urllib.urlencode({"first":tree_size1,
                                   "second":tree_size2})
        result = \
          urlopen(baseurl + "ct/v1/get-sth-consistency?" + params).read()
        return json.loads(result)["consistency"]
    except urllib2.HTTPError, e:
        print "ERROR:", e.read()
        sys.exit(1)

def tls_array(data, length_len):
    length_bytes = struct.pack(">Q", len(data))[-length_len:]
    return length_bytes + data

def unpack_tls_array(packed_data, length_len):
    padded_length = ["\x00"] * 8
    padded_length[-length_len:] = packed_data[:length_len]
    (length,) = struct.unpack(">Q", "".join(padded_length))
    unpacked_data = packed_data[length_len:length_len+length]
    assert len(unpacked_data) == length, \
      "data is only %d bytes long, but length is %d bytes" % \
      (len(unpacked_data), length)
    rest_data = packed_data[length_len+length:]
    return (unpacked_data, rest_data)

def add_chain(baseurl, submission):
    try:
        result = urlopen(baseurl + "ct/v1/add-chain", json.dumps(submission)).read()
        return json.loads(result)
    except urllib2.HTTPError, e:
        print "ERROR", e.code,":", e.read()
        if e.code == 400:
            return None
        sys.exit(1)
    except ValueError, e:
        print "==== FAILED REQUEST ===="
        print submission
        print "======= RESPONSE ======="
        print result
        print "========================"
        raise e

def add_prechain(baseurl, submission):
    try:
        result = urlopen(baseurl + "ct/v1/add-pre-chain",
            json.dumps(submission)).read()
        return json.loads(result)
    except urllib2.HTTPError, e:
        print "ERROR", e.code,":", e.read()
        if e.code == 400:
            return None
        sys.exit(1)
    except ValueError, e:
        print "==== FAILED REQUEST ===="
        print submission
        print "======= RESPONSE ======="
        print result
        print "========================"
        raise e

def get_entries(baseurl, start, end):
    params = urllib.urlencode({"start":start, "end":end})
    try:
        result = urlopen(baseurl + "ct/v1/get-entries?" + params).read()
        return json.loads(result)
    except urllib2.HTTPError, e:
        print "ERROR:", e.read()
        sys.exit(1)

def extract_precertificate(precert_chain_entry):
    (precert, certchain) = unpack_tls_array(precert_chain_entry, 3)
    return (precert, certchain)

def decode_certificate_chain(packed_certchain):
    (unpacked_certchain, rest) = unpack_tls_array(packed_certchain, 3)
    assert len(rest) == 0
    certs = []
    while len(unpacked_certchain):
        (cert, rest) = unpack_tls_array(unpacked_certchain, 3)
        certs.append(cert)
        unpacked_certchain = rest
    return certs

def decode_signature(signature):
    (hash_alg, signature_alg) = struct.unpack(">bb", signature[0:2])
    (unpacked_signature, rest) = unpack_tls_array(signature[2:], 2)
    assert rest == ""
    return (hash_alg, signature_alg, unpacked_signature)

def encode_signature(hash_alg, signature_alg, unpacked_signature):
    signature = struct.pack(">bb", hash_alg, signature_alg)
    signature += tls_array(unpacked_signature, 2)
    return signature

def check_signature(baseurl, signature, data, publickey=None):
    if publickey == None:
        if baseurl in publickeys:
            publickey = base64.decodestring(publickeys[baseurl])
        else:
            print >>sys.stderr, "Public key for", baseurl, \
                "not found, specify key file with --publickey"
            sys.exit(1)
    (hash_alg, signature_alg, unpacked_signature) = decode_signature(signature)
    assert hash_alg == 4, \
        "hash_alg is %d, expected 4" % (hash_alg,) # sha256
    assert signature_alg == 3, \
        "signature_alg is %d, expected 3" % (signature_alg,) # ecdsa

    vk = ecdsa.VerifyingKey.from_der(publickey)
    vk.verify(unpacked_signature, data, hashfunc=hashlib.sha256,
              sigdecode=ecdsa.util.sigdecode_der)

def parse_auth_header(authheader):
    splittedheader = authheader.split(";")
    (signature, rawoptions) = (splittedheader[0], splittedheader[1:])
    options = dict([(e.partition("=")[0], e.partition("=")[2]) for e in rawoptions])
    return (base64.b64decode(signature), options)

def check_auth_header(authheader, expected_key, publickeydir, data, path):
    if expected_key == None:
        return True
    (signature, options) = parse_auth_header(authheader)
    keyname = options.get("key")
    if keyname != expected_key:
        raise Exception("Response claimed to come from %s, expected %s" % (keyname, expected_key))
    publickey = get_public_key_from_file(publickeydir + "/" + keyname + ".pem")
    vk = ecdsa.VerifyingKey.from_der(publickey)
    vk.verify(signature, "%s\0%s\0%s" % ("REPLY", path, data), hashfunc=hashlib.sha256,
              sigdecode=ecdsa.util.sigdecode_der)
    return True

def http_request(url, data=None, key=None, verifynode=None, publickeydir="."):
    opener = get_opener()

    (keyname, keyfile) = key
    privatekey = get_eckey_from_file(keyfile)
    sk = ecdsa.SigningKey.from_der(privatekey)
    parsed_url = urlparse.urlparse(url)
    if data == None:
        data_to_sign = parsed_url.query
        method = "GET"
    else:
        data_to_sign = data
        method = "POST"
    signature = sk.sign("%s\0%s\0%s" % (method, parsed_url.path, data_to_sign), hashfunc=hashlib.sha256,
                        sigencode=ecdsa.util.sigencode_der)
    opener.addheaders = [('X-Catlfish-Auth', base64.b64encode(signature) + ";key=" + keyname)]
    result = opener.open(url, data)
    authheader = result.info().get('X-Catlfish-Auth')
    data = result.read()
    check_auth_header(authheader, verifynode, publickeydir, data, parsed_url.path)
    return data

def get_signature(baseurl, data, key=None):
    try:
        params = json.dumps({"plop_version":1, "data": base64.b64encode(data)})
        result = http_request(baseurl + "plop/v1/signing/sth", params, key=key)
        parsed_result = json.loads(result)
        return base64.b64decode(parsed_result.get(u"result"))
    except urllib2.URLError, e:
        print >>sys.stderr, "ERROR: get_signature", e.reason
        sys.exit(1)
    except urllib2.HTTPError, e:
        print "ERROR: get_signature", e.read()
        raise e

def create_signature(baseurl, data, key=None):
    unpacked_signature = get_signature(baseurl, data, key)
    return encode_signature(4, 3, unpacked_signature)

def check_sth_signature(baseurl, sth, publickey=None):
    signature = base64.decodestring(sth["tree_head_signature"])

    version = struct.pack(">b", 0)
    signature_type = struct.pack(">b", 1)
    timestamp = struct.pack(">Q", sth["timestamp"])
    tree_size = struct.pack(">Q", sth["tree_size"])
    hash = base64.decodestring(sth["sha256_root_hash"])
    tree_head = version + signature_type + timestamp + tree_size + hash

    check_signature(baseurl, signature, tree_head, publickey=publickey)

def create_sth_signature(tree_size, timestamp, root_hash, baseurl, key=None):
    version = struct.pack(">b", 0)
    signature_type = struct.pack(">b", 1)
    timestamp_packed = struct.pack(">Q", timestamp)
    tree_size_packed = struct.pack(">Q", tree_size)
    tree_head = version + signature_type + timestamp_packed + tree_size_packed + root_hash

    return create_signature(baseurl, tree_head, key=key)

def check_sct_signature(baseurl, signed_entry, sct, precert=False, publickey=None):
    if publickey == None:
        publickey = base64.decodestring(publickeys[baseurl])
    calculated_logid = hashlib.sha256(publickey).digest()
    received_logid = base64.decodestring(sct["id"])
    assert calculated_logid == received_logid, \
        "log id is incorrect:\n  should be %s\n        got %s" % \
        (calculated_logid.encode("hex_codec"),
         received_logid.encode("hex_codec"))

    signature = base64.decodestring(sct["signature"])

    version = struct.pack(">b", sct["sct_version"])
    signature_type = struct.pack(">b", 0)
    timestamp = struct.pack(">Q", sct["timestamp"])
    if precert:
        entry_type = struct.pack(">H", 1)
    else:
        entry_type = struct.pack(">H", 0)
    signed_struct = version + signature_type + timestamp + \
      entry_type + signed_entry + \
      tls_array(base64.decodestring(sct["extensions"]), 2)

    check_signature(baseurl, signature, signed_struct, publickey=publickey)

def pack_mtl(timestamp, leafcert):
    entry_type = struct.pack(">H", 0)
    extensions = ""

    timestamped_entry = struct.pack(">Q", timestamp) + entry_type + \
      tls_array(leafcert, 3) + tls_array(extensions, 2)
    version = struct.pack(">b", 0)
    leaf_type = struct.pack(">b", 0)
    merkle_tree_leaf = version + leaf_type + timestamped_entry
    return merkle_tree_leaf

def pack_mtl_precert(timestamp, cleanedcert, issuer_key_hash):
    entry_type = struct.pack(">H", 1)
    extensions = ""

    timestamped_entry = struct.pack(">Q", timestamp) + entry_type + \
      pack_precert(cleanedcert, issuer_key_hash) + tls_array(extensions, 2)
    version = struct.pack(">b", 0)
    leaf_type = struct.pack(">b", 0)
    merkle_tree_leaf = version + leaf_type + timestamped_entry
    return merkle_tree_leaf

def pack_precert(cleanedcert, issuer_key_hash):
    assert len(issuer_key_hash) == 32

    return issuer_key_hash + tls_array(cleanedcert, 3)

def pack_cert(cert):
    return tls_array(cert, 3)

def unpack_mtl(merkle_tree_leaf):
    version = merkle_tree_leaf[0:1]
    leaf_type = merkle_tree_leaf[1:2]
    timestamped_entry = merkle_tree_leaf[2:]
    (timestamp, entry_type) = struct.unpack(">QH", timestamped_entry[0:10])
    if entry_type == 0:
        issuer_key_hash = None
        (leafcert, rest_entry) = unpack_tls_array(timestamped_entry[10:], 3)
    elif entry_type == 1:
        issuer_key_hash = timestamped_entry[10:42]
        (leafcert, rest_entry) = unpack_tls_array(timestamped_entry[42:], 3)
    return (leafcert, timestamp, issuer_key_hash)

def get_leaf_hash(merkle_tree_leaf):
    leaf_hash = hashlib.sha256()
    leaf_hash.update(struct.pack(">b", 0))
    leaf_hash.update(merkle_tree_leaf)

    return leaf_hash.digest()

def timing_point(timer_dict=None, name=None):
    t = datetime.datetime.now()
    if timer_dict:
        starttime = timer_dict["lasttime"]
        stoptime = t
        deltatime = stoptime - starttime
        timer_dict["deltatimes"].append((name, deltatime.seconds * 1000000 + deltatime.microseconds))
        timer_dict["lasttime"] = t
        return None
    else:
        timer_dict = {"deltatimes":[], "lasttime":t}
        return timer_dict

def internal_hash(pair):
    if len(pair) == 1:
        return pair[0]
    else:
        hash = hashlib.sha256()
        hash.update(struct.pack(">b", 1))
        hash.update(pair[0])
        hash.update(pair[1])
        return hash.digest()

def chunks(l, n):
    return [l[i:i+n] for i in range(0, len(l), n)]

def next_merkle_layer(layer):
    return [internal_hash(pair) for pair in chunks(layer, 2)]

def build_merkle_tree(layer0):
    if len(layer0) == 0:
        return [[hashlib.sha256().digest()]]
    layers = []
    current_layer = layer0
    layers.append(current_layer)
    while len(current_layer) > 1:
        current_layer = next_merkle_layer(current_layer)
        layers.append(current_layer)
    return layers

def print_inclusion_proof(proof):
    audit_path = proof[u'audit_path']
    n = proof[u'leaf_index']
    level = 0
    for s in audit_path:
        entry = base64.b16encode(base64.b64decode(s))
        n ^= 1
        print level, n, entry
        n >>= 1
        level += 1

def get_one_cert(store, i):
    filename = i / 10000
    zf = zipfile.ZipFile("%s/%04d.zip" % (store, i / 10000))
    cert = zf.read("%08d" % i)
    zf.close()
    return cert

def get_hash_from_certfile(cert):
    for line in cert.split("\n"):
        if line.startswith("-----"):
            return None
        if line.startswith("Leafhash: "):
            return base64.b16decode(line[len("Leafhash: "):])
    return None

def get_timestamp_from_certfile(cert):
    for line in cert.split("\n"):
        if line.startswith("-----"):
            return None
        if line.startswith("Timestamp: "):
            return int(line[len("Timestamp: "):])
    return None

def get_proof(store, tree_size, n):
    hash = get_hash_from_certfile(get_one_cert(store, n))
    return get_proof_by_hash(args.baseurl, hash, tree_size)

def get_certs_from_zipfiles(zipfiles, firstleaf, lastleaf):
    for i in range(firstleaf, lastleaf + 1):
        try:
            yield zipfiles[i / 10000].read("%08d" % i)
        except KeyError:
            return

def get_merkle_hash_64k(store, blocknumber, write_to_cache=False, treesize=None):
    firstleaf = blocknumber * 65536
    lastleaf = firstleaf + 65535
    if treesize != None:
        assert firstleaf < treesize
        usecache = lastleaf < treesize
        lastleaf = min(lastleaf, treesize - 1)
    else:
        usecache = True

    hashfilename = "%s/%04x.64khash" % (store, blocknumber)
    if usecache:
        try:
            hash = base64.b16decode(open(hashfilename).read())
            assert len(hash) == 32
            return ("hash", hash)
        except IOError:
            pass
    firstfile = firstleaf / 10000
    lastfile = lastleaf / 10000
    zipfiles = {}
    for i in range(firstfile, lastfile + 1):
        try:
            zipfiles[i] = zipfile.ZipFile("%s/%04d.zip" % (store, i))
        except IOError:
            break
    certs = get_certs_from_zipfiles(zipfiles, firstleaf, lastleaf)
    layer0 = [get_hash_from_certfile(cert) for cert in certs]
    tree = build_merkle_tree(layer0)
    calculated_hash = tree[-1][0]
    for zf in zipfiles.values():
        zf.close()
    if len(layer0) != lastleaf - firstleaf + 1:
        return ("incomplete", (len(layer0), calculated_hash))
    if write_to_cache:
        f = open(hashfilename, "w")
        f.write(base64.b16encode(calculated_hash))
        f.close()
    return ("hash", calculated_hash)

def get_tree_head(store, treesize):
    merkle_64klayer = []

    for blocknumber in range(0, (treesize / 65536) + 1):
        (resulttype, result) = get_merkle_hash_64k(store, blocknumber, treesize=treesize)
        if resulttype == "incomplete":
            print >>sys.stderr, "Couldn't read until tree size", treesize
            (incompletelength, hash) = result
            print >>sys.stderr, "Stopped at", blocknumber * 65536 + incompletelength
            sys.exit(1)
        assert resulttype == "hash"
        hash = result
        merkle_64klayer.append(hash)
        #print >>sys.stderr, print blocknumber * 65536,
        sys.stdout.flush()
    tree = build_merkle_tree(merkle_64klayer)
    calculated_root_hash = tree[-1][0]
    return calculated_root_hash

def get_intermediate_hash(store, treesize, level, index):
    if level >= 16:
        merkle_64klayer = []

        levelsize = (2**(level-16))

        for blocknumber in range(index * levelsize, (index + 1) * levelsize):
            if blocknumber * (2 ** 16) >= treesize:
                break
            #print "looking at block", blocknumber
            (resulttype, result) = get_merkle_hash_64k(store, blocknumber, treesize=treesize)
            if resulttype == "incomplete":
                print >>sys.stderr, "Couldn't read until tree size", treesize
                (incompletelength, hash) = result
                print >>sys.stderr, "Stopped at", blocknumber * 65536 + incompletelength
                sys.exit(1)
            assert resulttype == "hash"
            hash = result
            #print "block hash", base64.b16encode(hash)
            merkle_64klayer.append(hash)
            #print >>sys.stderr, print blocknumber * 65536,
            sys.stdout.flush()
        tree = build_merkle_tree(merkle_64klayer)
        return tree[-1][0]
    else:
        levelsize = 2 ** level
        firstleaf = index * levelsize
        lastleaf = firstleaf + levelsize - 1
        #print "firstleaf", firstleaf
        #print "lastleaf", lastleaf
        assert firstleaf < treesize
        lastleaf = min(lastleaf, treesize - 1)
        #print "modified lastleaf", lastleaf
        firstfile = firstleaf / 10000
        lastfile = lastleaf / 10000
        #print "files", firstfile, lastfile
        zipfiles = {}
        for i in range(firstfile, lastfile + 1):
            try:
                zipfiles[i] = zipfile.ZipFile("%s/%04d.zip" % (store, i))
            except IOError:
                break
        certs = get_certs_from_zipfiles(zipfiles, firstleaf, lastleaf)
        layer0 = [get_hash_from_certfile(cert) for cert in certs]
        #print "layer0", repr(layer0)
        tree = build_merkle_tree(layer0)
        calculated_hash = tree[-1][0]
        for zf in zipfiles.values():
            zf.close()
        assert len(layer0) == lastleaf - firstleaf + 1
        return calculated_hash

def bits(n):
    p = 0
    while n > 0:
        n >>= 1
        p += 1
    return p

def merkle_height(n):
    if n == 0:
        return 1
    return bits(n - 1)

def node_above((pathp, pathl), levels=1):
    return (pathp >> levels, pathl + levels)

def node_even((pathp, pathl)):
    return pathp & 1 == 0

def node_odd((pathp, pathl)):
    return pathp & 1 == 1

def node_lower((path1p, path1l), (path2p, path2l)):
    return path1l < path2l

def node_higher((path1p, path1l), (path2p, path2l)):
    return path1l > path2l

def node_level((path1p, path1l)):
    return path1l

def node_outside((path1p, path1l), (path2p, path2l)):
    assert path1l == path2l
    return path1p > path2p

def combine_two_hashes((path1, hash1), (path2, hash2), treesize):
    assert not node_higher(path1, path2)
    edge_node = (treesize - 1, 0)

    if node_lower(path1, path2):
        assert path1 == node_above(edge_node, levels=node_level(path1))
        while node_even(path1):
            path1 = node_above(path1)

    assert node_above(path1) == node_above(path2)
    assert (node_even(path1) and node_odd(path2)) or (node_odd(path1) and node_even(path2))

    if node_outside(path2, node_above(edge_node, levels=node_level(path2))):
        return (node_above(path1), hash1)

    if node_even(path1):
        newhash = internal_hash((hash1, hash2))
    else:
        newhash = internal_hash((hash2, hash1))

    return (node_above(path1), newhash)

def path_as_string(pos, level, treesize):
    height = merkle_height(treesize)
    path = "{0:0{width}b}".format(pos, width=height - level)
    if height == level:
        return ""
    return path

def nodes_for_subtree(subtreesize, treesize):
    height = merkle_height(treesize)
    nodes = []
    level = 0
    pos = subtreesize
    while pos > 0 and pos & 1 == 0:
        pos >>= 1
        level += 1
    if pos & 1:
        nodes.append((pos ^ 1, level))
    #print pos, level
    while level < height:
        pos_level0 = pos * (2 ** level)
        #print pos, level
        if pos_level0 < treesize:
            nodes.append((pos, level))
        pos >>= 1
        pos ^= 1
        level += 1
    return nodes

def nodes_for_index(pos, treesize):
    height = merkle_height(treesize)
    nodes = []
    level = 0
    pos ^= 1
    #print pos, level
    while level < height:
        pos_level0 = pos * (2 ** level)
        #print pos, level
        if pos_level0 < treesize:
            nodes.append((pos, level))
        pos >>= 1
        pos ^= 1
        level += 1
    return nodes

def verify_consistency_proof(consistency_proof, first, second, oldhash_input):
    if 2 ** bits(first - 1) == first:
        consistency_proof = [oldhash_input] + consistency_proof
    chain = zip(nodes_for_subtree(first, second), consistency_proof)
    assert len(nodes_for_subtree(first, second)) == len(consistency_proof)
    (_, hash) = reduce(lambda e1, e2: combine_two_hashes(e1, e2, second), chain)
    (_, oldhash) = reduce(lambda e1, e2: combine_two_hashes(e1, e2, first), chain)
    return (oldhash, hash)

def verify_inclusion_proof(inclusion_proof, index, treesize, leafhash):
    chain = zip([(index, 0)] + nodes_for_index(index, treesize), [leafhash] + inclusion_proof)
    assert len(nodes_for_index(index, treesize)) == len(inclusion_proof)
    (_, hash) = reduce(lambda e1, e2: combine_two_hashes(e1, e2, treesize), chain)
    return hash

def extract_original_entry(entry):
    leaf_input =  base64.decodestring(entry["leaf_input"])
    (leaf_cert, timestamp, issuer_key_hash) = unpack_mtl(leaf_input)
    extra_data = base64.decodestring(entry["extra_data"])
    if issuer_key_hash != None:
        (precert, extra_data) = extract_precertificate(extra_data)
        leaf_cert = precert
    certchain = decode_certificate_chain(extra_data)
    return ([leaf_cert] + certchain, timestamp, issuer_key_hash)

def mv_file(fromfn, tofn):
    shutil.move(fromfn, tofn)

def write_file(fn, jsondata):
    tempname = fn + ".new"
    open(tempname, 'w').write(json.dumps(jsondata))
    mv_file(tempname, fn)

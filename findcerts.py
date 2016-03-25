#!/usr/bin/env python
import os
import sys
import time
import base64
import random
import ctypes
import hashlib
import zipfile
import datetime
import argparse

import findcerts_extra

from multiprocessing import Pool, cpu_count, Array

from pyx509.pkcs7.asn1_models.X509_certificate import Certificate
from pyx509.pkcs7_models import X509Certificate, PublicKeyInfo, ExtendedKeyUsageExt
from pyx509.pkcs7.asn1_models.decoder_workarounds import decode

processLeaf = True
processIntermediates = False
processRoot = False

def certificate_interesting(cert):
    tbs = cert.tbsCertificate
    if "ritter.vg" in str(tbs.subject):
        return "ritter.vg"
    if tbs.subjAltNameExt:
        san = tbs.subjAltNameExt.value
        for component_type, name_list in san.values.items():
            for n in name_list:
                if "ritter.vg" in n:
                    return "ritter.vg"

    return None

#=========================================================================

class State:
    LookForCert = 0
    AppendCert = 1

class Status:
    Queued = 0
    Processing = 1
    Completed = 2
    Errored = 3

def process_zipfile(ziptuple):
    global args
    global processLeaf, processIntermediates, processRoot

    zipindx, zipfilename = ziptuple
    if isinstance(zipfilename, file):
        zipfilename = zipfilename.name
    if zipindx >= 0:
        findcerts_extra.zipfilestate[zipindx] = Status.Processing

    z = zipfile.ZipFile(zipfilename, "r")
    findx = 1
    hasError = False
    numcerts = len(z.namelist())
    numMatchingCerts = 0
    for filename in z.namelist():
        lines = z.open(filename, "r").readlines()

        certs = []
        thiscert = ""
        currentstate = State.LookForCert
        for l in lines:
            if currentstate == State.LookForCert and \
               ("-----BEGIN CERTIFICATE-----" in l or "-----BEGIN PRECERTIFICATE-----" in l):
                thiscert = ""
                currentstate = State.AppendCert
            elif currentstate == State.LookForCert and "-----BEGIN" in l:
                print "[?] Got an unexpected begin line:", l
            elif currentstate == State.AppendCert and "-----END" in l:
                certs.append(base64.b64decode(thiscert))
                currentstate = State.LookForCert
            elif currentstate == State.AppendCert:
                thiscert += l
            elif currentstate == State.LookForCert and "Timestamp:" in l:
                pass
            elif currentstate == State.LookForCert and "Leafhash:" in l:
                pass
            elif currentstate == State.LookForCert and not l.strip():
                pass
            else:
                print "[!] What the heck? State machine error."

        cindx = 1
        for c in certs:
            if cindx == len(certs) and not processRoot:
                continue
            elif cindx == 1 and not processLeaf:
                continue
            elif cindx not in [1, len(certs)] and not processIntermediates:
                continue

            fingerprint = hashlib.sha1(c).hexdigest()
            try:
                cert = decode(c, asn1Spec=Certificate())[0]
                cert = X509Certificate(cert)
            
                certMatchType = certificate_interesting(cert)
            
                if certMatchType:
                    numMatchingCerts += 1
                    outputname = fingerprint + "_" + str(cindx) + "_" + str(random.random())[2:]
                    outputpath = os.path.join(args.out, certMatchType, fingerprint[0:2], fingerprint[2])
                    if not os.path.exists(outputpath):
                        try:
                            os.makedirs(outputpath)
                        except:
                            pass
                    outputfile = open(os.path.join(outputpath,  outputname), 'w')
                    outputfile.write("-----BEGIN CERTIFICATE-----\n")
                    outputfile.write(base64.b64encode(c) + "\n")
                    outputfile.write("-----END CERTIFICATE-----\n")
                    outputfile.write(zipfilename + " " + filename)
                    outputfile.close()
            except Exception, e:
                exc_info = sys.exc_info()
                try:
                    outputname = fingerprint + "_" + str(cindx) + "_" + str(random.random())[2:]
                    outputpath = os.path.join(args.err, fingerprint[0:2], fingerprint[2])
                    if not os.path.exists(outputpath):
                        try:
                            os.makedirs(outputpath)
                        except:
                            pass
                    outputfile = open(os.path.join(outputpath,  outputname), 'w')
                    outputfile.write("-----BEGIN CERTIFICATE-----\n")
                    outputfile.write(base64.b64encode(c) + "\n")
                    outputfile.write("-----END CERTIFICATE-----\n")
                    outputfile.write(zipfilename + " " + filename + "\n")
                    outputfile.write(str(exc_info) + "\n")
                    outputfile.write(str(e) + "\n")
                    outputfile.close()
                except:
                    hasError = True
            cindx += 1
        findx += 1

    findcerts_extra.resultcount[zipindx] = numMatchingCerts
    if zipindx >= 0:
        if not hasError:
            findcerts_extra.zipfilestate[zipindx] = Status.Completed
        else:
            findcerts_extra.zipfilestate[zipindx] = Status.Errored
    else:
        if hasError:
            print "Job Status: Errored", zipfilename
        else:
            print "Job Status: Completed", zipfilename

def initProcess(share1, share2):
    findcerts_extra.zipfilestate = share1
    findcerts_extra.resultcount = share2
    

args = None
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run a query on every certificate in the CT logs')
    parser.add_argument("--data", help="Directory the ct data is in")
    parser.add_argument("--out", help="Directory the results will go to", required=True)
    parser.add_argument("--err", help="Directory the errors will go to", required=True)
    parser.add_argument("--zip", action="append", help="Process a zipfile directly, ignoring the multiprocessing features. Can be specified multiple times", type=argparse.FileType('r'))
    parser.add_argument("--log", action="append", help="Limit searching to these logs. Case-insensitive match, can be specified multiple times.")
    args = parser.parse_args()
    if not args.data and not args.zip:
        print "Error: Must supply either --data or --zip"
        sys.exit(1)
    if args.data and (not os.path.exists(args.data) or not os.path.isdir(args.data)):
        print "Error: Input directory is missing?"
        sys.exit(-1)
    if os.path.exists(args.out) and not os.path.isdir(args.out):
        print "Error: Output directory is not a directory!"
        sys.exit(-1)
    if os.path.exists(args.err) and not os.path.isdir(args.err):
        print "Error: Error directory is not a directory!"
        sys.exit(-1)
    if args.log:
        for i in range(len(args.log)):
            args.log[i] = args.log[i].lower()

    logs = []
    zipfiles = []
    if args.zip:
        for z in args.zip:
            zipfiles.append(z)
        logs.append("User-Specified")
    else:
        for d in os.listdir(args.data):
            if  os.path.isdir(os.path.join(args.data, d)):
                processThisLog = False
                if args.log:
                    for l in args.log:
                        processThisLog |= l in d.lower()
                else:
                    processThisLog = True
                if processThisLog:
                    logs.append(d)
                    for f in os.listdir(os.path.join(args.data, d)):
                        if ".zip" in f:
                            zipfiles.append(os.path.join(args.data, d, f))

    if not zipfiles:
        print "[!] No files were found to process!"
        sys.exit(0)
    
    print "[+] Found", cpu_count(), "CPUs and", len(zipfiles), "zipfiles in", len(logs), "log(s):", tuple(logs)
    if not args.zip:
        print "[+] Running", cpu_count(), "jobs to estimate completion time..."

        zipfilestate = Array('i', len(zipfiles), lock=False)
        resultcount = Array('i', len(zipfiles), lock=False)

        pool = Pool(processes=cpu_count(), initializer=initProcess, initargs=(zipfilestate,resultcount,))
        
        bench = []
        for i in range(len(zipfiles[:cpu_count()])):
            bench.append((i, zipfiles[i]))
        start = time.time()
        pool.map(process_zipfile, bench)
        runtime = time.time() - start

        chunks = (len(zipfiles[cpu_count():]) / cpu_count()) + 1
        total_runtime = runtime * chunks
        completion = datetime.datetime.now() + datetime.timedelta(seconds=total_runtime)
        print "[+] This is an estimate, but it looks like we'll complete sometime around", completion

        fullworkload = []
        for i in range(len(zipfiles[cpu_count():])):
            fullworkload.append((i+cpu_count(), zipfiles[i]))
        result = pool.map_async(process_zipfile, fullworkload)

        errors = []
        results = 0
        while not result.ready():
            q = 0
            p = 0
            c = 0
            e = 0
            for z in range(len(zipfilestate)):
                if zipfilestate[z] == Status.Queued:
                    q += 1
                elif zipfilestate[z] == Status.Processing:
                    p += 1
                elif zipfilestate[z] == Status.Completed:
                    c += 1
                    results += resultcount[z]
                elif zipfilestate[z] == Status.Errored:
                    e += 1
                    results += resultcount[z]
                    if zipfiles[z] not in errors:
                        print "[!] Caught a unhandle-able error:", zipfiles[z]
                        errors.append(zipfiles[z])
            sys.stdout.write("[+] Job Status: " + str(results) + " results. Jobs: "+ str(p) + " in progress, " + str(q) + " queued, " + str(c+e) + " completed (" + str(e) + " Errors).             \r")
            sys.stdout.flush()
            time.sleep(5)
    else:
        for z in zipfiles:
            process_zipfile((-1, z))

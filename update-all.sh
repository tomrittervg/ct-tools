#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 key_directory certstore_directory";
    exit
fi

for i in $1/*
do
    echo "================================================================"
    echo "Processing $i"
    if [ ! -d "$2/`basename -s .pem $i`" ]; then
	mkdir $2/`basename -s .pem $i`
    fi
    ./fetchallcerts.py `tail -n 1 $i` --store $2/`basename -s .pem $i` --pub $i
done

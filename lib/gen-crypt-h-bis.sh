#!/usr/bin/env bash

infile=$1
crypt_hashes_h=$2

if grep -q "#define HASH_ALGORITHM_DEFAULT" "$crypt_hashes_h"; then
    value=1
else
    value=0
fi

sed -e "s/@DEFAULT_PREFIX_ENABLED@/$value/g" < "$infile"

#!/bin/bash
set -e

if [[ "$PERFORM_COVERITY_SCAN" == "1" ]]; then
  exit 0
fi

docker exec -t buildenv /bin/sh -c "rpm -E %optflags" > cflags.txt
docker exec -t buildenv /bin/sh -c "rpm -E %__global_ldflags" > ldflags.txt
cat cflags.txt  | tr -d '\012\015' > cflags.txt.new
mv -f cflags.txt.new cflags.txt
cat ldflags.txt | tr -d '\012\015' > ldflags.txt.new
mv -f ldflags.txt.new ldflags.txt

if [[ "$CC" == "clang" ]]; then
  sed -i -e 's![ \t]*-fcf-protection[ \t]*! -Wno-unused-command-line-argument!g' cflags.txt
fi

if [[ "$FCVER" == "latest" ]]; then
  sed -i -e 's![ \t]*-mcet[ \t]*! !g' cflags.txt
fi

#!/bin/bash
set -e

if [[ "$PERFORM_COVERITY_SCAN" == "1" ]]; then
  echo -n | openssl s_client -connect 'scan.coverity.com:443' | \
  sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | \
  sudo tee -a /etc/ssl/certs/ca-
  curl 'http://de.archive.ubuntu.com/ubuntu/pool/main/p/pkg-config/pkg-config_0.29.1-0ubuntu1_amd64.deb' \
    --output /tmp/pkg-config_0.29.1-0ubuntu1_amd64.deb
  sudo apt --yes install /tmp/pkg-config_0.29.1-0ubuntu1_amd64.deb
  exit 0
fi

for i in `seq 0 99`; do
  docker pull fedora:$FCVER && i= && break || sleep 1
done; [ -z "$i" ]

perl -pe 's/\$(\w+)/$ENV{$1}/g' .travis.env.in > travis.env

docker run -t -d -P --env-file travis.env --name buildenv \
  -v $HOME/.ccache:/root/.ccache -v $PWD:/opt/libxcrypt fedora:$FCVER \
  /bin/sh -c "mkdir -p /opt/libxcrypt ; bash"
docker exec -t buildenv /bin/sh \
  -c "echo \"deltarpm=0\" >> /etc/dnf/dnf.conf"
docker exec -t buildenv /bin/sh \
  -c "echo \"install_weak_deps=0\" >> /etc/dnf/dnf.conf"
docker exec -t buildenv /bin/sh \
  -c "echo \"max_parallel_downloads=20\" >> /etc/dnf/dnf.conf"
docker exec -t buildenv /bin/sh \
  -c "echo \"\" >> /etc/dnf/dnf.conf"

if [[ "$FCVER" == "rawhide" ]]; then
  docker exec -t buildenv /bin/sh \
    -c "cat /opt/libxcrypt/.travis.dnf.conf.rawhide_latest >> /etc/dnf/dnf.conf"
fi

docker exec -t buildenv /bin/sh \
  -c 'for i in `seq 0 99`; do dnf makecache && i= && break || sleep 1; done; [ -z "$i" ]'
docker exec -t buildenv /bin/sh \
  -c 'for i in `seq 0 99`; do dnf -y upgrade && i= && break || sleep 1; done; [ -z "$i" ]'
docker exec -t buildenv /bin/sh \
  -c 'for i in `seq 0 99`; do dnf -y swap coreutils-single coreutils && i= && break || sleep 1; done; [ -z "$i" ]'
docker exec -t buildenv /bin/sh \
  -c 'for i in `seq 0 99`; do dnf -y groups install buildsys-build && i= && break || sleep 1; done; [ -z "$i" ]'
docker exec -t buildenv /bin/sh \
  -c 'for i in `seq 0 99`; do dnf -y install git libtool valgrind && i= && break || sleep 1; done; [ -z "$i" ]'

if [[ "$CC" == "clang" ]]; then
  docker exec -t buildenv /bin/sh \
    -c 'for i in `seq 0 99`; do dnf -y install clang && i= && break || sleep 1; done; [ -z "$i" ]'
fi

if [[ "$CODECOV" == "1" ]]; then
  docker exec -t buildenv /bin/sh \
  -c 'for i in `seq 0 99`; do dnf -y install lcov python3-pip && i= && break || sleep 1; done; [ -z "$i" ]'
fi

if [[ "$CODECOV" == "1" ]]; then
  docker exec -t buildenv /bin/sh -c "pip3 install codecov"
fi

docker exec -t buildenv /bin/sh \
  -c 'for i in `seq 0 99`; do dnf -y autoremove && i= && break || sleep 1; done; [ -z "$i" ]'

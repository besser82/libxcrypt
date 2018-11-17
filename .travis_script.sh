#!/bin/bash
set -e

export NPROCS="$((`nproc --all 2>/dev/null || sysctl -n hw.ncpu` * 2))"
echo paralleism is $NPROCS

if [[ "$PERFORM_COVERITY_SCAN" == "1" ]]; then
  TAG_VERSION="`echo ${TRAVIS_BRANCH} | sed -e 's/^v//g'`"
  curl -s "https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh" \
    --output /tmp/travisci_build_coverity_scan.sh
  sed -i -e "s/--form version=\$SHA/--form version=\"${TAG_VERSION}\"/g" \
    -e "s/--form description=\"Travis CI build\"/--form description=\"${SHA}\"/g" \
    -e "s/201/200/g" /tmp/travisci_build_coverity_scan.sh
  bash /tmp/travisci_build_coverity_scan.sh
  exit 0
fi

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then
  export CFLAGS="-O2 -g -arch i386 -arch x86_64 --coverage"
  export CXXFLAGS="$CFLAGS"
  export LDFLAGS="-arch i386 -arch x86_64 -lprofile_rt"
elif [[ "$CODECOV" == "1" ]]; then
  export CFLAGS="-O0 -g --coverage"
  export CXXFLAGS="$CFLAGS"
else
  export DEB_BUILD_MAINT_OPTIONS="hardening=+all"
  export CPPFLAGS="$(dpkg-buildflags --get CPPFLAGS)"
  export CFLAGS="$(dpkg-buildflags --get CFLAGS) --coverage"
  export CXXFLAGS="$(dpkg-buildflags --get CXXFLAGS) --coverage"
  export LDFLAGS="$(dpkg-buildflags --get LDFLAGS)"
fi

rm -fr build
mkdir -p build
pushd build
../configure --disable-silent-rules $CONF || \
  (cat config.log && exit 1)

if [[ "$DISTCHECK" == "1" ]]; then
  make -j$NPROCS distcheck
else
  make -j$NPROCS
  make check -j$NPROCS || (cat test-suite.log && exit 1)
fi

if [[ "$VALGRIND" == "1" ]]; then
  make -j$NPROCS check-valgrind-memcheck || \
    (cat test-suite-memcheck.log && exit 1)
fi

popd

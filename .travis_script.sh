#!/bin/bash
set -e

log_time () {
   local duration="$SECONDS"
   local secs=$((duration % 60)); duration=$((duration / 60))
   local mins=$((duration % 60)); duration=$((duration / 60))
   local hours=$duration
   if [ $hours -gt 0 ]; then
      txt="${hours}h ${mins}m ${secs}s"
   elif [[ $mins -gt 0 ]]; then
      txt="${mins}m ${secs}s"
   else
      txt="${secs}s"
   fi
   printf 'time for %s: %s\n' "$1" "$txt"
   SECONDS=0
}

# travis_wait is not a proper command, it's a bash function, so it is
# not available to this script.  This is a simplification of code from
# https://github.com/travis-ci/travis-build/lib/travis/build/bash/
travis_jigger () {
    local cmd_pid="$1"
    local timeout="$2"
    local count=0

    while [[ "$count" -lt "$timeout" ]]; do
        sleep 60
        count="$((count + 1))"
        echo "Long job still running (${count}m / ${timeout}m)"
    done
    printf '\033[33;1m%s\033[0m\n' "Timeout, terminating long job."
    # Use a negative process ID to target the entire process group of
    # the background job.
    kill -15 "-$cmd_pid"
    sleep 60
    printf '\033[31;1m%s\033[0m\n' "Timeout, killing long job."
    kill -9 "-$cmd_pid"
    # Ensure, as best we can, that this PID sticks around to be killed
    # by travis_wait.
    sleep 3600
}
travis_wait () {
    local timeout="${1}"
    if [[ "${timeout}" =~ ^[0-9]+$ ]]; then
        shift
    else
        timeout=20
    fi

    # The background jobs we're about to start must be run in separate
    # process groups, so we can kill them off all at once later.
    set -m

    "$@" &
    local cmd_pid="$!"

    travis_jigger "$cmd_pid" "$timeout" &
    local jigger_pid="$!"

    # ... but don't print reports when they finish.
    set +m

    wait "$cmd_pid" 2>/dev/null
    local result="$?"
    if [[ "$result" -eq 0 ]]; then
        : # successful completion
    elif [[ "$result" -eq -15 || $result -eq -9 ]]; then
        : # terminated, error already printed
    elif [[ "$result" -lt 0 ]]; then
        printf '\033[31;1m%s\033[0m\n' "Long job killed by signal ${result#-}"
    else
        printf '\033[33;1m%s\033[0m\n' "Long job exited with status ${result}"
    fi
    kill -15 "-$jigger_pid"
    wait "$jigger_pid"
    return "$result"
}


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

MAKE_ARGS=
if [[ "$SANITIZER" == "1" ]]; then
  # ASan is incompatible with -z defs.
  MAKE_ARGS="UNDEF_FLAG="
  export CFLAGS="$CFLAGS -fsanitize=undefined,address"
  export CXXFLAGS="$CXXFLAGS -fsanitize=undefined,address"
fi

rm -fr build
mkdir -p build
pushd build
log_time preparation

../configure --disable-silent-rules $CONF || \
  (cat config.log && exit 1)
log_time configure

if [[ "$DISTCHECK" == "1" ]]; then
  make -j$NPROCS $MAKE_ARGS distcheck
  log_time distcheck
else
  make -j$NPROCS $MAKE_ARGS all
  log_time build
  travis_wait 60 \
  make -j$NPROCS $MAKE_ARGS check || (cat test-suite.log && exit 1)
  log_time test
fi

if [[ "$VALGRIND" == "1" ]]; then
  # This step can take considerably longer than the default
  # Travis no-output timeout on individual tests, just because
  # that's how slow memcheck is.
  travis_wait 60 \
    make -j$NPROCS $MAKE_ARGS check-valgrind-memcheck || \
    (cat test-suite-memcheck.log && exit 1)
  log_time test-memcheck
fi

popd

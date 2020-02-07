#!/bin/bash
set -e

if [[ "$PERFORM_COVERITY_SCAN" == "1" ]]; then
  exit 0
fi

if [[ "$DISTCHECK" == "1" ]]; then
  exit 0
fi

export GCOV="gcov"

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then
  GCC_VER="$(curl -s https://formulae.brew.sh/api/formula/gcc.json | jq -r '.versions.stable' | cut -d. -f1)"
  if [[ "$CC" == "gcc" ]] || [[ "$CC" == "gcc-$GCC_VER" ]]; then
    export GCOV="gcov-$GCC_VER"
  fi
elif [[ "$TRAVIS_OS_NAME" == "linux" ]] && [[ "$CC" == "clang" ]]; then
  export GCOV="$PWD/.clang_gcov_wrapper.sh"
fi

. build/venv/bin/activate
set -x

lcov --gcov-tool $GCOV --directory . --capture --output-file all_coverage.info
lcov --gcov-tool $GCOV --remove all_coverage.info '/usr/*' '*test*' > coverage.info
rm all_coverage.info
codecov -X gcov

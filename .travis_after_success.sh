#! /bin/sh

if [ "$PERFORM_COVERITY_SCAN" = 1 ] || [ "$DISTCHECK" = 1 ]; then
  exit 0
fi

set -e
. build/venv/bin/activate

GCOV=gcov

if [ "$CC" = "clang" ]; then
  GCOV="$PWD/.clang_gcov_wrapper.sh"

elif [ "$TRAVIS_OS_NAME" = osx ]; then
  GCC_VER="$( (brew list --versions gcc || echo gcc 0) |
              sed 's/^gcc \([0-9]*\)\..*$/\1/' )"
  if [ "$CC" = gcc ] || [ "$CC" = "gcc-$GCC_VER" ]; then
    GCOV="gcov-$GCC_VER"
  fi
fi
export GCOV

set -x

lcov --gcov-tool $GCOV --directory . --capture --output-file all_coverage.info
lcov --gcov-tool $GCOV --remove all_coverage.info \
     '/usr/*' '*test*' > coverage.info
rm all_coverage.info
codecov -X gcov

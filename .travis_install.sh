#! /bin/sh

if [ "$PERFORM_COVERITY_SCAN" = 1 ] || [ "$DISTCHECK" = 1 ]; then
  exit 0
fi
set -x
pip install --user codecov

#!/bin/bash
set -e

if [[ "$PERFORM_COVERITY_SCAN" == "1" ]]; then
  exit 0
fi

if [[ "$DISTCHECK" == "1" ]]; then
  exit 0
fi

lcov --directory . --capture --output-file all_coverage.info
lcov --remove all_coverage.info '/usr/*' '*test*' > coverage.info
rm all_coverage.info
codecov -X gcov

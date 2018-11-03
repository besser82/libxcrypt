#!/bin/bash
set -e

if [[ "$CODECOV" == "1" ]]; then
  lcov --directory . --capture --output-file all_coverage.info
  lcov --remove all_coverage.info '/usr/*' '*test*' > coverage.info
  rm all_coverage.info
  codecov -X gcov
fi

exit 0

#! /bin/sh
set -e

# Log the identities and versions of the build tools.
for tool in \
    "${CC-cc}" \
    "${AUTOCONF-autoconf}" \
    "${AUTOMAKE-automake}" \
    "${LIBTOOLIZE-libtoolize}" \
    "${PKG_CONFIG-pkg-config}" \
    "${PERL-perl}" \
    "${PYTHON-python3}"
do
    # $tool might include mandatory command-line arguments.
    # Interpret it the same way Make would.
    set fnord $tool
    shift
    if command -V $1; then
        echo + "$@" --version
        "$@" --version
    fi
    echo
done
set fnord; shift  # clear $@

# Prepare the configure scripts.
set -x
. ./autogen.sh

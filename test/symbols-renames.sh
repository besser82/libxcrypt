#! /bin/sh
# Written by Zack Weinberg <zackw at panix.com> in 2017.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

# Check that all of the symbols renamed by crypt-port.h
# still appear somewhere in the source code.  This test does not attempt
# to parse the source code, so it can get false negatives (e.g. a word used
# in a comment will be enough).
#
# Due to limitations in Automake, this program takes parameters from
# the environment:
# $lib_la - full pathname of libcrypt.la
# $lib_map - full pathname of libcrypt.map.in (used only to locate
# crypt-port.h and all of the .c files).

set -e
LC_ALL=C; export LC_ALL

list_library_internals ()
{
    eval $(grep old_library= "$1")
    nm -og "${1%/*}/.libs/${old_library}" |
        grep -v ' U ' | cut -d' ' -f3 | sort -u |
        grep '^_crypt_'
    unset old_library
}

list_symbol_renames ()
{
    printf '#include "crypt-port.h"\n' |
        ${CPP-cc -E} ${CPPFLAGS} -dD -xc - |
        ${AWK-awk} '
            $1 == "#define" && $3 ~ /^_crypt_/ {
                print $3
            }
            ' |
        sort -u
}

if [ ! -f "$lib_la" ] || [ ! -f "$lib_map" ]; then
    echo "Usage: lib_la=/path/to/library.la lib_map=/path/to/library.map $0" >&2
    exit 1
fi

printf 'lib_la=%s\n' "$lib_la" >&2
printf 'lib_map=%s\n' "$lib_map" >&2
printf 'CPP=%s\n' "${CPP-cc -E}" >&2
printf 'CPPFLAGS=%s\n' "${CPPFLAGS}" >&2
printf 'AWK=%s\n' "${AWK-awk}" >&2

lib_internals=""
lib_renames=""

trap 'rm -f $lib_internals $lib_renames || :' 0

lib_internals="$(mktemp)"
lib_renames="$(mktemp)"

list_library_internals "$lib_la" > "$lib_internals"
list_symbol_renames "${lib_map%/*}/crypt-port.h" > "$lib_renames"

extra_renames="$(comm -23 "$lib_renames" "$lib_internals" |
    sed 's/^_crypt_//' | tr -s "$IFS" " ")"
missing_renames="$(comm -13 "$lib_renames" "$lib_internals" |
    sed 's/^_crypt_//' | tr -s "$IFS" " ")"

status=0
if [ -n "$extra_renames" ]; then
    printf '*** Extra renames: %s\n' "$extra_renames" >&2
    status=1
fi
if [ -n "$missing_renames" ]; then
    printf '*** Missing renames: %s\n' "$missing_renames" >&2
    status=1
fi
exit $status

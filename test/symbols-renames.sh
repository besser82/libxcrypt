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
# $host_os - autoconf host_os variable
# $AWK, $CPP, $CPPFLAGS - awk, C preprocessor, and parameters

set -e
LC_ALL=C; export LC_ALL

list_library_internals ()
{
    eval $(grep old_library= "$1")
    ${NM-nm} -o --extern-only --defined-only "${1%/*}/.libs/${old_library}" |
        ${AWK-awk} -v symbol_prefix="$symbol_prefix" '
            NF == 0 { next }
            {
               sym = $NF;
               if (symbol_prefix != "") { sub("^" symbol_prefix, "", sym); }
               if (sym ~ /^_crypt_/) { print sym; }
            }
        ' |
        sort -u
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

if [ ! -f "$lib_la" ] || [ -z "$host_os" ]; then
    echo "Usage: host_os=foonix lib_la=/path/to/library.la $0" >&2
    exit 1
fi

case "$host_os" in
    *darwin*)
        # Mach-O follows the old a.out tradition of prepending an
        # underscore to all global symbols defined in C.
        symbol_prefix='_'
        ;;
    *)
        # Assume ELF, which does *not* prepend an underscore to
        # global symbols defined in C.
        symbol_prefix=''
        ;;
esac

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

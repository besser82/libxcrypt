#! /bin/sh
# Written by Zack Weinberg <zackw at panix.com> in 2017.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

# Test that all global symbols in the static version of the library
# (libcrypt.a) are either listed as global and supported for new code
# in libcrypt.map.in, or begin with a _crypt prefix.  Also test that
# all of the global, supported for new code, symbols mentioned in
# libcrypt.map.in are in fact defined.
#
# Due to limitations in Automake, this program takes parameters from
# the environment:
# $lib_la - full pathname of libcrypt.la
# $lib_map - full pathname of libcrypt.map.in
# $host_os - autoconf host_os variable

set -e
LC_ALL=C; export LC_ALL

list_library_globals ()
{
    eval $(grep old_library= "$1")
    nm -o --extern-only --defined-only "${1%/*}/.libs/${old_library}" |
        ${AWK-awk} -v symbol_prefix="$symbol_prefix" '
            NF == 0 { next }
            {
               sym = $NF;
               if (symbol_prefix != "") { sub("^" symbol_prefix, "", sym); }
               if (sym !~ /^_([_A-Y]|crypt_)/) { print sym; }
            }
        ' |
        sort -u
    unset old_library
}

list_allowed_globals ()
{
    ${AWK-awk} '
        NF == 0        { next }
        $1 == "#"      { next }
        $1 == "%chain" { next }
        $2 != "-"      { print $1 }
    ' "$1" | sort -u
}

if [ ! -f "$lib_la" ] || [ ! -f "$lib_map" ] || [ -z "$host_os" ]; then
    echo "Usage: host_os=foonix lib_la=/p/lib.la lib_map=/p/lib.map $0" >&2
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

lib_globals=""
lib_xglobals=""

trap 'rm -f $lib_globals $lib_xglobals || :' 0

lib_globals="$(mktemp)"
lib_xglobals="$(mktemp)"

list_library_globals "$lib_la" > "$lib_globals"
list_allowed_globals "$lib_map" > "$lib_xglobals"

extra_globals="$(comm -23 "$lib_globals" "$lib_xglobals" | tr -s "$IFS" " ")"
missing_globals="$(comm -13 "$lib_globals" "$lib_xglobals"| tr -s "$IFS" " ")"

status=0
if [ -n "$extra_globals" ]; then
    printf '*** Extra symbols: %s\n' "$extra_globals" >&2
    status=1
fi
if [ -n "$missing_globals" ]; then
    printf '*** Missing symbols: %s\n' "$missing_globals" >&2
    status=1
fi
exit $status

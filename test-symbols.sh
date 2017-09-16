#! /bin/sh
# Test that all global symbols in the static version of the library
# (libcrypt.a) are either listed as global in libcrypt.map, or begin
# with a _crypt prefix.  Also test that all global symbols mentioned
# in libcrypt.map are in fact defined.
#
# Due to limitations in Automake, this program takes parameters from
# the environment:
# $lib_la - full pathname of libcrypt.la
# $lib_map - full pathname of libcrypt.map

set -e
LC_ALL=C; export LC_ALL

list_library_globals ()
{
    eval $(grep old_library= "$1")
    nm -o "${1%/*}/.libs/${old_library}" |
        grep ' [A-TV-Z] ' | cut -d' ' -f3 | sort -u | grep -v '^_crypt_'
    unset old_library
}

list_allowed_globals ()
{
    ${AWK-awk} '
        BEGIN            { in_block = 0; in_global = 0; }
        /^[A-Z0-9_.]+ {/ { in_block = 1; }
        /^}/             { in_block = 0; in_global = 0; }
        /^ *global:$/    { in_global = 1; }
        /^ *local:$/     { in_global = 0; }
        /;/ && in_block && in_global {
            for (i = 1; i <= NF; i++) {
                sub(/;/, "", $i);
                print $i;
            }
       }' "$1" | sort -u
}

if [ ! -f "$lib_la" ] || [ ! -f "$lib_map" ]; then
    echo "Usage: lib_la=/path/to/library.la lib_map=/path/to/library.map $0" >&2
    exit 1
fi

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

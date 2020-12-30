#! /bin/sh
# Written by Zack Weinberg <zackw at panix.com> in 2017.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

# This test is only run if we are building a shared library intended
# to be binary backward compatible with GNU libc (libcrypt.so.1).
# It locates any installed version of libcrypt.so.1, and verifies that
# each public symbol exposed by that library is also exposed by our
# libcrypt.so.1 with a matching symbol version.
#
# Due to limitations in Automake, this program takes parameters from
# the environment:
# $lib_la - full pathname of libcrypt.la
# $host_os - autoconf host_os variable

set -e
LC_ALL=C; export LC_ALL

# BSD-format nm output, when restricted to external, defined symbols,
# has three fields per line: address type name.
# The symbol version is appended to the name field, set off by one or
# more @ signs.
# Symbols whose address is zero and type is A are uninteresting
# (they define the set of symbol version tags).
# Strip addresses and type codes from all other symbols.
# Then, compensate for a bug in some versions of GNU nm where the
# symbol version is printed twice.
# Finally, strip any "symbol prefix" off each name.
get_symbols_with_versions ()
{
    ${NM-nm} --format=bsd --dynamic --extern-only --defined-only \
             --with-symbol-versions "$1" |
        tr -s ' \t\r\v\f' ' ' |
        sed -e '
          /^00* A /d
          /^[0-9a-fA-F][0-9a-fA-F]* [A-Z] /!d
          s/^[0-9a-fA-F]* [A-Z] //
          s/\(@@*[A-Z0-9_.]*\)\1$/\1/
          s/^'"$symbol_prefix"'//
        ' |
        sort -u
}

get_our_symbols_with_versions ()
{
    eval $(grep dlname= "$1")
    get_symbols_with_versions "${1%/*}/.libs/${dlname}"
    unset dlname
}

get_their_symbols_with_versions ()
{
    # Ask the compiler whether a libcrypt.so.1 exists in its search
    # path.  The compiler option -print-file-name should be supported
    # on all operating systems where there's an older libcrypt that we
    # can be backward compatible with.
    their_library=$(${CC-cc} $CFLAGS $LDFLAGS -print-file-name=libcrypt.so.1)

    if [ -z "$their_library" ] || [ "$their_library" = "libcrypt.so.1" ]; then
        printf '%s\n' '- No libcrypt.so.1 to be compatible with' >&2
        exit 77
    fi

    printf '%s%s\n' '- Their library: ' "$their_library" >&2
    get_symbols_with_versions "$their_library"
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

# If 'nm' and/or 'ldd' are not available, this test will not work.
command -v nm > /dev/null 2>&1 || {
    echo "Error: 'nm' is unavailable" >&2
    exit 77
}
command -v ldd > /dev/null 2>&1 || {
    echo "Error: 'ldd' is unavailable" >&2
    exit 77
}

workdir=""
trap '[ -z "$workdir" ] || rm -rf "$workdir" || :' 0
workdir="$(mktemp -d)"

get_our_symbols_with_versions "$lib_la" > "$workdir/our_symbols"
get_their_symbols_with_versions > "$workdir/their_symbols"

# It's okay if we define more symbol (versions) than they do, but every
# symbol they define should have a matching definition in our library.
missing_symbols="$(comm -13 "$workdir/our_symbols" "$workdir/their_symbols")"
if [ -n "$missing_symbols" ]; then
    {
        printf '%s\n%s\n' '*** Missing symbols:' "$missing_symbols"
        printf '\n%s\n' '--- Our symbols:'
        cat "$workdir/our_symbols"
        printf '\n%s\n' '--- Their symbols:'
        cat "$workdir/their_symbols"
    } >&2
    exit 1
fi
exit 0

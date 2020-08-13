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

get_symbols_with_versions ()
{
    ${NM-nm} --dynamic --extern-only --defined-only --with-symbol-versions "$1" |
        ${AWK-awk} -v symbol_prefix="$symbol_prefix" '
            NF == 0 { next }
            {
               sym = $NF;
               if (symbol_prefix != "") { sub("^" symbol_prefix, "", sym); }
               split(sym, t, /@+/);
               if (t[0] != t[1] || t[0] !~ /^[A-Z0-9._]+$/)) { print sym; }
            }
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
    (
        set -e
        cd "$1"
        cat >test.c <<\EOF
extern char *crypt(const char *, const char *);
int main(int argc, char **argv)
{
  return !!crypt(argv[0], argv[1]);
}
EOF
        ${CC-cc} test.c -lcrypt >&2 || exit 77
        if ldd ./a.out | grep -qF libcrypt.so.1; then
            get_symbols_with_versions $(ldd ./a.out | grep -F libcrypt.so.1 |
                                            cut -d' ' -f3)
        else
            exit 77
        fi
    )
    if [ $? -ne 0 ]; then exit $?; fi
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
get_their_symbols_with_versions "$workdir" > "$workdir/their_symbols"

# It's okay if we define more symbol (versions) than they do, but every
# symbol they define should have a matching definition in our library.
missing_symbols="$(comm -13 "$workdir/our_symbols" "$workdir/their_symbols")"
if [ -n "$missing_symbols" ]; then
    printf '*** Missing symbols: %s\n' "$missing_symbols" >&2
    exit 1
fi
exit 0

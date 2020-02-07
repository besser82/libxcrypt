#! /usr/bin/python3
# Written by Zack Weinberg <zackw at panix.com> in 2017-2019.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

"""
This test is only run if we are building a shared library intended
to be binary backward compatible with GNU libc (libcrypt.so.1).
It locates any installed version of libcrypt.so.1, and verifies that
each public symbol exposed by that library is also exposed by our
libcrypt.so.1 with a matching symbol version.

Due to limitations in Automake, this program takes parameters from
the environment:
$CC      - C compiler  (default: 'cc')
$LDD     - ldd utility (default: 'ldd')
$NM      - nm utility  (default: 'nm')
$lib_so  - full pathname of libcrypt.so
$host_os - Autoconf's identifier for the host operating system
"""

import argparse
import os
import re
import shlex
import sys
import subprocess

from common import (
    command,
    ensure_C_locale,
    ensure_absolute_PATH,
    get_symbol_prefix,
    get_symbols,
    run,
    scratch_working_directory,
    write_file,
)

from typing import (
    List,
    Optional,
    Set,
)


def get_symbol_versions(nm: List[str], symbol_prefix: str,
                        library: str) -> Set[str]:
    """Return a set of all the symbols defined by LIBRARY,
       with version information."""

    def filter_symbol_versions(ty: str, sym: str) -> Optional[str]:
        sym, ver = re.split(r"@+", sym, 1)
        # discard the special symbols that name the versions themselves
        if ty == "A" and sym == ver:
            return None
        return sym + " " + ver

    return get_symbols(library, symbol_prefix, nm,
                       nmflags=["--dynamic", "--with-symbol-versions"],
                       filter=filter_symbol_versions)


def find_system_libcrypt(cc: List[str], ldd: List[str]) -> str:
    with scratch_working_directory():
        write_file("test.c", """\
extern char *crypt(const char *, const char *);
int main(int argc, char **argv)
{
  return !!crypt(argv[0], argv[1]);
}
""")
        try:
            run(cc + ["-o", "test.x", "test.c", "-lcrypt"])
        except subprocess.CalledProcessError as e:
            sys.stderr.write("*** " + str(e) + "\n")
            sys.exit(77)

        ldd_out = run(ldd + ["./test.x"], stdout=subprocess.PIPE,
                      encoding="utf-8", errors="backslashreplace")
        for rec in ldd_out.stdout.splitlines():
            fields: List[str] = rec.split()
            if fields[0] == 'libcrypt.so.1':
                return fields[2]

        sys.exit(77)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()

    ensure_absolute_PATH()
    ensure_C_locale()

    lib_so = os.environ.get("lib_so")
    if lib_so is None:
        sys.stderr.write("$lib_so environment variable must be set")
        sys.exit(1)

    host_os = os.environ.get("host_os")
    if host_os is None:
        sys.stderr.write("$host_os environment variable must be set")
        sys.exit(1)

    cc = shlex.split(os.environ.get("CC", "cc"))
    ldd = shlex.split(os.environ.get("LDD", "ldd"))
    nm = shlex.split(os.environ.get("NM", "nm"))

    sys.stderr.write("host_os=" + shlex.quote(host_os) + "\n")
    sys.stderr.write("lib_so=" + shlex.quote(lib_so) + "\n")
    sys.stderr.write("CC=" + " ".join(shlex.quote(w) for w in cc) + "\n")
    sys.stderr.write("LDD=" + " ".join(shlex.quote(w) for w in ldd) + "\n")
    sys.stderr.write("NM=" + " ".join(shlex.quote(w) for w in nm) + "\n")

    # If any of the above tools are unavailable, this test cannot be
    # carried out.
    try:
        command(cc[0])
        command(ldd[0])
        command(nm[0])

    except KeyError as e:
        sys.stderr.write('Skipping test: {!r} is unavailable\n'
                         .format(e.args[0]))
        sys.exit(77)

    symbol_prefix = get_symbol_prefix(host_os)
    their_symbols = get_symbol_versions(nm, symbol_prefix,
                                        find_system_libcrypt(cc, ldd))
    our_symbols = get_symbol_versions(nm, symbol_prefix, lib_so)

    # It's okay if we define more symbol (versions) than they do,
    # but every symbol they define should have a matching
    # definition in our library.
    missing_symbols = their_symbols - our_symbols
    if missing_symbols:
        sys.stderr.write("*** Missing symbols:\n")
        for sym in sorted(missing_symbols):
            sys.stderr.write(sym + "\n")
        sys.exit(1)
    sys.exit(0)


main()

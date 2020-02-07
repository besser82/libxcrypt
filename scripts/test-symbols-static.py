#! /usr/bin/python3
# Written by Zack Weinberg <zackw at panix.com> in 2017-2019.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

"""
Test that all global symbols in the static version of the library
(libcrypt.a) are either listed as global and supported for new code
in libcrypt.map.in, or begin with a _crypt prefix.  Also test that
all of the global, supported for new code, symbols mentioned in
libcrypt.map.in are in fact defined.

Due to limitations in Automake, this program takes parameters from
the environment:
$NM      - nm utility (default: 'nm')
$lib_a   - pathname of libcrypt.a
$lib_map - pathname of libcrypt.map.in
$host_os - Autoconf's identifier for the host operating system
"""

import argparse
import re
import os
import shlex
import sys

from common import (
    command,
    ensure_C_locale,
    ensure_absolute_PATH,
    get_symbols,
    get_symbol_prefix,
)

from typing import (
    List,
    Optional,
    Set,
)


def list_library_globals(nm: List[str], symbol_prefix: str,
                         library: str) -> Set[str]:

    internal_symbol_re = re.compile(r"^_(crypt_|[_A-Y])", re.ASCII)

    def filter_globals(ty: str, sym: str) -> Optional[str]:
        if internal_symbol_re.match(sym):
            return None
        return sym

    return get_symbols(library, symbol_prefix, nm, filter=filter_globals)


def list_allowed_globals(mapfile: str) -> Set[str]:
    symbols = set()
    with open(mapfile, "rt", encoding="utf-8", errors="backslashreplace") as f:
        for line in f:
            tokens = line.split()
            if (
                    len(tokens) >= 2
                    and tokens[1] != '-'
                    and tokens[0] not in ('#', '%chain')
            ):
                symbols.add(tokens[0])
    return symbols


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()

    ensure_absolute_PATH()
    ensure_C_locale()

    lib_a = os.environ.get("lib_a")
    if lib_a is None:
        sys.stderr.write("$lib_a environment variable must be set")
        sys.exit(1)

    lib_map = os.environ.get("lib_map")
    if lib_map is None:
        sys.stderr.write("$lib_map environment variable must be set")
        sys.exit(1)

    host_os = os.environ.get("host_os")
    if host_os is None:
        sys.stderr.write("$host_os environment variable must be set")
        sys.exit(1)

    nm = shlex.split(os.environ.get("NM", "nm"))

    sys.stderr.write("host_os=" + shlex.quote(host_os) + "\n")
    sys.stderr.write("lib_a=" + shlex.quote(lib_a) + "\n")
    sys.stderr.write("lib_map=" + shlex.quote(lib_map) + "\n")
    sys.stderr.write("NM=" + " ".join(shlex.quote(w) for w in nm) + "\n")

    # If 'nm' is not available, this test cannot be carried out.
    try:
        command(nm[0])

    except KeyError as e:
        sys.stderr.write('Skipping test: {!r} is unavailable\n'
                         .format(e.args[0]))
        sys.exit(77)

    library_globals = list_library_globals(
        nm, get_symbol_prefix(host_os), lib_a)
    allowed_globals = list_allowed_globals(lib_map)

    extra_globals = library_globals - allowed_globals
    missing_globals = allowed_globals - library_globals

    if extra_globals:
        sys.stderr.write("*** Extra globals: "
                         + " ".join(sorted(extra_globals))
                         + "\n")
    if missing_globals:
        sys.stderr.write("*** Missing globals: "
                         + " ".join(sorted(missing_globals))
                         + "\n")

    if extra_globals or missing_globals:
        sys.exit(1)

    sys.exit(0)


main()

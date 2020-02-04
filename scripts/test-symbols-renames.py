#! /usr/bin/python3
# Written by Zack Weinberg <zackw at panix.com> in 2017-2019.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

"""
Check that all of the symbols renamed by crypt-port.h still appear
somewhere in the source code.  This test works by scanning the
static library for global symbol definitions, since the point of the
renaming is to ensure namespace cleanliness of the static library.

Due to limitations in Automake, this program takes parameters from
the environment:
$CPP      - C preprocessor (default: 'cc -E')
$CPPFLAGS - additional arguments to pass to $CPP
$NM       - nm utility (default: 'nm')
$lib_la   - full pathname of libcrypt.la
$host_os  - Autoconf's identifier for the host operating system
"""

import argparse
import os
import shlex
import sys
import subprocess

from common import (
    command,
    ensure_C_locale,
    ensure_absolute_PATH,
    find_real_alib,
    get_symbol_prefix,
    get_symbols,
    run,
)

from typing import (
    List,
    Optional,
    Set,
)


def list_library_internals(nm: List[str], symbol_prefix: str,
                           library: str) -> Set[str]:

    def filter_internals(ty: str, sym: str) -> Optional[str]:
        if sym.startswith("_crypt_"):
            return sym
        return None

    return get_symbols(library, symbol_prefix, nm,
                       filter=filter_internals)


def list_symbol_renames(cpp_cmd: List[str]) -> Set[str]:
    cc_out = run(cpp_cmd + ["-dD", "-xc", "-"],
                 input='#include "crypt-port.h"\n',
                 stdout=subprocess.PIPE,
                 encoding="utf-8", errors="backslashreplace")
    renames = set()
    for line in cc_out.stdout.splitlines():
        tokens = line.split()
        if (
                len(tokens) >= 3
                and tokens[0] == "#define"
                and tokens[2].startswith("_crypt_")
        ):
            renames.add(tokens[2])
    return renames


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()

    ensure_absolute_PATH()
    ensure_C_locale()

    lib_la = os.environ.get("lib_la")
    if lib_la is None:
        sys.stderr.write("$lib_la environment variable must be set")
        sys.exit(1)

    host_os = os.environ.get("host_os")
    if host_os is None:
        sys.stderr.write("$host_os environment variable must be set")
        sys.exit(1)

    nm = shlex.split(os.environ.get("NM", "nm"))
    cpp = shlex.split(os.environ.get("CPP", "cc -E"))
    cppflags = shlex.split(os.environ.get("CPPFLAGS", ""))

    sys.stderr.write("host_os=" + shlex.quote(host_os) + "\n")
    sys.stderr.write("lib_la=" + shlex.quote(lib_la) + "\n")
    sys.stderr.write("NM=" + " ".join(shlex.quote(w) for w in nm) + "\n")
    sys.stderr.write("CPP=" + " ".join(shlex.quote(w) for w in cpp) + "\n")
    sys.stderr.write("CPPFLAGS=" + " ".join(shlex.quote(w) for w in cppflags)
                     + "\n")

    # If any of the above tools are unavailable, this test cannot be
    # carried out.
    try:
        command(cpp[0])
        command(nm[0])

    except KeyError as e:
        sys.stderr.write('Skipping test: {!r} is unavailable\n'
                         .format(e.args[0]))
        sys.exit(77)

    internal_symbols = list_library_internals(nm, get_symbol_prefix(host_os),
                                              find_real_alib(lib_la))
    renamed_symbols = list_symbol_renames(cpp + cppflags)

    extra_renames = renamed_symbols - internal_symbols
    missing_renames = internal_symbols - renamed_symbols

    if extra_renames:
        sys.stderr.write("*** Extra renames: "
                         + " ".join(sorted(extra_renames))
                         + "\n")
    if missing_renames:
        sys.stderr.write("*** Missing renames: "
                         + " ".join(sorted(missing_renames))
                         + "\n")

    if extra_renames or missing_renames:
        sys.exit(1)

    sys.exit(0)


main()

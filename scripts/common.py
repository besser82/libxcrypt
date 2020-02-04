#   Copyright 2019, 2020 Zack Weinberg
#
#   This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public License
#   as published by the Free Software Foundation; either version 2.1 of
#   the License, or (at your option) any later version.
#
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, see
#   <https://www.gnu.org/licenses/>.

"""Common code shared among all of the scripts in this directory."""

import contextlib
import locale
import os
import shlex
import stat
import subprocess
import sys
import tempfile

from typing import (
    Any,
    Callable,
    Dict,
    IO,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
)


def log(argv: Iterable[str]) -> None:
    """Log the execution of a command, like sh -x would do it."""
    sys.stderr.write("+ " + " ".join(shlex.quote(w) for w in argv) + "\n")
    sys.stderr.flush()


def log_exc(e: BaseException) -> None:
    """Log an exception E."""
    s = str(e)
    if not s:
        s = type(e).__name__
    sys.stderr.write(s + "\n")
    sys.stderr.flush()


def inode_is_executable(st: os.stat_result) -> bool:
    """Given ST an object returned by one of the os.*stat functions,
       return True if that object describes a file that *could* be
       executed by some user.  (Not necessarily the current user.)
    """
    if not stat.S_ISREG(st.st_mode):
        return False
    if (st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) == 0:
        return False
    return True


_command_cache: Dict[str, str] = {}
_command_path: Optional[str] = None
_command_original_wd: Optional[str] = None


def command(cmd: str) -> str:
    """Search for a shell command named CMD, the same way os.execvp would,
       and return its full pathname.  If CMD is not found, raises
       KeyError."""

    global _command_cache, _command_path, _command_original_wd

    # If the PATH environment variable has been changed,
    # clear the cache of previously looked-up commands.
    path = os.environ.get('PATH', os.defpath)
    if _command_path is None:
        _command_path = path
    elif _command_path != path:
        _command_path = path
        _command_cache.clear()

    # Special case: the command 'false' is never considered to be available.
    # (Autoconf sets config variables like $CC and $NM to 'false' if it can't
    # find the requested tool.)
    if cmd == 'false':
        raise KeyError('false')

    if cmd not in _command_cache:
        if os.sep in cmd or (os.altsep is not None and os.altsep in cmd):
            # don't do path search, but do resolve to an absolute path
            if not os.path.isabs(cmd):
                if _command_original_wd is None:
                    _command_original_wd = os.getcwd()
                cand = os.path.normpath(os.path.join(_command_original_wd,
                                                     cmd))

            # check it exists and is executable, then cache it as is
            st = os.stat(cand)
            if not inode_is_executable(st):
                raise KeyError(cmd)

            _command_cache[cmd] = cand

        else:
            for d in path.split(os.pathsep):
                try:
                    cand = os.path.normpath(os.path.join(d, cmd))
                    st = os.stat(cand)
                except FileNotFoundError:
                    continue
                except OSError as e:
                    raise KeyError(cmd) from e
                if not inode_is_executable(st):
                    raise KeyError(cmd)

                _command_cache[cmd] = cand
                break

            else:
                raise KeyError(cmd)

    return _command_cache[cmd]


@contextlib.contextmanager
def working_directory(wd: str) -> Iterator[None]:
    """Chdir into the specified directory for the duration of the context."""
    cur_wd = os.getcwd()

    global _command_original_wd
    if _command_original_wd is None:
        _command_original_wd = cur_wd

    try:
        log(["cd", wd])
        os.chdir(wd)
        yield
    finally:
        log(["cd", cur_wd])
        os.chdir(cur_wd)


@contextlib.contextmanager
def scratch_working_directory() -> Iterator[str]:
    """Create a temporary directory and chdir into it."""
    cur_wd = os.getcwd()

    global _command_original_wd
    if _command_original_wd is None:
        _command_original_wd = cur_wd

    with tempfile.TemporaryDirectory() as scratch_wd:
        try:
            log(["cd", scratch_wd])
            os.chdir(scratch_wd)
            yield scratch_wd
        finally:
            log(["cd", cur_wd])
            os.chdir(cur_wd)
            log(["rm", "-rf", scratch_wd])


def ensure_absolute_PATH() -> None:
    """If any paths in $PATH are relative, replace them with absolute
       paths, so they still work within a scratch_working_directory block."""
    opath = os.environ.get('PATH', os.defpath)
    seen: Set[str] = set()
    npath = []
    for d in opath.split(os.pathsep):
        d = os.path.abspath(d)
        if d not in seen:
            npath.append(d)
            seen.add(d)
    xpath = os.pathsep.join(npath)
    if xpath != opath:
        os.environ['PATH'] = xpath


def ensure_C_locale() -> None:
    """Force the use of the C locale for this process and all subprocesses.
       This is necessary because subprocesses' output may be locale-dependent.
       If the C.UTF-8 locale is available, it is used, otherwise the plain
       C locale."""
    drop = [
        k for k in os.environ.keys()
        if k == "LANG" or k == "LANGUAGE" or k.startswith("LC_")
    ]
    for k in drop:
        del os.environ[k]
    try:
        locale.setlocale(locale.LC_ALL, "C.UTF-8")
        os.environ["LC_ALL"] = "C.UTF-8"
    except locale.Error:
        locale.setlocale(locale.LC_ALL, "C")
        os.environ["LC_ALL"] = "C"


# the return type of this function must be hidden from python proper
def run(argv: Iterable[str],
        check: bool = True,
        **kwargs: Any) -> 'subprocess.CompletedProcess[Any]':
    """Like subprocess.run, but logs the argument vector to stderr,
       caches PATH lookups, and defaults to throwing an exception on
       failure.
    """
    xargv: List[str] = []
    xargv.extend(argv)
    xargv[0] = command(xargv[0])
    log(xargv)
    return subprocess.run(xargv, check=check, **kwargs)


def write_file(name: str, contents: str) -> None:
    """Create text file NAME with contents CONTENTS, and log this."""
    sys.stderr.write("+ cat > {} <<\\EOF\n{}EOF\n".format(
        shlex.quote(name), contents))
    with open(name, "wt", encoding="utf-8") as fp:
        fp.write(contents)


@contextlib.contextmanager
def atomic_update_file(name: str,
                       mode: str = "wt",
                       encoding: str = "utf-8",
                       **kwargs: Any) -> Iterator[IO[Any]]:
    """Upon context entry, produce a file object open for writing.
       Upon _successful_ context exit, whatever has been written to
       this file object atomically replaces the file named NAME.
       (If NAME previously did not exist, it comes into existence
       upon successful context exit.)"""

    if mode not in ("w", "wb", "wt"):
        raise ValueError("improper mode for atomic_update_file: " + mode)
    if "closefd" in kwargs:
        raise TypeError(
            "atomic_update_file() got an unexpected keyword argument 'closefd'"
        )
    if "opener" in kwargs:
        raise TypeError(
            "atomic_update_file() got an unexpected keyword argument 'opener'"
        )

    (fd, tpath) = tempfile.mkstemp(dir=os.path.dirname(name) or ".")
    try:
        with open(fd, mode=mode, encoding=encoding,
                  closefd=False, **kwargs) as fp:
            yield fp
        os.fsync(fd)

    except BaseException:
        os.close(fd)
        os.unlink(tpath)
        raise

    os.close(fd)
    os.rename(tpath, name)


def find_real_shlib(lib_la: str) -> str:
    """Given a Libtool .la file, locate the actual shared library it
       refers to."""

    with open(lib_la, "rt", encoding="utf-8", errors="backslashreplace") as fp:
        for line in fp:
            if line.startswith("dlname="):
                dlname = shlex.split(line.partition("=")[2])[0]
                return os.path.join(os.path.dirname(lib_la),
                                    ".libs", dlname)

    sys.stderr.write("{}: dlname= line not found\n".format(lib_la))
    sys.exit(1)


def find_real_alib(lib_la: str) -> str:
    """Given a Libtool .la file, locate the actual static library it
       refers to."""

    with open(lib_la, "rt", encoding="utf-8", errors="backslashreplace") as fp:
        for line in fp:
            if line.startswith("old_library="):
                old_library = shlex.split(line.partition("=")[2])[0]
                return os.path.join(os.path.dirname(lib_la),
                                    ".libs", old_library)

    sys.stderr.write("{}: old_library= line not found\n".format(lib_la))
    sys.exit(1)


def get_symbols(library: str,
                symbol_prefix: str,
                nm: Iterable[str], *,
                nmflags: Iterable[str] = [],
                filter: Callable[[str, str], Optional[str]] = (lambda t, s: s)
                ) -> Set[str]:
    """Get a set of all the globally visible symbols defined by LIBRARY.
       SYMBOL_PREFIX is a prefix to remove from all symbols
           (see get_symbol_prefix for further explanation).
       NM is an argument vector that invokes the 'nm' utility.
       NMFLAGS are additional command-line flags to pass to 'nm'.
       FILTER is an optional callback that can filter and/or rewrite
           the symbols.  It takes the type code for the symbol
           (e.g. 'T' for a function, 'D' for writable data, 'R' for
           read-only data) and the symbol name, in that order, and
           returns either a modified version of the symbol name, or
           None to drop the symbol.
    """

    argv: List[str] = []
    argv.extend(nm)
    argv.append("-gop")  # --extern-only --print-file-name --no-sort
    argv.append("--defined-only")
    argv.extend(nmflags)
    argv.append(library)

    nm_out = run(argv,
                 stdout=subprocess.PIPE, stdin=subprocess.DEVNULL,
                 encoding="utf-8", errors="backslashreplace")

    symbols = set()
    l_symbol_prefix = len(symbol_prefix)
    for rec in nm_out.stdout.splitlines():
        fields = rec.split()
        ty = fields[-2]
        sym = fields[-1]
        if symbol_prefix and sym.startswith(symbol_prefix):
            sym = sym[l_symbol_prefix:]
        xsym = filter(ty, sym)
        if xsym:
            symbols.add(xsym)

    return symbols


def get_symbol_prefix(host_os: str) -> str:
    """Return the prefix that is prepended to all global symbols defined in
       C on this operating system.   This is a function of the object file
       format; the original Unix a.out format prepended a '_' to all symbols
       defined in C (so there could be symbols accessible only from assembly
       language), and this convention was copied by some formats still in use
       (e.g. Mach-O).  ELF, on the other hand, does not do this."""

    if "darwin" in host_os:
        # Mach-O uses _ as the prefix.
        return "_"
    else:
        # Assume ELF and report an empty prefix.
        return ""

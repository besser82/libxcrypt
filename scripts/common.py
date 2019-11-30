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


def log(argv):
    """Log the execution of a command, like sh -x would do it."""
    sys.stderr.write("+ " + " ".join(shlex.quote(w) for w in argv) + "\n")
    sys.stderr.flush()


def log_exc(e):
    """Log an exception E."""
    s = str(e)
    if not s:
        s = type(e).__name__
    sys.stderr.write(s + "\n")
    sys.stderr.flush()


def inode_is_executable(st):
    """Given ST an object returned by one of the os.*stat functions,
       return True if that object describes a file that *could* be
       executed by some user.  (Not necessarily the current user.)
    """
    if not stat.S_ISREG(st.st_mode):
        return False
    if (st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) == 0:
        return False
    return True


_command_cache = {}
_command_path = None
_command_original_wd = None


def command(cmd):
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

    if cmd not in _command_cache:
        if os.sep in cmd or (os.altsep is not None and os.altsep in cmd):
            # don't do path search, but do resolve to an absolute path
            if not os.path.isabs(cmd):
                if _command_original_wd is None:
                    _command_original_wd = os.getcwd()
                cand = os.path.normpath(os.path.join(_command_original_wd, cmd))

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
def scratch_working_directory():
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


def ensure_absolute_PATH():
    """If any paths in $PATH are relative, replace them with absolute
       paths, so they still work within a scratch_working_directory block."""
    opath = os.environ.get('PATH', os.defpath)
    seen = set()
    npath = []
    for d in opath.split(os.pathsep):
        d = os.path.abspath(d)
        if d not in seen:
            npath.append(d)
            seen.add(d)
    npath = os.pathsep.join(npath)
    if npath != opath:
        os.environ['PATH'] = npath


def ensure_C_locale():
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


def run(argv, check=True, **kwargs):
    """Like subprocess.run, but logs the argument vector to stderr,
       caches PATH lookups, and defaults to throwing an exception on
       failure.
    """
    log(argv)
    argv[0] = command(argv[0])
    return subprocess.run(argv, check=check, **kwargs)


def write_file(name, contents):
    """Create text file NAME with contents CONTENTS, and log this."""
    sys.stderr.write("+ cat > {} <<\\EOF\n{}EOF\n".format(
        shlex.quote(name), contents))
    with open(name, "wt", encoding="utf-8") as fp:
        fp.write(contents)


@contextlib.contextmanager
def atomic_update_file(name, mode="wt", encoding="utf-8", **kwargs):
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

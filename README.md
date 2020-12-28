[![Build Status](https://travis-ci.org/besser82/libxcrypt.svg?branch=develop)](https://travis-ci.org/besser82/libxcrypt)
[![COPR Build Status](https://copr.fedorainfracloud.org/coprs/besser82/libxcrypt_CI/package/libxcrypt/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/besser82/libxcrypt_CI)
[![codecov](https://codecov.io/gh/besser82/libxcrypt/branch/develop/graph/badge.svg)](https://codecov.io/gh/besser82/libxcrypt)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/17073/badge.svg)](https://scan.coverity.com/projects/besser82-libxcrypt)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1ebaa2314aca4bab92e14130906d5096)](https://www.codacy.com/manual/besser82/libxcrypt?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=besser82/libxcrypt&amp;utm_campaign=Badge_Grade)

README for libxcrypt
====================

libxcrypt is a modern library for one-way hashing of passwords.  It
supports a wide variety of both modern and historical hashing methods:
yescrypt, gost-yescrypt, scrypt, bcrypt, sha512crypt, sha256crypt,
md5crypt, SunMD5, sha1crypt, NT, bsdicrypt, bigcrypt, and descrypt.
It provides the traditional Unix `crypt` and `crypt_r` interfaces, as
well as a set of extended interfaces pioneered by Openwall Linux,
`crypt_rn`, `crypt_ra`, `crypt_gensalt`, `crypt_gensalt_rn`, and
`crypt_gensalt_ra`.

libxcrypt is intended to be used by `login(1)`, `passwd(1)`, and other
similar programs; that is, to hash a small number of passwords during
an interactive authentication dialogue with a human.  It is not
suitable for use in bulk password-cracking applications, or in any
other situation where speed is more important than careful handling of
sensitive data.  However, it *is* intended to be fast and lightweight
enough for use in servers that must field thousands of login attempts
per minute.

Authorship and Licensing
------------------------

libxcrypt is currently maintained by Björn Esser and Zack Weinberg.
Many people have contributed to the code making up libxcrypt, often
under the aegis of a different project.  Please see the AUTHORS and
THANKS files for a full set of credits.

libxcrypt as a whole is licensed under the GNU Lesser General Public
License (version 2.1, or at your option, any later version).  However,
many individual files may be reused under more permissive licenses if
separated from the library.  Please see the LICENSING file for a
comprehensive inventory of licenses, and COPYING.LIB for the terms of
the LGPL.

Bug Reports, Feature Requests, Contributions, Etc.
--------------------------------------------------

libxcrypt is currently maintained at Github: the canonical repository
URL is <https://github.com/besser82/libxcrypt>.  Please file bug
reports at <https://github.com/besser82/libxcrypt/issues>.  This is
also the appropriate place to suggest new features, offer patches,
etc.  All your feedback is welcome and will eventually receive a
response, but this is a spare-time project for all of the present
maintainers, so please be patient.

Build Requirements and Instructions
-----------------------------------

To build from a tarball release, the tools required are the standard
Unix shell environment, a C compiler, and Perl (version 5.14 or
later).  Follow the generic build and installation instructions in the
file `INSTALL`.  There are several package-specific configure options;
run `./configure --help` for more detail on these options.
Run `man -l crypt.5` for more detail on the hashing algorithms that
can be enabled or disabled by `--enable-hashes`.  You can do both of
these things before building the software.

Building from a Git checkout additionally requires the Autotools
suite: `autoconf`, `automake`, `libtool`, and `pkg-config`.
Run `./autogen.sh` at the top level of the source tree, and then
follow the instructions in `INSTALL` (which is created by that command).

The oldest versions of Autotools components that are known to work
are: autoconf 2.69, automake 1.14, libtool 2.4.6, pkg-config 0.29.
If you test with an older version of one of these and find that it
works, please let us know.  We are not deliberately requiring newer
versions; we just can’t conveniently test older versions ourselves.

Portability Notes
-----------------

libxcrypt should be buildable with any ISO C1999-compliant C compiler,
with one critical exception: the symbol versioning macros in
`crypt-port.h` only work with compilers that implement certain GCC and
GNU Binutils extensions (`__attribute__((alias))`, GCC-style `asm`,
and `.symver`).

A few C2011 features are used; the intention is not to use any of them
without a fallback, but we do not currently test this.  A few POSIX
and nonstandard-but-widespread Unix APIs are also used; again, the
intention is not to use any of them without a fallback, but we do not
currently test this.  In particular, the crypt_gensalt functions may
not always be able to retrieve cryptographically-sound random numbers
from the operating system; if you call these functions with a null
pointer for the “rbytes” argument, be prepared for them to fail.

As of mid-2018, GCC and LLVM don’t support link-time optimization of
libraries that use symbol versioning.  If you build libxcrypt with
either of these compilers, do not use `-flto`.  See [GCC bug 48200][1]
for specifics; the problem is very similar for LLVM.  Because this is,
at its root, a set of missing compiler features, we expect link-time
optimization won’t work in other C compilers either, but we haven’t
tested it ourselves.

[1]: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=48200

Compatibility Notes
-------------------

On Linux-based systems, by default libxcrypt will be binary backward
compatible with the libcrypt.so.1 shipped as part of the GNU C
Library.  This means that all existing binary executables linked
against glibc’s libcrypt should work unmodified with this library’s
libcrypt.so.1.  We have taken pains to provide exactly the same symbol
versions as were used by glibc on various CPU architectures, and to
account for the variety of ways in which the Openwall extensions were
patched into glibc’s libcrypt by some Linux distributions.  (For
instance, compatibility symlinks for SUSE’s “libowcrypt” are provided.)

However, the converse is not true: programs linked against libxcrypt
will not work with glibc’s libcrypt.  Also, programs that use certain
legacy APIs supplied by glibc’s libcrypt (`encrypt`, `encrypt_r`,
`setkey`, `setkey_r`, and `fcrypt`) cannot be *compiled* against
libxcrypt.

Binary backward compatibility can be disabled by supplying the
`--disable-obsolete-api` switch to `configure`, in which case libxcrypt
will install libcrypt.so.2 instead of libcrypt.so.1.  This
configuration is always used on all operating systems other than
Linux.  We are willing to consider adding binary backward
compatibility for other operating systems’ existing libcrypts, but we
don’t currently plan to do that work ourselves.

Individual hash functions may be enabled or disabled by use of the
`--enable-hashes` switch to `configure`.  The default is to enable all
supported hashes.  Disabling the traditional ‘des’ hash algorithm
implies `--disable-obsolete-api`.  Security-conscious environments
without backward compatibility constraints are encouraged to use
`--enable-hashes=strong`, which enables only the hash functions that
are strong enough to be safe for newly hashed passwords.

The original implementation of the SunMD5 hashing algorithm has a bug,
which is mimicked by libxcrypt to be fully compatible with hashes
generated on (Open)Solaris.  According to the only existing
[documentation of this algorithm][2], its hashes were supposed to have
the format `$md5[,rounds=%u]$<salt>$<checksum>`, and include only the
bare string `$md5[,rounds=%u]$<salt>` in the salt digest
step. However, almost all hashes encountered in production
environments have the format `$md5[,rounds=%u]$<salt>$$<checksum>`
(note the double $$).  Unfortunately, it is not merely a cosmetic
difference: hashes of this format incorporate the first $ after the
salt within the salt digest step, so the resulting checksum is
different.  The documentation hints that this stems from a bug within
the production implementation’s parser.  This bug causes the
implementation to return `$$`-format hashes when passed a
configuration string that ends with `$`.  It returns the intended
original format and checksum only if there is at least one letter
after the `$`, e.g. `$md5[,rounds=%u]$<salt>$x`.

The NT algorithm, in its original implementation, never came with any
`gensalt` function, because the algorithm does not use any.  libxcrypt
ships a bogus `gensalt` function for the NT algorithm, which simply
returns `$3$`.

glibc’s libcrypt could optionally be configured to use Mozilla’s NSS
library’s implementations of the cryptographic primitives md5crypt,
sha256crypt, and sha512crypt.  This option is not available in
libxcrypt, because we do not currently believe it is a desirable
option.  The stated rationale for the option was to source all
cryptographic primitives from a library that has undergone FIPS
certification, but we believe FIPS certification would need to cover
all of libxcrypt itself to have any meaningful value.  Moreover, the
strongest hashing methods, yescrypt and bcrypt, use cryptographic
primitives that are not available from NSS, so the certification
would not cover any part of what will hopefully be the most used code
paths.

[2]: https://dropsafe.crypticide.com/article/1389

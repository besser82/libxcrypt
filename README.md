[![Build Status](https://travis-ci.org/besser82/libxcrypt.svg?branch=develop)](https://travis-ci.org/besser82/libxcrypt)
[![COPR Build Status](https://copr.fedorainfracloud.org/coprs/besser82/libxcrypt_CI/package/libxcrypt/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/besser82/libxcrypt_CI)
[![codecov](https://codecov.io/gh/besser82/libxcrypt/branch/develop/graph/badge.svg)](https://codecov.io/gh/besser82/libxcrypt)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/17073/badge.svg)](https://scan.coverity.com/projects/besser82-libxcrypt)

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

To build libcrypt from either a tarball release or a Git checkout,
the tools required are: the standard Unix shell environment;
a C compiler; Python 3.6 or later (no third-party packages are required);
the low-level build tool “ninja” (see <https://ninja-build.org/>);
and the high-level build tool “meson” (see <https://mesonbuild.com/>).
The GNU `nm` and `objcopy` tools are used at a few points during the
build; if you are cross-compiling, you may need to specify appropriate
variants of these tools in the `[binaries]` section of the Meson
cross-build definition file.

The oldest version of ninja that is known to work is 1.8.2.
The oldest version of meson that is known to work is 0.53.
Versions of meson up to and including 0.49 are known *not* to work.

From the top level of the source tree, the following shell recipe will
generate and install a standard build of the library.

```sh
meson setup build
ninja -C build
meson test -C build
sudo meson install -C build --no-rebuild
```

See <https://mesonbuild.com/Builtin-options.html> for universal
configuration options that can be supplied to `meson setup`, and
`meson_options.txt` for project-specific configuration options.

Run `man -l doc/crypt.5` for more detail on the hashing algorithms
that can be enabled or disabled by `-Dhashes`.  You can do this
immediately after unpacking the source.

libxcrypt currently cannot be compiled with any sort of cross-file
optimization; the build will fail if you use either `-Db_lto=true` or
`--unity on`.  This is because of missing compiler features; see
[GCC bug 48200][1] for specifics.  (The situation is known to be
the same for LLVM and icc as well as GCC.  We have not tried
building this library with any other compiler, but we expect
it is the same for them as well.)

[1]: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=48200

Portability Notes
-----------------

libxcrypt should be buildable with any ISO C1999-compliant C compiler.
A few C2011 features are used, as are a few CPU-specific features; the
intention is not to use any of them without a fallback, but we do not
currently test this.  A few POSIX and nonstandard-but-widespread Unix
APIs are also used; again, the intention is not to use any of them
without a fallback, but we do not currently test this.

Binary backward compatibility with GNU libc (see below) requires
support for ELF symbol versioning (including GNU extensions to the
original Solaris spec) from the toolchain and dynamic linker.  This
feature is disabled on systems where the C library is not glibc, but
building on such systems is not currently tested either.

The static `libcrypt.a` is rewritten after compilation to avoid
polluting the application namespace with internal symbols.  This
process currently requires features of the `nm` and `objcopy`
utilities that are specific to GNU Binutils.

Depending on the underlying operating system, the crypt_gensalt
functions are not always able to generate cryptographically-sound
random numbers themselves.  Callers that supply a null pointer for the
“rbytes” argument must be prepared for these functions to fail.

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
`-Dobsolete-api=false` switch to `configure`, in which case libxcrypt
will install libcrypt.so.2 instead of libcrypt.so.1.  This
configuration is always used on all operating systems other than
Linux.  We are willing to consider adding binary backward
compatibility for other operating systems’ existing libcrypts, but we
don’t currently plan to do that work ourselves.

Individual hash functions may be enabled or disabled by use of the
`-Dhashes` switch to `meson setup`.  The default is to enable all
supported hashes.  Disabling the traditional ‘des’ hash algorithm
implies `-Dobsolete-api=false`.  Security-conscious environments
without backward compatibility constraints are encouraged to use
`-Dhashes=strong`, which enables only the hash functions that are
strong enough to be safe for newly hashed passwords.

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


[2]: https://dropsafe.crypticide.com/article/1389

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

[![Build Status](https://travis-ci.org/besser82/libxcrypt.svg?branch=develop)](https://travis-ci.org/besser82/libxcrypt)
[![codecov](https://codecov.io/gh/besser82/libxcrypt/branch/develop/graph/badge.svg)](https://codecov.io/gh/besser82/libxcrypt)

README for libxcrypt
====================

libxcrypt is a modern library for one-way hashing of passwords.  It
supports DES, MD5, NTHASH, SUNMD5, SHA-2-256, SHA-2-512, and
bcrypt-based password hashes, and provides the traditional Unix `crypt`
and `crypt_r` interfaces, as well as a set of extended interfaces
pioneered by Openwall Linux, `crypt_rn`, `crypt_ra`, `crypt_gensalt`,
`crypt_gensalt_rn`, and `crypt_gensalt_ra`.

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
under the aegis of a different project.  We particularly wish to thank
Solar Designer, Ulrich Drepper, David Burren, and Thorsten Kukuk.
Please see the AUTHORS and THANKS files for a full set of credits.

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

Portability Notes
-----------------

libxcrypt should be buildable with any ISO C1999-compliant C compiler,
with one critical exception: the symbol versioning macros in
`crypt-port.h` only work with compilers that implement certain GCC/GNU
Binutils extensions (`.symver`, `__asm__`, and `__attribute__((alias)))`.

A few C2011 features are used; the intention is not to use any of them
without a fallback, but we do not currently test this.  A few POSIX
and nonstandard-but-widespread Unix APIs are also used; again, the
intention is not to use any of them without a fallback, but we do not
currently test this.  In particular, the crypt_gensalt functions may
not always be able to retrieve cryptographically-sound random numbers
from the operating system; if you call these functions with a null
pointer for the "rbytes" argument, be prepared for them to fail.

Compatibility Notes
-------------------

On Linux-based systems, by default libxcrypt will be binary backward
compatible with the libcrypt.so.1 shipped as part of the GNU C
Library.  This means that all existing binary executables linked
against glibc's libcrypt should work unmodified with this library's
libcrypt.so.1.  We have taken pains to provide exactly the same
"symbol versions" as were used by glibc on various CPU architectures,
and to account for the variety of ways in which the Openwall
extensions were patched into glibc's libcrypt by some Linux
distributions.  (For instance, compatibility symlinks for SUSE's
"libowcrypt" are provided.)

However, the converse is not true: programs linked against libxcrypt
will not work with glibc's libcrypt.  Also, programs that use certain
legacy APIs supplied by glibc's libcrypt (`encrypt`, `encrypt_r`,
`setkey`, `setkey_r`, and `fcrypt`) cannot be *compiled* against
libxcrypt.

Binary backward compatibility can be disabled by supplying the
`--disable-obsolete-api` switch to `configure`, in which case libxcrypt
will install libcrypt.so.2 instead of libcrypt.so.1.  This
configuration is always used on all operating systems other than
Linux.  We are willing to consider adding binary backward
compatibility for other operating systems' existing libcrypts, but we
don't currently plan to do that work ourselves.

Individual hash functions may be enabled or disabled by use of the
`--enable-hashes` switch to `configure`.  The default is to enable all
supported hashes.  Disabling the traditional 'des' hash algorithm
implies `--disable-obsolete-api`.  Security-conscious environments
without backward compatibility constraints are encouraged to use
`--enable-hashes=strong`, which enables only the hash functions that
are strong enough to be safe for newly hashed passwords.

The original implementation of the SUNMD5 hashing algorithm has a bug,
which is mimicked by libxcrypt to be fully compatible with hashes
generated on (Open)Solaris: According to the only existing
[documentation of this algorithm](https://dropsafe.crypticide.com/article/1389),
its hashes were supposed to have the format
`$md5[,rounds=%u]$<salt>$<checksum>`, and include only the bare
string `$md5[,rounds=%u]$<salt>` in the salt digest step. However,
almost all hashes encountered in production environments have the
format `$md5[,rounds=%u]$<salt>$$<checksum>` (note the double $$).
Unfortunately, it is not merely a cosmetic difference: hashes of this
format incorporate the first $ after the salt within the salt digest
step, so the resulting checksum is different.
The documentation hints that this stems from a bug within the
production implementation’s parser.  This bug causes the
implementation to return `$$`-format hashes when passed a configuration
string that ends with `$`.  It returns the intended original format
and checksum only if there is at least one letter after the `$`,
e.g. `$md5[,rounds=%u]$<salt>$x`.

The NTHASH algorithm, in its original implementation, never came with
any `gensalt` function, because the algorithm does not use any.
libxcrypt ships a bogus `gensalt` function for the NTHASH algorithm,
which simply returns `$3$__not_used__XXXXXXXXXXXXXX`, where the `X`s
stand for some more or less random salt.  There is no difference in
the resulting hash returned by the `crypt` function, whether using
one of the hashes returned by `gensalt` or simply using `$3$` as a
setting for hashing a password with NTHASH.

As a final compatibility note, glibc's libcrypt could optionally be
configured to use Mozilla's NSS library's implementations of the
cryptographic primitives MD5, SHA-2-256, and SHA-2-512.  This option
does not currently exist in libxcrypt, because we do not currently
believe it is a desirable option.  The stated rationale for the option
in glibc is to source all cryptographic primitives from a library that
has undergone FIPS certification, but we believe FIPS certification
would need to cover all of libxcrypt itself to have any meaningful
value.  Moreover, the primitive currently recommended for use by new
password hashes, bcrypt, is not available from NSS, so the
certification would not cover any part of what will hopefully be the
most used code path.

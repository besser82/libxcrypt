to-do list for libxcrypt
------------------------

This list is categorized but not in any kind of priority order.
It was last updated 20 October 2018.

* Code cleanliness
  * Find and remove any code that still does dodgy things with type punning
  * Factor out all of the repetitive base64 code
  * Factor out the multiple implementations of HMAC and PBKDF

* Testsuite improvements
  * Investigate branch coverage
  * Do some API fuzz testing and add missing cases to the testsuite
  * Many of the `test-crypt-*.c` files repeat more or less the same
    code with different data, consider merging them

* Portability
  * Make sure the symbol versioning macros work with all of the
    compilers that anyone needs (they use GCC extensions that clang
    also supports).

* Hardening
  * bcrypt-like selftest/memory scribble for all hashing methods
    * how do we know the memory scribble is doing its job?
  * build out of the box with compiler hardening features turned on
  * something bespoke for not having to write serialization and
    deserialization logic for hash strings by hand, as this is
    probably the most error-prone part of writing a hashing method

  * the most sensitive piece of data handled by this library is a
    cleartext passphrase.  OS may have trusted-path facilities for
    prompting the user for a passphrase and feeding it to a KDF
    without its ever being accessible in normal memory.  investigate
    whether we can use these.

* Additional hashing methods
  * Argon2 <https://password-hashing.net/>
  * ...?

* Runtime configurability (in progress on the [crypt.conf branch][])
  * allow installations to enable or disable specific hash methods
    without rebuilding the library
  * make the default cost parameter used by `crypt_gensalt_*` for new
    hashes configurable
  * update the compiled-in defaults used by `crypt_gensalt_*` (not the
    defaults used when no explicit cost parameter is present in a
    hash; those can’t be changed without breaking existing stored hashes)
    * relevant benchmarking at
      <https://pthree.org/2016/06/28/lets-talk-password-hashing/>
  * offer a way to tune cost parameters for a specific installation
  * N.B. Solaris 11 has all of these features but our implementation will
    probably not match them (they have a `crypt.conf` but it’s not the
    same, and their `crypt_gensalt` is API-incompatible anyway).

[crypt.conf branch]: https://github.com/besser82/libxcrypt/tree/zack/crypt.conf

* Potential API enhancements:

  * Support for "pepper" (an additional piece of information, _not_
    stored in the password file, that you need to check a password)

  * Reading passphrases from the terminal is finicky and there are
    several competing, poorly portable, questionably sound library
    functions to do it (`getpass`, `readpassphrase`, etc) -- should we
    incorporate one?
    * If we do, should it know how to trigger the trusted-path
      password prompt in modern GUI environments? (probably)

  * Make the crypt and crypt_gensalt static state thread-specific?
    * Solaris 11 may have done this (its `crypt(3)` manpage describes
      it as MT-Safe and I don’t see any other way they could have
      accomplished that).
    * if allocated on first use, this would also shave 32kB of
      data segment off the shared library
    * alternatively, add a global lock and *crash the program* if we
      detect concurrent calls

  * Allow access to more of yescrypt’s tunable parameters and ROM
    feature, in a way that’s generic enough that we could also use it
    for e.g. Argon2’s tunable parameters

  * Other yescrypt-inspired features relevant to using this library to
    back a “dedicated authentication service,” e.g. preallocation of
    large blocks of scratch memory
    * the main obstacles here are that `struct crypt_data` has a fixed
      size which is either too big or too small depending how you look
      at it, and no destructor function

* Permissive relicensing, to encourage use beyond the GNU ecosystem?
  * Replace crypt-md5.c with original md5crypt from FreeBSD?
  * Other files subject to the (L)GPL are crypt.c, crypt-static.c,
    crypt-gensalt-static.c, crypt-obsolete.h, crypt-port.h,
    test-badsalt.c.  It is not clear to me how much material originally
    assigned to the FSF remains in these files.
    Several of them are API definitions and trivial wrappers that
    could not be meaningfully changed without breaking them (so are
    arguably uncopyrightable).
  * Most of the test suite lacks any license or even authorship
    information.  We would have to track down the original authors.

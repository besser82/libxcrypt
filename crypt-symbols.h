#ifndef _CRYPT_SYMBOLS_H
#define _CRYPT_SYMBOLS_H 1

#include "config.h"

#undef NDEBUG
#include <assert.h>

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#ifndef HAVE_SYS_CDEFS_THROW
#define __THROW /* nothing */
#endif

#ifndef HAVE_SYS_CDEFS_NONNULL
#define __nonnull(param) /* nothing */
#endif

/* Suppression of unused-argument warnings.  */
#if defined __GNUC__ && __GNUC__ >= 3
# define ARG_UNUSED(x) x __attribute__ ((__unused__))
#else
# define ARG_UNUSED(x) x
#endif

/* static_assert shim.  */
#ifdef HAVE_STATIC_ASSERT_IN_ASSERT_H
/* nothing to do */
#elif defined HAVE__STATIC_ASSERT
# define static_assert(expr, message) _Static_assert(expr, message)
#else
/* This fallback is known to work with most C99-compliant compilers.
   See verify.h in gnulib for extensive discussion.  */
# define static_assert(expr, message) \
  extern int (*xcrypt_static_assert_fn (void)) \
  [!!sizeof (struct { int xcrypt_error_if_negative: (expr) ? 2 : -1; })]
#endif

/* Per-symbol version tagging.  Currently we only know how to do this
   using GCC extensions.  */

#if defined __GNUC__ && __GNUC__ >= 3

/* Define ALIASNAME as a strong alias for NAME.  */
#define strong_alias(name, aliasname) _strong_alias(name, aliasname)
#define _strong_alias(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((alias (#name)))

/* Set the symbol version for EXTNAME, which uses INTNAME as its
   implementation.  */
#define symver_set(extname, intname, version, mode) \
  __asm__ (".symver " #intname "," #extname mode #version)

/* A construct with the same syntactic role as the expansion of symver_set,
   but which does nothing.  */
#define symver_nop() __asm__ ("")

#else
#error "Don't know how to do symbol versioning with this compiler"
#endif

/* The macros for versioned symbols work differently in this library
   than they do in glibc.  They are mostly auto-generated (see gen-vers.awk),
   and we currently don't support compatibility symbols that need a different
   definition from the default version.

   Each definition of a public symbol should look like this:
   #if INCLUDE_foo
   int foo(arguments)
   {
     body
   }
   SYMVER_foo;
   #endif

   and the macros take care of the rest.  Normally, to call a public
   symbol you do nothing special.  The macro symver_ref() forces
   all uses of a particular name (in the file where it's used) to refer
   to a particular version of a public symbol, e.g. for testing.  */

#ifdef IN_LIBCRYPT

#include "crypt-symbol-vers.h"

#ifdef PIC

#define symver_compat(n, extname, intname, version) \
  strong_alias (intname, extname ## __ ## n); \
  symver_set (extname, extname ## __ ## n, version, "@")

#define symver_compat0(extname, intname, version) \
  symver_set (extname, intname, version, "@")

#define symver_default(extname, intname, version) \
  symver_set (extname, intname, version, "@@")

#else

/* When not building the shared library, don't do any of this.  */
#define symver_compat(n, extname, intname, version) symver_nop ()
#define symver_compat0(extname, intname, version) symver_nop ()
#define symver_default(extname, intname, version) symver_nop ()

#endif
#endif

/* Tests may need to _refer_ to compatibility symbols, but should never need
   to _define_ them.  */

#define symver_ref(extname, intname, version) \
  symver_set(extname, intname, version, "@")

/* Rename all of the internal-but-global symbols with a _crypt_ prefix
   so that they do not interfere with other people's code when linking
   statically.  This list cannot be autogenerated, but is validated by
   test-symbols.sh.  */

#define comp_maskl               _crypt_comp_maskl
#define comp_maskr               _crypt_comp_maskr
#define crypt_bcrypt_rn          _crypt_crypt_bcrypt_rn
#define crypt_des_trd_or_big_rn  _crypt_crypt_des_trd_or_big_rn
#define crypt_des_xbsd_rn        _crypt_crypt_des_xbsd_rn
#define crypt_md5_rn             _crypt_crypt_md5_rn
#define crypt_sha256_rn          _crypt_crypt_sha256_rn
#define crypt_sha512_rn          _crypt_crypt_sha512_rn
#define des_crypt_block          _crypt_des_crypt_block
#define des_set_key              _crypt_des_set_key
#define des_set_salt             _crypt_des_set_salt
#define fp_maskl                 _crypt_fp_maskl
#define fp_maskr                 _crypt_fp_maskr
#define gensalt_bcrypt_a_rn      _crypt_gensalt_bcrypt_a_rn
#define gensalt_bcrypt_b_rn      _crypt_gensalt_bcrypt_b_rn
#define gensalt_bcrypt_x_rn      _crypt_gensalt_bcrypt_x_rn
#define gensalt_bcrypt_y_rn      _crypt_gensalt_bcrypt_y_rn
#define gensalt_des_trd_rn       _crypt_gensalt_des_trd_rn
#define gensalt_des_xbsd_rn      _crypt_gensalt_des_xbsd_rn
#define gensalt_md5_rn           _crypt_gensalt_md5_rn
#define gensalt_sha256_rn        _crypt_gensalt_sha256_rn
#define gensalt_sha512_rn        _crypt_gensalt_sha512_rn
#define ip_maskl                 _crypt_ip_maskl
#define ip_maskr                 _crypt_ip_maskr
#define key_perm_maskl           _crypt_key_perm_maskl
#define key_perm_maskr           _crypt_key_perm_maskr
#define md5_finish_ctx           _crypt_md5_finish_ctx
#define md5_init_ctx             _crypt_md5_init_ctx
#define md5_process_bytes        _crypt_md5_process_bytes
#define m_sbox                   _crypt_m_sbox
#define psbox                    _crypt_psbox
#define sha256_finish_ctx        _crypt_sha256_finish_ctx
#define sha256_init_ctx          _crypt_sha256_init_ctx
#define sha256_process_bytes     _crypt_sha256_process_bytes
#define sha512_finish_ctx        _crypt_sha512_finish_ctx
#define sha512_init_ctx          _crypt_sha512_init_ctx
#define sha512_process_bytes     _crypt_sha512_process_bytes

#endif /* crypt-symbols.h */

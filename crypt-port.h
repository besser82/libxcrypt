/* Portability glue for libcrypt.

   Copyright 2007-2017 Thorsten Kukuk and Zack Weinberg

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see
   <https://www.gnu.org/licenses/>.  */

#ifndef _CRYPT_PORT_H
#define _CRYPT_PORT_H 1

#ifndef HAVE_CONFIG_H
#error "Run configure before compiling; see INSTALL for instructions"
#endif

#include "config.h"

#undef NDEBUG
#include <assert.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#ifndef HAVE_SYS_CDEFS_THROW
#define __THROW /* nothing */
#endif

/* Version of __GNUC_PREREQ with trailing underscores for BSD
   compatibility.  */
#ifndef __GNUC_PREREQ__
# define __GNUC_PREREQ__(ma, mi) __GNUC_PREREQ(ma, mi)
#endif

/* While actually compiling the library, suppress the __nonnull tags
   on the functions in crypt.h, so that internal checks for NULL are
   not deleted by the compiler.  */
#undef __nonnull
#define __nonnull(param) /* nothing */

/* Suppression of unused-argument warnings.  */
#if defined __GNUC__ && __GNUC__ >= 3
# define ARG_UNUSED(x) x __attribute__ ((__unused__))
#else
# define ARG_UNUSED(x) x
#endif

/* C99 Static array indices in function parameter declarations.  Syntax
   such as:  void bar(int myArray[static 10]);  is allowed in C99, but
   not all compiler support it properly.  Define MIN_SIZE appropriately
   so headers using it can be compiled using any compiler.
   Use like this:  void bar(int myArray[MIN_SIZE(10)]);  */
#if (defined(__clang__) || __GNUC_PREREQ__(4, 6)) && \
    (!defined(__STDC_VERSION__) || (__STDC_VERSION__ >= 199901))
#define MIN_SIZE(x) static (x)
#else
#define MIN_SIZE(x) (x)
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

/* max_align_t shim.  In the absence of official word from the
   compiler, we guess that one of long double, uintmax_t, void *, and
   void (*)(void) will have the maximum alignment.  This is probably
   not true in the presence of vector types, but we currently don't
   use vector types, and hopefully any compiler with extra-aligned
   vector types will provide max_align_t.  */
#ifndef HAVE_MAX_ALIGN_T
typedef union
{
  long double ld;
  uintmax_t ui;
  void *vp;
  void (*vpf)(void);
} max_align_t;
#endif

/* Several files expect the traditional definitions of these macros.  */
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

/* ARRAY_SIZE is used in tests.  */
#define ARRAY_SIZE(a_)  (sizeof (a_) / sizeof ((a_)[0]))

/* Provide a guaranteed way to erase sensitive memory at the best we
   can, given the possibilities of the system.  */
#if defined HAVE_MEMSET_S
/* Will never be optimized out.  */
#define XCRYPT_SECURE_MEMSET(s, len) \
  memset_s (s, len, 0x00, len)
#elif defined HAVE_EXPLICIT_BZERO
/* explicit_bzero() should give us enough guarantees.  */
#define XCRYPT_SECURE_MEMSET(s, len) \
  explicit_bzero(s, len)
#elif defined HAVE_EXPLICIT_MEMSET
/* Same guarantee goes for explicit_memset().  */
#define XCRYPT_SECURE_MEMSET(s, len) \
  explicit_memset (s, 0x00, len)
#else
/* The best hope we have in this case.  */
static inline void
_xcrypt_secure_memset (void *s, size_t len)
{
  volatile unsigned char *c = s;
  while (len--)
    *c++ = 0x00;
}
#define XCRYPT_SECURE_MEMSET(s, len) \
  _xcrypt_secure_memset (s, len)
#endif

/* Provide a safe way to copy strings with the guarantee src,
   including its terminating '\0', will fit d_size bytes.
   The trailing bytes of d_size will be filled with '\0'.
   dst and src must not be NULL.  Returns strlen (src).  */
static inline size_t
_xcrypt_strcpy_or_abort (void *dst, const size_t d_size,
                         const void *src)
{
  assert (dst != NULL);
  assert (src != NULL);
  const size_t s_size = strlen ((const char *) src);
  assert (d_size >= s_size + 1);
  memcpy (dst, src, s_size);
  XCRYPT_SECURE_MEMSET ((char *) dst + s_size, d_size - s_size);
  return s_size;
}
#define XCRYPT_STRCPY_OR_ABORT(dst, d_size, src) \
  _xcrypt_strcpy_or_abort (dst, d_size, src)

/* Per-symbol version tagging.  Currently we only know how to do this
   using GCC extensions.  */

#if defined __GNUC__ && __GNUC__ >= 3

/* Define ALIASNAME as a strong alias for NAME.  */
#define strong_alias(name, aliasname) _strong_alias(name, aliasname)
#define _strong_alias(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((alias (#name)))

/* Set the symbol version for EXTNAME, which uses INTNAME as its
   implementation.  */
#define symver_set(extstr, intname, version, mode) \
  __asm__ (".symver " #intname "," extstr mode #version)

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

#define symver_compat(n, extstr, extname, intname, version) \
  strong_alias (intname, extname ## __ ## n); \
  symver_set (extstr, extname ## __ ## n, version, "@")

#define symver_compat0(extstr, intname, version) \
  symver_set (extstr, intname, version, "@")

#define symver_default(extstr, intname, version) \
  symver_set (extstr, intname, version, "@@")

#else

/* When not building the shared library, don't do any of this.  */
#define symver_compat(n, extstr, extname, intname, version) symver_nop ()
#define symver_compat0(extstr, intname, version) symver_nop ()
#define symver_default(extstr, intname, version) symver_nop ()

#endif
#endif

/* Tests may need to _refer_ to compatibility symbols, but should never need
   to _define_ them.  */

#define symver_ref(extstr, intname, version) \
  symver_set(extstr, intname, version, "@")

/* Get the set of hash algorithms to be included and some related
   definitions.  */
#include "crypt-hashes.h"


/* Rename all of the internal-but-global symbols with a _crypt_ prefix
   so that they do not interfere with other people's code when linking
   statically.  This list cannot be autogenerated, but is validated by
   test-symbols.sh.  */

#define get_random_bytes         _crypt_get_random_bytes

#if INCLUDE_des || INCLUDE_des_xbsd || INCLUDE_des_big
#define des_crypt_block          _crypt_des_crypt_block
#define des_set_key              _crypt_des_set_key
#define des_set_salt             _crypt_des_set_salt
#define comp_maskl               _crypt_comp_maskl
#define comp_maskr               _crypt_comp_maskr
#define fp_maskl                 _crypt_fp_maskl
#define fp_maskr                 _crypt_fp_maskr
#define ip_maskl                 _crypt_ip_maskl
#define ip_maskr                 _crypt_ip_maskr
#define key_perm_maskl           _crypt_key_perm_maskl
#define key_perm_maskr           _crypt_key_perm_maskr
#define m_sbox                   _crypt_m_sbox
#define psbox                    _crypt_psbox
#endif

#if INCLUDE_nthash
#define MD4_Init   _crypt_MD4_Init
#define MD4_Update _crypt_MD4_Update
#define MD4_Final  _crypt_MD4_Final
#endif

#if INCLUDE_md5 || INCLUDE_sunmd5
#define MD5_Init   _crypt_MD5_Init
#define MD5_Update _crypt_MD5_Update
#define MD5_Final  _crypt_MD5_Final
#endif

#if INCLUDE_sha1
#define hmac_sha1_process_data   _crypt_hmac_sha1_process_data
#define sha1_finish_ctx          _crypt_sha1_finish_ctx
#define sha1_init_ctx            _crypt_sha1_init_ctx
#define sha1_process_bytes       _crypt_sha1_process_bytes
#endif

#if INCLUDE_sha512
#define libcperciva_SHA512_Init   _crypt_SHA512_Init
#define libcperciva_SHA512_Update _crypt_SHA512_Update
#define libcperciva_SHA512_Final  _crypt_SHA512_Final
#define libcperciva_SHA512_Buf    _crypt_SHA512_Buf
#endif

#if INCLUDE_md5 || INCLUDE_sha256 || INCLUDE_sha512
#define gensalt_sha_rn           _crypt_gensalt_sha_rn
#endif

#if INCLUDE_yescrypt
#define PBKDF2_SHA256            _crypt_PBKDF2_SHA256
#define yescrypt_encode_params_r _crypt_yescrypt_encode_params_r
#define yescrypt_free_local      _crypt_yescrypt_free_local
#define yescrypt_init_local      _crypt_yescrypt_init_local
#define yescrypt_kdf             _crypt_yescrypt_kdf
#define yescrypt_r               _crypt_yescrypt_r
#endif

#if INCLUDE_yescrypt || INCLUDE_scrypt
#define libcperciva_HMAC_SHA256_Init _crypt_HMAC_SHA256_Init
#define libcperciva_HMAC_SHA256_Update _crypt_HMAC_SHA256_Update
#define libcperciva_HMAC_SHA256_Final _crypt_HMAC_SHA256_Final
#define libcperciva_HMAC_SHA256_Buf _crypt_HMAC_SHA256_Buf
#endif

#if INCLUDE_sha256 || INCLUDE_scrypt || INCLUDE_yescrypt
#define libcperciva_SHA256_Init  _crypt_SHA256_Init
#define libcperciva_SHA256_Update _crypt_SHA256_Update
#define libcperciva_SHA256_Final _crypt_SHA256_Final
#define libcperciva_SHA256_Buf   _crypt_SHA256_Buf
#endif

#include "crypt.h"

#endif /* crypt-port.h */

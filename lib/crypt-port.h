/* Portability glue for libcrypt.

   Copyright 2007-2017 Thorsten Kukuk and Zack Weinberg
   Copyright 2018-2019 Björn Esser

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

#include "crypt-config.h"

#undef NDEBUG
#include <assert.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifndef HAVE_SYS_CDEFS_THROW
#define __THROW /* nothing */
#endif

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
#if (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L) && \
    ((defined __GNUC__ && __GNUC__ > 4) || defined __clang__)
#define MIN_SIZE(x) static (x)
#else
#define MIN_SIZE(x) (x)
#endif

/* Detect system endianness.  */
#if ENDIANNESS_IS_BIG
# define XCRYPT_USE_BIGENDIAN 1
#elif ENDIANNESS_IS_LITTLE
# define XCRYPT_USE_BIGENDIAN 0
#elif ENDIANNESS_IS_PDP
# error "Byte-order sensitive code in libxcrypt does not support PDP-endianness"
#else
# error "Unable to determine byte ordering"
#endif

/* Provide the endianness macros expected by the GOST R 34.11-2012
   "Streebog" hash function implementation, so we can use that file
   unmodified.  */
#if XCRYPT_USE_BIGENDIAN
#define __GOST3411_BIG_ENDIAN__ 1
#else
#define __GOST3411_LITTLE_ENDIAN__ 1
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

/* Several files expect the traditional definitions of these macros.
   (We don't trust sys/param.h to define them correctly.)  */

#undef MIN
#define MIN(a_, b_) (((a_) < (b_)) ? (a_) : (b_))

#undef MAX
#define MAX(a_, b_) (((a_) > (b_)) ? (a_) : (b_))

#undef ARRAY_SIZE
#define ARRAY_SIZE(a_)  (sizeof (a_) / sizeof ((a_)[0]))

#endif /* crypt-port.h */

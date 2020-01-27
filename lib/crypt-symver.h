/* ELF symbol versioning for libcrypt.

   Copyright 2007-2020 Thorsten Kukuk, Zack Weinberg, Björn Esser

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

#ifndef _CRYPT_SYMVER_H
#define _CRYPT_SYMVER_H 1

/* Currently we only know how to do this using GCC extensions.  */
#if defined __GNUC__ && __GNUC__ >= 3

/* Define ALIASNAME as a strong alias for NAME.  */
#define strong_alias(name, aliasname) _strong_alias(name, aliasname)

/* Darwin doesn't support alias attributes.  */
#ifdef __cplusplus
# ifndef __APPLE__
#  define _strong_alias(name, aliasname) \
     extern __typeof (name) aliasname __THROW __attribute__ ((alias (#name)))
# else
#  define _strong_alias(name, aliasname) \
     __THROW __asm__(".globl _" #aliasname); \
     __THROW __asm__(".set _" #aliasname ", _" #name); \
     extern __typeof(name) aliasname __THROW
# endif
#else
# ifndef __APPLE__
#  define _strong_alias(name, aliasname) \
     extern __typeof (name) aliasname __attribute__ ((alias (#name))) __THROW
# else
#  define _strong_alias(name, aliasname) \
     __asm__(".globl _" #aliasname) __THROW; \
     __asm__(".set _" #aliasname ", _" #name) __THROW; \
     extern __typeof(name) aliasname __THROW
# endif
#endif

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


#endif

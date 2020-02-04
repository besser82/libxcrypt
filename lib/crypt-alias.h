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

#ifndef _CRYPT_ALIAS_H
#define _CRYPT_ALIAS_H 1

/* Currently we only know how to do this using GCC extensions.  */
#if defined __GNUC__ && __GNUC__ >= 3

/* Define ALIASNAME as a strong alias for NAME.
   In libcrypt, NAME is always a function marked __THROW,
   so ALIASNAME will be declared with __THROW as well.  */
# define strong_alias(name, aliasname) _strong_alias(name, aliasname)

# ifdef __APPLE__

/* Darwin compilers don't support __attribute__((alias)).  */
#  define _strong_alias(name, aliasname)        \
  __asm__(".globl _" #aliasname);               \
  __asm__(".set _" #aliasname ", _" #name);     \
  extern __typeof(name) aliasname __THROW

# else

#  define _strong_alias(name, aliasname)        \
  extern __typeof (name) aliasname __THROW __attribute__ ((alias (#name)))

# endif

#else /* not GCC */

# error "Don't know how to do symbol aliasing with this compiler"

#endif

#endif /* crypt-alias.h */

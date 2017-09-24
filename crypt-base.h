/*
 * Copyright (C) 1991-2017 Free Software Foundation, Inc.
 *
 * The GNU C Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * The GNU C Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the GNU C Library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA.
 */

#ifndef _CRYPT_H
#define _CRYPT_H 1

/*HEADER*/

/* The strings returned by crypt, crypt_r, crypt_rn, and crypt_ra will
   be no longer than this.  This is NOT the appropriate size to use in
   allocating the buffer supplied to crypt_rn -- see below.  */
#define CRYPT_OUTPUT_SIZE (7 + 22 + 31 + 1)

/* The strings returned by crypt_gensalt, crypt_gensalt_rn, and
   crypt_gensalt_ra will be no longer than this.  This IS the
   appropriate size to use when allocating the buffer supplied to
   crypt_gensalt_rn.  */
#define CRYPT_GENSALT_OUTPUT_SIZE       (7 + 22 + 1)

/* One-way hash the passphrase PHRASE as specified by SETTING, and
   return a string suitable for storage in a Unix-style "passwd" file.

   If SETTING is a previously hashed passphrase, the string returned
   will be equal to SETTING if and only if PHRASE is the same as the
   passphrase that was previously hashed.  See the documentation for
   other ways to use this function.

   The string returned by this function is stored in a statically-
   allocated buffer, and will be overwritten if the function is called
   again.  It is not safe to call this function from multiple threads
   concurrently.

   If an error occurs (such as SETTING being nonsense or unsupported)
   the string returned will begin with '*', and will not be equal to
   SETTING nor to any valid hashed passphrase.  Otherwise, the string
   will not begin with '*'.  */
extern char *crypt (const char *__phrase, const char *__setting)
  __THROW __nonnull ((1, 2));

/* Memory area used by crypt_r.

   Older versions of this library expected applications to set the
   'initialized' field of this structure to 0 before calling crypt_r
   for the first time; this is no longer necessary, but the field is
   preserved for compatibility's sake.  */
struct crypt_data
{
  char opaque[16 * 8 + 32768 * 4 + 14 + 2 + sizeof(long int) + sizeof(int)];
  int initialized;
};

/* Thread-safe version of crypt.  Instead of writing to a static
   storage area, the string returned by this function will be
   somewhere within the crypt_data object supplied as an argument.
   Otherwise, behaves exactly the same as crypt.  */
extern char *crypt_r (const char *__phrase, const char *__setting,
                      struct crypt_data *restrict __data)
  __THROW __nonnull ((1, 2, 3));

/* Another thread-safe version of crypt.  Instead of writing to a
   static storage area, the string returned by this function will be
   somewhere within the space provided at DATA, which is of length SIZE
   bytes.  SIZE must be at least sizeof (struct crypt_data).

   Also, if an error occurs, this function returns a null pointer,
   not a special string.  (However, the string returned on success
   still will never begin with '*'.)  */
extern char *crypt_rn (const char *__phrase, const char *__setting,
                       void *__data, int __size)
  __THROW __nonnull ((1, 2, 3));

/* Yet a third thread-safe version of crypt; this one works like
   getline(3).  *DATA must be either NULL or a pointer to memory
   allocated by malloc, and *SIZE must be the size of the allocation.
   This space will be allocated or reallocated as necessary and the
   values updated.  The string returned by this function will be
   somewhere within the space at *DATA.  It is safe to deallocate
   this space with free when it is no longer needed.

   Like crypt_rn, this function returns a null pointer on failure, not
   a special string.  */
extern char *crypt_ra (const char *__phrase, const char *__setting,
                       void **__data, int *__size)
  __THROW __nonnull ((1, 2, 3, 4));


/* Generate a string suitable for use as the setting when hashing a
   new passphrase.  PREFIX controls which hash function will be used,
   COUNT controls the computational cost of the hash (for functions
   where this is tunable), and INPUT should point to SIZE bytes of
   random data.

   The string returned is stored in a statically-allocated buffer,
   and will be overwritten if the function is called again.  It is not
   safe to call this function from multiple threads concurrently.
   However, it is safe to pass the string to crypt without copying it
   first; the two functions use separate buffers.

   If an error occurs (e.g. a prefix that does not correspond to a
   supported hash function, or an inadequate amount of random data),
   this function returns a null pointer.  */
extern char *crypt_gensalt (const char *__prefix, unsigned long __count,
                            const char *__input, int __size)
  __THROW __nonnull ((1, 3));

/* Thread-safe version of crypt_gensalt; instead of a
   statically-allocated buffer, the generated setting string is
   written to OUTPUT, which is OUTPUT_SIZE bytes long.  OUTPUT_SIZE
   must be at least CRYPT_GENSALT_OUTPUT_SIZE (see above).  */
extern char *crypt_gensalt_rn (const char *__prefix, unsigned long __count,
                               const char *__input, int __size,
                               char *__output, int __output_size)
  __THROW __nonnull ((1, 5));

/* Another thread-safe version of crypt_gensalt; the string returned
   is in storage allocated by malloc, and should be deallocated with
   free when it is no longer needed.  */
extern char *crypt_gensalt_ra (const char *__prefix, unsigned long __count,
                               const char *__input, int __size)
  __THROW __nonnull ((1));

/*TRAILER*/

#endif /* crypt.h */

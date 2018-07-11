/* High-level libcrypt interfaces.

   Copyright (C) 1991-2017 Free Software Foundation, Inc.

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

#ifndef _CRYPT_H
#define _CRYPT_H 1

/*HEADER*/

/* The strings returned by crypt, crypt_r, crypt_rn, and crypt_ra will
   be no longer than this, counting the terminating NUL.  (Existing
   algorithms all produce much shorter strings, but we have reserved
   generous space for future expansion.)  This is NOT the appropriate
   size to use in allocating the buffer supplied to crypt_rn; use
   sizeof (struct crypt_data) instead.  */
#define CRYPT_OUTPUT_SIZE 384

/* Passphrases longer than this (counting the terminating NUL) are not
   supported.  Note that some hash algorithms have lower limits.  */
#define CRYPT_MAX_PASSPHRASE_SIZE 512

/* The strings returned by crypt_gensalt, crypt_gensalt_rn, and
   crypt_gensalt_ra will be no longer than this.  This IS the
   appropriate size to use when allocating the buffer supplied to
   crypt_gensalt_rn.  (Again, existing algorithms all produce
   much shorter strings, but we have reserved generous space for
   future expansion.)  */
#define CRYPT_GENSALT_OUTPUT_SIZE 192

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

/* These sizes are chosen to make sizeof (struct crypt_data) add up to
   exactly 32768 bytes.  */
#define CRYPT_DATA_RESERVED_SIZE 767
#define CRYPT_DATA_INTERNAL_SIZE 30720

/* Memory area used by crypt_r.  */
struct crypt_data
{
  /* crypt_r writes the hashed password to this field of its 'data'
     argument.  crypt_rn and crypt_ra do the same, treating the
     untyped data area they are supplied with as this struct.  */
  char output[CRYPT_OUTPUT_SIZE];

  /* Applications are encouraged, but not required, to use this field
     to store the "setting" string that must be passed to crypt_*.
     Future extensions to the API may make this more ergonomic.

     A valid "setting" is either previously hashed password or the
     string produced by one of the crypt_gensalt functions; see the
     crypt_gensalt documentation for further details.  */
  char setting[CRYPT_OUTPUT_SIZE];

  /* Applications are encouraged, but not required, to use this field
     to store the unhashed passphrase they will pass to crypt_*.
     Future extensions to the API may make this more ergonomic.  */
  char input[CRYPT_MAX_PASSPHRASE_SIZE];

  /* Reserved for future application-visible fields.  For maximum
     forward compatibility, applications should set this field to all
     bytes zero before calling crypt_r, crypt_rn, or crypt_ra for the
     first time with a just-allocated 'struct crypt_data'.  Future
     extensions to the API may make this more ergonomic.  */
  char reserved[CRYPT_DATA_RESERVED_SIZE];

  /* This field should be set to 0 before calling crypt_r, crypt_rn,
     or crypt_ra for the first time with a just-allocated
     'struct crypt_data'.  This is not required if crypt_ra is allowed
     to do the allocation itself (i.e. if the *DATA argument is a null
     pointer).  Future extensions to the API may make this more ergonomic.  */
  char initialized;

  /* Scratch space used internally.  Applications should not read or
     write this field.  All data written to this area is erased before
     returning from the library.  */
  char internal[CRYPT_DATA_INTERNAL_SIZE];
};

/* Thread-safe version of crypt.  Instead of writing to a static
   storage area, the string returned by this function will be within
   DATA->output.  Otherwise, behaves exactly the same as crypt.  */
extern char *crypt_r (const char *__phrase, const char *__setting,
                      struct crypt_data *__restrict __data)
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
   getline(3).  *DATA must be either 0 or a pointer to memory
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
   where this is tunable), and RBYTES should point to NRBYTES bytes of
   random data.  If PREFIX is a null pointer, the current best default
   is used; if RBYTES is a null pointer, random data will be retrieved
   from the operating system if possible.  (Caution: setting PREFIX to
   an *empty string* selects the use of the oldest and least secure
   hash in the library.  Don't do that.)

   The string returned is stored in a statically-allocated buffer, and
   will be overwritten if the function is called again.  It is not
   safe to call this function from multiple threads concurrently.
   However, within a single thread, it is safe to pass the string as
   the SETTING argument to crypt without copying it first; the two
   functions use separate buffers.

   If an error occurs (e.g. a prefix that does not correspond to a
   supported hash function, or an inadequate amount of random data),
   this function returns a null pointer.  */
extern char *crypt_gensalt (const char *__prefix, unsigned long __count,
                            const char *__rbytes, int __nrbytes)
__THROW;

/* Thread-safe version of crypt_gensalt; instead of a
   statically-allocated buffer, the generated setting string is
   written to OUTPUT, which is OUTPUT_SIZE bytes long.  OUTPUT_SIZE
   must be at least CRYPT_GENSALT_OUTPUT_SIZE (see above).

   If an error occurs, this function returns a null pointer and writes
   a string that does not correspond to any valid setting into OUTPUT.  */
extern char *crypt_gensalt_rn (const char *__prefix, unsigned long __count,
                               const char *__rbytes, int __nrbytes,
                               char *__output, int __output_size)
__THROW __nonnull ((5));

/* Another thread-safe version of crypt_gensalt; the generated setting
   string is in storage allocated by malloc, and should be deallocated
   with free when it is no longer needed.  */
extern char *crypt_gensalt_ra (const char *__prefix, unsigned long __count,
                               const char *__rbytes, int __nrbytes)
__THROW;

/* These macros could be checked by portable users of crypt_gensalt*
   functions to find out whether null pointers could be specified
   as PREFIX and RBYTES arguments.  */
#define CRYPT_GENSALT_IMPLEMENTS_DEFAULT_PREFIX 1
#define CRYPT_GENSALT_IMPLEMENTS_AUTO_ENTROPY 1

/*TRAILER*/

#endif /* crypt.h */

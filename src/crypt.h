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

#include <sys/types.h>

#ifndef __THROW
#define __THROW /* nothing */
#endif

#ifndef __nonnull
#define __nonnull(param) /* nothing */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPT_OUTPUT_SIZE               (7 + 22 + 31 + 1)
#define CRYPT_GENSALT_OUTPUT_SIZE       (7 + 22 + 1)

/* Encrypt at most 8 characters from KEY using salt to perturb DES.  */
extern char *crypt (const char *__key, const char *__salt)
  __THROW __nonnull ((1, 2));

/* Reentrant versions of the functions above.  The additional argument
   points to a structure where the results are placed in.  */
struct crypt_data
{
  char keysched[16 * 8];
  char sb0[32768];
  char sb1[32768];
  char sb2[32768];
  char sb3[32768];
  /* end-of-aligment-critical-data */
  char crypt_3_buf[14];
  char current_salt[2];
  long int current_saltbits;
  int direction, initialized;
};

extern char *crypt_r (const char *__key, const char *__salt,
                      struct crypt_data *__restrict __data)
  __THROW __nonnull ((1, 2, 3));

extern char *crypt_rn (const char *__key, const char *__salt,
                       void *__data, int __size)
  __THROW __nonnull ((1, 2, 3));

extern char *crypt_ra (const char *__key, const char *__salt,
                       void **__data, int *__size)
  __THROW __nonnull ((1, 2, 3, 4));

extern char *crypt_gensalt (const char *__prefix, unsigned long __count,
                            const char *__input, int __size)
  __THROW __nonnull ((1, 3));

extern char *crypt_gensalt_r (const char *__prefix, unsigned long __count,
                              const char *__input, int __size,
                              char *__output, int __output_size)
  __THROW __nonnull ((1, 5));

extern char *crypt_gensalt_rn (const char *__prefix, unsigned long __count,
                               const char *__input, int __size,
                               char *__output, int __output_size)
  __THROW __nonnull ((1, 5));

extern char *crypt_gensalt_ra (const char *__prefix, unsigned long __count,
                               const char *__input, int __size)
  __THROW __nonnull ((1));


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* crypt.h */

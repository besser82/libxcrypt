/*
 * Copyright (C) 1991, 92, 93, 96, 97, 98, 2000, 2002, 2007 Free Software Foundation, Inc.
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

#ifndef _XCRYPT_H
#define _XCRYPT_H	1

#include <features.h>

__BEGIN_DECLS

#define CRYPT_OUTPUT_SIZE               (7 + 22 + 31 + 1)
#define CRYPT_GENSALT_OUTPUT_SIZE       (7 + 22 + 1)

/* Encrypt at most 8 characters from KEY using salt to perturb DES.  */
extern char *xcrypt (__const char *__key, __const char *__salt)
  __THROW __nonnull ((1,2));
#define crypt xcrypt

/* Setup DES tables according KEY.  */
extern void setkey (__const char *__key) __THROW __nonnull ((1));

/* Encrypt data in BLOCK in place if EDFLAG is zero; otherwise decrypt
   block in place.  */
extern void encrypt (char *__block, int __edflag) __THROW __nonnull ((1));

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
    int  direction, initialized;
};

extern char *xcrypt_r (__const char *__key, __const char *__salt,
		       struct crypt_data * __restrict __data)
  __THROW __nonnull ((1,2,3));
#define crypt_r xcrypt_r


extern void setkey_r (__const char *__key,
		      struct crypt_data * __restrict __data)
  __THROW __nonnull ((1,2));

extern void encrypt_r (char *__block, int __edflag,
		       struct crypt_data * __restrict __data)
  __THROW __nonnull ((1,3));

extern char *xcrypt_gensalt (__const char *prefix, unsigned long count,
			     __const char *input, int size)
  __THROW __nonnull ((1,3));
#define crypt_gensalt xcrypt_gensalt

extern char *xcrypt_gensalt_r (__const char *prefix, unsigned long count,
			       __const char *input, int size, char *output,
			       int output_size) __THROW __nonnull ((1,5));
#define crypt_gensalt_r xcrypt_gensalt_r

extern char *bigcrypt (__const char *key, __const char *salt)
  __THROW __nonnull ((1,2));

__END_DECLS

#endif	/* xcrypt.h */

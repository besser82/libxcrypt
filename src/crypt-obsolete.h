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

#ifndef _CRYPT_OBSOLETE_H
#define _CRYPT_OBSOLETE_H 1

#include "crypt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* These functions are obsolete and should never be used, but we have to
   keep providing them for binary backward compatibility.  */

/* Setup DES tables according KEY.  */
extern void setkey (const char *__key)
  __THROW __nonnull ((1));

/* Encrypt data in BLOCK in place if EDFLAG is zero; otherwise decrypt
   block in place.  */
extern void encrypt (char *__block, int __edflag)
  __THROW __nonnull ((1));

extern void setkey_r (const char *__key,
                      struct crypt_data *__restrict __data)
  __THROW __nonnull ((1, 2));

extern void encrypt_r (char *__block, int __edflag,
                       struct crypt_data *__restrict __data)
  __THROW __nonnull ((1, 3));

extern char *bigcrypt (const char *key, const char *salt)
  __THROW __nonnull ((1, 2));

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* crypt-obsolete.h */

/*
 * UFC-crypt: ultra fast crypt(3) implementation
 *
 * Copyright (C) 1991, 92, 93, 96, 97, 98 Free Software Foundation, Inc.
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
 *
 * @(#)crypt-private.h  1.4 12/20/96
 */

/* Prototypes for local functions in libcrypt.a.  */

#ifndef CRYPT_PRIVATE_H
#define CRYPT_PRIVATE_H 1

#include <stdint.h>

struct crypt_data;

#if UINT_FAST32_MAX == UINT_FAST64_MAX
#define UFC_USE_64BIT 1
#else
#define UFC_USE_64BIT 0
#endif

/* crypt.c */
extern void _ufc_doit_r (uint_fast32_t itr,
                         struct crypt_data *restrict __data,
                         uint_fast32_t * res);

/* crypt_util.c */
extern void __init_des_r (struct crypt_data *restrict __data);
extern void __init_des (void);

extern void _ufc_setup_salt_r (const char *s,
                               struct crypt_data *restrict __data);
extern void _ufc_mk_keytab_r (const char *key,
                              struct crypt_data *restrict __data);
extern void _ufc_dofinalperm_r (uint_fast32_t * res,
                                struct crypt_data *restrict __data);
extern void _ufc_output_conversion_r (uint_fast32_t v1, uint_fast32_t v2,
                                      const char *salt,
                                      struct crypt_data *restrict __data);

extern void __setkey_r (const char *__key,
                        struct crypt_data *restrict __data);
extern void __encrypt_r (char *restrict __block, int __edflag,
                         struct crypt_data *restrict __data);

#endif /* crypt-private.h */

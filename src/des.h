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

/* Prototypes for internal-UFC routines and data.  */

#ifndef CRYPT_PRIVATE_H
#define CRYPT_PRIVATE_H 1

#include <stdint.h>

struct crypt_data;

#if UINT_FAST32_MAX == UINT_FAST64_MAX
#define UFC_USE_64BIT 1
#else
#define UFC_USE_64BIT 0
#endif

/* des.c */
extern void _ufc_doit_r (uint_fast32_t itr,
                         struct crypt_data *restrict __data,
                         uint_fast32_t * res);
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

/* des-tables.c */
extern const int pc1[56];
extern const int rots[16];
extern const int pc2[48];
extern const int esel[48];
extern const int perm32[32];
extern const int sbox[8][4][16];
extern const int initial_perm[64];
extern const int final_perm[64];
extern const uint_fast32_t bitmask[24];
extern const unsigned char bytemask[8];
extern const uint_fast32_t longmask[32];

/* des-tables2.c */
extern const uint_fast32_t do_pc1[8][2][128];
extern const uint_fast32_t do_pc2[8][128];
extern const uint_fast32_t eperm32tab[4][256][2];
extern const uint_fast32_t efp[16][64][2];

/* des-obsolete.c */
extern void __setkey_r (const char *__key,
                        struct crypt_data *restrict __data);
extern void __encrypt_r (char *restrict __block, int __edflag,
                         struct crypt_data *restrict __data);

#endif /* des.h */

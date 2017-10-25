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

#ifndef _CRYPT_PRIVATE_H
#define _CRYPT_PRIVATE_H 1

#include "crypt-base.h"

/* Utility functions */

bool get_random_bytes (void *buf, size_t buflen);

extern void gensalt_sha_rn (char tag, size_t maxsalt, unsigned long defcount,
                            unsigned long mincount, unsigned long maxcount,
                            unsigned long count,
                            const uint8_t *rbytes, size_t nrbytes,
                            uint8_t *output, size_t output_size);

/* The "scratch" area passed to each of the individual hash functions is
   this big.  */
#define ALG_SPECIFIC_SIZE 8192

/* Individual hash functions */

#if ENABLE_WEAK_HASHES
extern void crypt_des_trd_or_big_rn (const char *phrase, const char *setting,
                                     uint8_t *output, size_t o_size,
                                     void *scratch, size_t s_size);
extern void crypt_des_xbsd_rn (const char *phrase, const char *setting,
                               uint8_t *output, size_t o_size,
                               void *scratch, size_t s_size);
extern void crypt_md5_rn (const char *phrase, const char *setting,
                          uint8_t *output, size_t o_size,
                          void *scratch, size_t s_size);
extern void crypt_nthash_rn (const char *phrase, const char *setting,
                             uint8_t *output, size_t o_size,
                             void *scratch, size_t s_size);
extern void crypt_sha1_rn (const char *phrase, const char *setting,
                           uint8_t *output, size_t o_size,
                           void *scratch, size_t s_size);
extern void crypt_sunmd5_rn (const char *phrase, const char *setting,
                             uint8_t *output, size_t o_size,
                             void *scratch, size_t s_size);
#endif

extern void crypt_sha256_rn (const char *phrase, const char *setting,
                             uint8_t *output, size_t o_size,
                             void *scratch, size_t s_size);
extern void crypt_sha512_rn (const char *phrase, const char *setting,
                             uint8_t *output, size_t o_size,
                             void *scratch, size_t s_size);
extern void crypt_bcrypt_rn (const char *phrase, const char *setting,
                             uint8_t *output, size_t o_size,
                             void *scratch, size_t s_size);

#if ENABLE_WEAK_HASHES
extern void gensalt_des_trd_rn (unsigned long count,
                                const uint8_t *rbytes, size_t nrbytes,
                                uint8_t *output, size_t o_size);
extern void gensalt_des_xbsd_rn (unsigned long count,
                                 const uint8_t *rbytes, size_t nrbytes,
                                 uint8_t *output, size_t o_size);
extern void gensalt_md5_rn (unsigned long count,
                            const uint8_t *rbytes, size_t nrbytes,
                            uint8_t *output, size_t o_size);
extern void gensalt_nthash_rn (unsigned long count,
                               const uint8_t *rbytes, size_t nrbytes,
                               uint8_t *output, size_t o_size);
extern void gensalt_sha1_rn (unsigned long count,
                             const uint8_t *rbytes, size_t nrbytes,
                             uint8_t *output, size_t o_size);
extern void gensalt_sunmd5_rn (unsigned long count,
                               const uint8_t *rbytes, size_t nrbytes,
                               uint8_t *output, size_t o_size);
#endif

extern void gensalt_sha256_rn (unsigned long count,
                               const uint8_t *rbytes, size_t nrbytes,
                               uint8_t *output, size_t o_size);
extern void gensalt_sha512_rn (unsigned long count,
                               const uint8_t *rbytes, size_t nrbytes,
                               uint8_t *output, size_t o_size);

extern void gensalt_bcrypt_a_rn (unsigned long count,
                                 const uint8_t *rbytes, size_t nrbytes,
                                 uint8_t *output, size_t o_size);
extern void gensalt_bcrypt_b_rn (unsigned long count,
                                 const uint8_t *rbytes, size_t nrbytes,
                                 uint8_t *output, size_t o_size);
extern void gensalt_bcrypt_x_rn (unsigned long count,
                                 const uint8_t *rbytes, size_t nrbytes,
                                 uint8_t *output, size_t o_size);
extern void gensalt_bcrypt_y_rn (unsigned long count,
                                 const uint8_t *rbytes, size_t nrbytes,
                                 uint8_t *output, size_t o_size);

#endif /* crypt-private.h */

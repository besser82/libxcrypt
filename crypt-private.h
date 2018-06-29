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

#define CRYPT_RN_PROTOTYPE(name) \
        void crypt_ ## name ## _rn (const char *phrase, const char *setting, \
                                    uint8_t *output, size_t o_size, \
                                    void *scratch, size_t s_size)

#define GENSALT_RN_PROTOTYPE(name) \
        void gensalt_ ## name ## _rn (unsigned long count,\
                                      const uint8_t *rbytes, size_t nrbytes, \
                                      uint8_t *output, size_t o_size)

#if ENABLE_WEAK_HASHES
CRYPT_RN_PROTOTYPE(des_trd_or_big);
CRYPT_RN_PROTOTYPE(md5);
#if ENABLE_WEAK_NON_GLIBC_HASHES
CRYPT_RN_PROTOTYPE(des_xbsd);
CRYPT_RN_PROTOTYPE(nthash);
CRYPT_RN_PROTOTYPE(sha1);
CRYPT_RN_PROTOTYPE(sunmd5);
#endif
#endif

CRYPT_RN_PROTOTYPE(sha256);
CRYPT_RN_PROTOTYPE(sha512);
CRYPT_RN_PROTOTYPE(bcrypt);

#if ENABLE_WEAK_HASHES
GENSALT_RN_PROTOTYPE(des_trd);
GENSALT_RN_PROTOTYPE(md5);
#if ENABLE_WEAK_NON_GLIBC_HASHES
GENSALT_RN_PROTOTYPE(des_xbsd);
GENSALT_RN_PROTOTYPE(nthash);
GENSALT_RN_PROTOTYPE(sha1);
GENSALT_RN_PROTOTYPE(sunmd5);
#endif
#endif

GENSALT_RN_PROTOTYPE(sha256);
GENSALT_RN_PROTOTYPE(sha512);

GENSALT_RN_PROTOTYPE(bcrypt_a);
GENSALT_RN_PROTOTYPE(bcrypt_b);
GENSALT_RN_PROTOTYPE(bcrypt_x);
GENSALT_RN_PROTOTYPE(bcrypt_y);

#endif /* crypt-private.h */

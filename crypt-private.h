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

#include <stddef.h>

/* Miscellaneous utilities */

extern void make_failure_token (const char *salt, char *output, int size);

/* Individual hash functions */

#if ENABLE_WEAK_HASHES
extern char *crypt_des_trd_or_big_rn (const char *key, const char *salt,
                                      char *data, size_t size);
extern char *crypt_des_xbsd_rn (const char *key, const char *salt,
                                char *data, size_t size);
extern char *crypt_md5_rn (const char *key, const char *salt,
                           char *data, size_t size);
#endif

extern char *crypt_sha256_rn (const char *key, const char *salt,
                              char *data, size_t size);
extern char *crypt_sha512_rn (const char *key, const char *salt,
                              char *data, size_t size);
extern char *crypt_bcrypt_rn (const char *key, const char *salt,
                              char *data, size_t size);

#if ENABLE_WEAK_HASHES
extern char *gensalt_des_trd_rn (unsigned long count,
                                 const char *input, int size,
                                 char *output, int output_size);
extern char *gensalt_des_xbsd_rn (unsigned long count,
                                  const char *input, int size,
                                  char *output, int output_size);
extern char *gensalt_md5_rn (unsigned long count, const char *input,
                             int size, char *output, int output_size);
#endif

extern char *gensalt_sha256_rn (unsigned long count,
                                const char *input,
                                int size, char *output,
                                int output_size);
extern char *gensalt_sha512_rn (unsigned long count,
                                const char *input,
                                int size, char *output,
                                int output_size);

extern char *gensalt_bcrypt_a_rn (unsigned long count,
                                  const char *input, int size,
                                  char *output, int output_size);
extern char *gensalt_bcrypt_b_rn (unsigned long count,
                                  const char *input, int size,
                                  char *output, int output_size);
extern char *gensalt_bcrypt_x_rn (unsigned long count,
                                  const char *input, int size,
                                  char *output, int output_size);
extern char *gensalt_bcrypt_y_rn (unsigned long count,
                                  const char *input, int size,
                                  char *output, int output_size);

#endif /* crypt-private.h */

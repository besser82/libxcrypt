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

#ifndef _XCRYPT_PRIVATE_H
#define _XCRYPT_PRIVATE_H       1

#include "crypt.h"

/* Individual hash functions */

extern char *_xcrypt_crypt_trd_or_big_rn (const char *key, const char *salt,
                                          char *data, size_t size);
extern char *_xcrypt_crypt_extended_rn (const char *key, const char *salt,
                                        char *data, size_t size);
extern char *_xcrypt_crypt_bigcrypt_rn (const char *key, const char *salt,
                                        char *data, size_t size);

extern char *_xcrypt_crypt_md5_rn (const char *key, const char *salt,
                                   char *data, size_t size);
extern char *_xcrypt_crypt_sha256_rn (const char *key, const char *salt,
                                      char *data, size_t size);
extern char *_xcrypt_crypt_sha512_rn (const char *key, const char *salt,
                                      char *data, size_t size);
extern char *_xcrypt_crypt_bcrypt_rn (const char *key, const char *salt,
                                      char *data, size_t size);

extern char *_xcrypt_gensalt_traditional_rn (unsigned long count,
                                             const char *input, int size,
                                             char *output, int output_size);
extern char *_xcrypt_gensalt_extended_rn (unsigned long count,
                                          const char *input, int size,
                                          char *output, int output_size);
extern char *_xcrypt_gensalt_md5_rn (unsigned long count, const char *input,
                                     int size, char *output, int output_size);
extern char *_xcrypt_gensalt_sha256_rn (unsigned long count,
                                        const char *input,
                                        int size, char *output,
                                        int output_size);
extern char *_xcrypt_gensalt_sha512_rn (unsigned long count,
                                        const char *input,
                                        int size, char *output,
                                        int output_size);

extern char *_xcrypt_gensalt_bcrypt_a_rn (unsigned long count,
                                          const char *input, int size,
                                          char *output, int output_size);
extern char *_xcrypt_gensalt_bcrypt_b_rn (unsigned long count,
                                          const char *input, int size,
                                          char *output, int output_size);
extern char *_xcrypt_gensalt_bcrypt_x_rn (unsigned long count,
                                          const char *input, int size,
                                          char *output, int output_size);
extern char *_xcrypt_gensalt_bcrypt_y_rn (unsigned long count,
                                          const char *input, int size,
                                          char *output, int output_size);

#endif

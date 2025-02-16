/* Copyright (c) 2025 Björn Esser <besser82 at fedoraproject.org>
 * All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * --
 * alg-blake2b.h
 * BLAKE2b Hashing Context and API Prototypes
 */

#ifndef ALG_BLAKE2B_H
#define ALG_BLAKE2B_H

#include <stdint.h>
#include <stddef.h>

/* state context */
typedef struct
{
  uint8_t b[128];  /* input buffer */
  uint64_t h[8];   /* chained state */
  uint64_t t[2];   /* total number of bytes */
  size_t c;        /* pointer for b[] */
  size_t outlen;   /* digest size */
} blake2b_ctx;

/* Initialize the hashing context "ctx" with optional key "key".
   1 <= outlen <= 64 gives the digest size in bytes.
   Secret key (also <= 64 bytes) is optional (keylen = 0). */
extern int blake2b_init(blake2b_ctx *ctx, size_t outlen,
                        const void *key, size_t keylen);  /* secret key */

/* Add "inlen" bytes from "in" into the hash. */
extern int blake2b_update(blake2b_ctx *ctx,               /* context */
                          const void *in, size_t inlen);  /* data to be hashed */

/* Generate the message digest (size given in init).
   Result placed in "out". */
extern int blake2b_final(blake2b_ctx *ctx, void *out);

/* All-in-one convenience function. */
extern int blake2b(void *out, size_t outlen,        /* return buffer for digest */
                   const void *key, size_t keylen,  /* optional secret key */
                   const void *in, size_t inlen);   /* data to be hashed */

/* Interface for Argon2. */
extern int blake2b_long(void *out, size_t outlen,
                        const void *in, size_t inlen);

#endif /* alg-blake2b.h */

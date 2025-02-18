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
 * alg-argon2-blamka.h *
 * BLAKE2b extension for Argon2
 */

#ifndef ALG_ARGON2_BLAMKA_H
#define ALG_ARGON2_BLAMKA_H

#define ROTR64(x, y)  (((x) >> (y)) ^ ((x) << (64 - (y))))

#define FBLAMKA(x,y) x + y + 2 * (x & 0xFFFFFFFF) * (y & 0xFFFFFFFF);

#define G(a, b, c, d)       \
do                          \
  {                         \
    a = FBLAMKA(a, b);      \
    d = ROTR64(d ^ a, 32);  \
    c = FBLAMKA(c, d);      \
    b = ROTR64(b ^ c, 24);  \
    a = FBLAMKA(a, b);      \
    d = ROTR64(d ^ a, 16);  \
    c = FBLAMKA(c, d);      \
    b = ROTR64(b ^ c, 63);  \
  }                         \
while ((void)0, 0)

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5,    \
                           v6, v7, v8, v9, v10, v11,  \
                           v12, v13, v14, v15)        \
do                                                    \
  {                                                   \
    G(v0, v4, v8, v12);                               \
    G(v1, v5, v9, v13);                               \
    G(v2, v6, v10, v14);                              \
    G(v3, v7, v11, v15);                              \
    G(v0, v5, v10, v15);                              \
    G(v1, v6, v11, v12);                              \
    G(v2, v7, v8, v13);                               \
    G(v3, v4, v9, v14);                               \
  }                                                   \
while ((void)0, 0)

#endif /* alg-argon2-blamka.h */

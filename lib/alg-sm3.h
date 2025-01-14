/*
 * Copyright (C) 2024 Tianjia Zhang
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of other contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SM3_H_
#define _SM3_H_

#include "crypt-port.h"

#include <stddef.h>
#include <stdint.h>

#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE  64

/* Context structure for SM3 operations */
typedef struct {
    uint32_t state[SM3_DIGEST_SIZE / 4];
    uint64_t count;
    uint8_t buffer[SM3_BLOCK_SIZE];
} sm3_ctx;

/**
 * sm3_init(ctx):
 * Initialize the SM3 context ${ctx}.
 */
extern void sm3_init(sm3_ctx *);

/**
 * sm3_update(ctx, in, len):
 * Input ${len} bytes from ${in} into the SM3 context ${ctx}
 */
extern void sm3_update(sm3_ctx *, const void *, size_t);

/**
 * sm3_final(digest, ctx):
 * Output the SM3 hash of the data input to the context ${ctx} into the
 * buffer ${digest}.
 */
extern void sm3_final(uint8_t[32], sm3_ctx *);

/**
 * sm3_buf(in, len, digest):
 * Compute the SM3 hash of ${len} bytes from ${in} and write it to ${digest}.
 */
extern void sm3_buf(const void *, size_t, uint8_t[32]);

/* Context struct for HMAC-SM3 operations. */
typedef struct {
    sm3_ctx ictx;
    sm3_ctx octx;
} hmac_sm3_ctx;

/**
 * hmac_sm3_init(ctx, K, Klen):
 * Initialize the HMAC-SM3 context ${ctx} with ${Klen} bytes of key from ${K}.
 */
extern void hmac_sm3_init(hmac_sm3_ctx *, const void *, size_t);

/**
 * hmac_sm3_update(ctx, in, len):
 * Input ${len} bytes from ${in} into the HMAC-SM3 context ${ctx}.
 */
extern void hmac_sm3_update(hmac_sm3_ctx *, const void *, size_t);

/**
 * hmac_sm3_final(digest, ctx):
 * Output the HMAC-SM3 of the data input to the context ${ctx} into the
 * buffer ${digest}.
 */
extern void hmac_sm3_final(uint8_t[32], hmac_sm3_ctx *);

/**
 * hmac_sm3_buf(K, Klen, in, len, digest):
 * Compute the HMAC-SM3 of ${len} bytes from ${in} using the key ${K} of
 * length ${Klen}, and write the result to ${digest}.
 */
extern void hmac_sm3_buf(const void *, size_t, const void *, size_t, uint8_t[32]);

/**
 * PBKDF2_SM3(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SM3 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
extern void PBKDF2_SM3(const uint8_t *, size_t, const uint8_t *, size_t,
    uint64_t, uint8_t *, size_t);

#endif /* !_SM3_H_ */

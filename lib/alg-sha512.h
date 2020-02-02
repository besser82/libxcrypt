/*-
 * Copyright 2005 Colin Percival
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

#ifndef _SHA512_H_
#define _SHA512_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Use #defines in order to avoid namespace collisions with anyone else's
 * SHA512 code (e.g., the code in OpenSSL).
 */
#define SHA512_Init libcperciva_SHA512_Init
#define SHA512_Update libcperciva_SHA512_Update
#define SHA512_Final libcperciva_SHA512_Final
#define SHA512_Buf libcperciva_SHA512_Buf
#define SHA512_CTX libcperciva_SHA512_CTX

/* Common constants. */
#define SHA512_BLOCK_LENGTH 128
#define SHA512_DIGEST_LENGTH 64

/* Context structure for SHA512 operations. */
typedef struct {
	uint64_t state[8];
	uint64_t count[2];
	uint8_t  buf[SHA512_BLOCK_LENGTH];
} SHA512_CTX;

/**
 * SHA512_Init(ctx):
 * Initialize the SHA512 context ${ctx}.
 */
extern void SHA512_Init(SHA512_CTX *);

/**
 * SHA512_Update(ctx, in, len):
 * Input ${len} bytes from ${in} into the SHA512 context ${ctx}.
 */
extern void SHA512_Update(SHA512_CTX *, const void *, size_t);

/**
 * SHA512_Final(digest, ctx):
 * Output the SHA512 hash of the data input to the context ${ctx} into the
 * buffer ${digest}.
 */
extern void SHA512_Final(unsigned char[MIN_SIZE(SHA512_DIGEST_LENGTH)],
    SHA512_CTX *);

/**
 * SHA512_Buf(in, len, digest):
 * Compute the SHA512 hash of ${len} bytes from ${in} and write it to ${digest}.
 */
extern void SHA512_Buf(const void *, size_t,
    unsigned char[MIN_SIZE(SHA512_DIGEST_LENGTH)]);

#endif /* !_SHA512_H_ */

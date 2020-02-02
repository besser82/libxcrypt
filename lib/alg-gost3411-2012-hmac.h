/* Copyright (C) 2018 vt@altlinux.org
 * Copyright (C) 2018 Björn Esser <besser82@fedoraproject.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
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

#ifndef _CRYPT_ALG_GOST3411_2012_HMAC_H
#define _CRYPT_ALG_GOST3411_2012_HMAC_H

#include "alg-gost3411-2012-core.h"

/* Constants for HMAC_GOSTR3411_2012_256 */
#define GOSTR3411_2012_L 32 /* hash output len */
#define GOSTR3411_2012_B 64 /* hash input len (512) */
#define GOSTR3411_2012_BITS GOSTR3411_2012_L * 8 /* 256 */

typedef struct
{
  GOST34112012Context ctx;
  unsigned char pad[GOSTR3411_2012_B];   /* ipad and opad */
  unsigned char kstar[GOSTR3411_2012_B]; /* derived key */
  unsigned char digest[GOSTR3411_2012_L];
} gost_hmac_256_t;

extern void
gost_hash256 (const uint8_t *t, size_t n, uint8_t *out32,
              GOST34112012Context *ctx);

extern void
gost_hmac256 (const uint8_t *k, size_t n, const uint8_t *t, size_t len,
              uint8_t *out32, gost_hmac_256_t *gostbuf);

#endif /* alg-gost3411-2012-hmac.h */

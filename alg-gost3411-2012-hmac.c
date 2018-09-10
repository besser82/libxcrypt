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


#include "crypt-port.h"

#if INCLUDE_gost_yescrypt

#include "alg-gost3411-2012-hmac.h"

/* GOST2012_256 */
void
gost_hash256 (const uint8_t *t, size_t n, uint8_t *out32,
              GOST34112012Context *ctx)
{
  GOST34112012Init (ctx, GOSTR3411_2012_BITS);
  GOST34112012Update (ctx, t, n);
  GOST34112012Final (ctx, out32);
}

/* HMAC_GOSTR3411_2012_256 */
void
gost_hmac256 (const uint8_t *k, size_t n, const uint8_t *t, size_t len,
              uint8_t *out32, gost_hmac_256_t *gostbuf)
{
  size_t i;

  /* R 50.1.113-2016 only allowed N to be in range 256..512 bits */
  assert (n >= GOSTR3411_2012_L && n <= GOSTR3411_2012_B);

  for (i = 0; i < sizeof (gostbuf->pad); i++)
    gostbuf->kstar[i] = i < n ? k[i] : 0;

  GOST34112012Init (&gostbuf->ctx, GOSTR3411_2012_BITS);

  for (i = 0; i < sizeof (gostbuf->pad); i++)
    gostbuf->pad[i] = gostbuf->kstar[i] ^ 0x36; /* ipad */

  GOST34112012Update (&gostbuf->ctx, gostbuf->pad,
                      sizeof (gostbuf->pad));
  GOST34112012Update (&gostbuf->ctx, t, len);
  GOST34112012Final (&gostbuf->ctx, gostbuf->digest);

  GOST34112012Init (&gostbuf->ctx, GOSTR3411_2012_BITS);

  for (i = 0; i < sizeof (gostbuf->pad); i++)
    gostbuf->pad[i] = gostbuf->kstar[i] ^ 0x5c; /* opad */

  GOST34112012Update (&gostbuf->ctx, gostbuf->pad,
                      sizeof (gostbuf->pad));
  GOST34112012Update (&gostbuf->ctx, gostbuf->digest,
                      sizeof (gostbuf->digest));
  GOST34112012Final (&gostbuf->ctx, out32);
}

#endif /* INCLUDE_gost_yescrypt */

/* Copyright (C) 2024 Björn Esser <besser82@fedoraproject.org>
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

#if INCLUDE_sm3_yescrypt

#include <string.h>
#include "alg-sm3-hmac.h"

/**
 * HMAC_k(m) = H((k ^ opad), H((k ^ ipad), m))
 * pseudo-code:
 * function hmac(key, message)
 *   opad = [0x5c * blocksize]
 *   ipad = [0x36 * blocksize]
 *   if (length(key) > blocksize) then
 *     key = hash(key)
 *   end if
 *   for i from 0 to length(key) - 1 step 1
 *     ipad[i] = ipad[i] XOR key[i]
 *     opad[i] = opad[i] XOR key[i]
 *   end for
 *   return hash(opad || hash(ipad || message))
 * end function
 */

#define IPAD 0x36
#define OPAD 0x5C

void
sm3_hmac_init (sm3_hmac_ctx_t *ctx, const uint8_t *key, size_t key_len)
{
  int i;

  if (key_len <= SM3_BLOCK_SIZE)
    {
      memcpy (ctx->key, key, key_len);
      explicit_bzero (ctx->key + key_len, SM3_BLOCK_SIZE - key_len);
    }
  else
    {
      sm3_init (&ctx->sm3_ctx);
      sm3_update (&ctx->sm3_ctx, key, key_len);
      sm3_final (ctx->key, &ctx->sm3_ctx);
      explicit_bzero (ctx->key + SM3_DIGEST_SIZE,
                      SM3_BLOCK_SIZE - SM3_DIGEST_SIZE);
    }
  for (i = 0; i < SM3_BLOCK_SIZE; i++)
    {
      ctx->key[i] ^= IPAD;
    }

  sm3_init (&ctx->sm3_ctx);
  sm3_update (&ctx->sm3_ctx, ctx->key, SM3_BLOCK_SIZE);
}

void
sm3_hmac_update (sm3_hmac_ctx_t *ctx, const uint8_t *data, size_t data_len)
{
  sm3_update (&ctx->sm3_ctx, data, data_len);
}

void
sm3_hmac_final (sm3_hmac_ctx_t *ctx, uint8_t mac[SM3_HMAC_MAC_SIZE])
{
  int i;
  for (i = 0; i < SM3_BLOCK_SIZE; i++)
    {
      ctx->key[i] ^= (IPAD ^ OPAD);
    }
  sm3_final (mac, &ctx->sm3_ctx);
  sm3_init (&ctx->sm3_ctx);
  sm3_update (&ctx->sm3_ctx, ctx->key, SM3_BLOCK_SIZE);
  sm3_update (&ctx->sm3_ctx, mac, SM3_DIGEST_SIZE);
  sm3_final (mac, &ctx->sm3_ctx);

  /* Zeroize sensitive information. */
  explicit_bzero (&ctx, sizeof (ctx));
}

void
sm3_hmac (const unsigned char *data, size_t data_len,
          const uint8_t *key, size_t key_len,
          uint8_t mac[SM3_HMAC_MAC_SIZE], sm3_hmac_ctx_t *ctx)
{
  sm3_hmac_init (ctx, key, key_len);
  sm3_hmac_update (ctx, data, data_len);
  sm3_hmac_final (ctx, mac);

  /* Zeroize sensitive information. */
  explicit_bzero (ctx, sizeof (sm3_hmac_ctx_t));
}

void
sm3_hmac_buf (const unsigned char *data, size_t data_len,
              const uint8_t *key, size_t key_len,
              uint8_t mac[SM3_HMAC_MAC_SIZE])
{
  sm3_hmac_ctx_t ctx;
  sm3_hmac (data, data_len, key, key_len, mac, &ctx);
}

#endif /* INCLUDE_sm3_yescrypt */

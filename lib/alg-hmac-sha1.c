/*
 * Copyright (c) 2017, Björn Esser <besser82@fedoraproject.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Implement HMAC as described in RFC 2104
 *
 */

#include "crypt-port.h"
#include "alg-hmac-sha1.h"
#include "alg-sha1.h"

#include <stdlib.h>

#if INCLUDE_sha1crypt

/* Don't change these */
#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

/* Nor this */
#ifndef HMAC_BLOCKSZ
# define HMAC_BLOCKSZ 64
# define HASH_LENGTH  20
#endif

/*
 * The logic here is lifted straight from RFC 2104 except that
 * rather than filling the pads with 0, copying in the key and then
 * XOR with the pad byte, we just fill with the pad byte and
 * XOR with the key.
 */
void
hmac_sha1_process_data (const uint8_t *text, size_t text_len,
                        const uint8_t *key, size_t key_len,
                        void *resbuf)
{
  struct sha1_ctx ctx;
  /* Inner padding key XOR'd with ipad */
  uint8_t k_ipad[HMAC_BLOCKSZ];
  /* Outer padding key XOR'd with opad */
  uint8_t k_opad[HMAC_BLOCKSZ];
  /* HASH(key) if needed */
  unsigned char tk[HASH_LENGTH];
  size_t i;

  /*
   * If key is longer than HMAC_BLOCKSZ bytes
   * reset it to key=HASH(key)
   */
  if (key_len > HMAC_BLOCKSZ)
    {
      struct sha1_ctx tctx;

      sha1_init_ctx (&tctx);
      sha1_process_bytes (key, &tctx, key_len);
      sha1_finish_ctx(&tctx, &tk);

      key = tk;
      key_len = HASH_LENGTH;
    }

  /*
   * The HMAC_ transform looks like:
   *
   * HASH(K XOR opad, HASH(K XOR ipad, text))
   *
   * where K is an n byte key
   * ipad is the byte HMAC_IPAD repeated HMAC_BLOCKSZ times
   * opad is the byte HMAC_OPAD repeated HMAC_BLOCKSZ times
   * and text is the data being protected
   */

  /*
   * Fill the pads and XOR in the key
   */
  memset (k_ipad, HMAC_IPAD, sizeof k_ipad);
  memset (k_opad, HMAC_OPAD, sizeof k_opad);
  for (i = 0; i < key_len; i++)
    {
      k_ipad[i] ^= key[i];
      k_opad[i] ^= key[i];
    }

  /*
   * Perform inner HASH.
   * Start with inner pad,
   * then the text.
   */
  sha1_init_ctx (&ctx);
  sha1_process_bytes (k_ipad, &ctx, HMAC_BLOCKSZ);
  sha1_process_bytes (text, &ctx, text_len);
  sha1_finish_ctx(&ctx, resbuf);

  /*
   * Perform outer HASH.
   * Start with the outer pad,
   * then the result of the inner hash.
   */
  sha1_init_ctx (&ctx);
  sha1_process_bytes (k_opad, &ctx, HMAC_BLOCKSZ);
  sha1_process_bytes (resbuf, &ctx, HASH_LENGTH);
  sha1_finish_ctx(&ctx, resbuf);
}

#endif

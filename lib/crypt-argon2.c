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
 * crypt-argon2.c
 * crypt(3) interface for Argon2 hash.
 */

#include "crypt-port.h"

#if INCLUDE_argon2

#include <errno.h>
#include "alg-argon2.h"
#include "alg-argon2-encoding.h"

struct argon2_crypt_ctx
{
  argon2_context argon2_ctx;
  uint8_t ctx_out[CRYPT_OUTPUT_SIZE];
  uint8_t ctx_salt[CRYPT_OUTPUT_SIZE];
  char setbuf[CRYPT_OUTPUT_SIZE];
  char obuf[CRYPT_OUTPUT_SIZE];
};

static_assert (sizeof (struct argon2_crypt_ctx) <= ALG_SPECIFIC_SIZE,
               "ALG_SPECIFIC_SIZE is too small for ARGON2.");

static void
crypt_argon2_rn (const char *phrase, size_t phr_size,
                 const char *setting, size_t set_size,
                 uint8_t *output, size_t out_size,
                 void *scratch, size_t scr_size,
                 argon2_type type)
{
  /* Sanity check */
  if (out_size < set_size + 1 + 43 + 1 ||
      CRYPT_OUTPUT_SIZE < set_size + 1 + 43 + 1 ||
      scr_size < sizeof (struct argon2_crypt_ctx))
    {
      errno = ERANGE;
      return;
    }

  /* Verify setting with phrase. */
  int retval = argon2_verify (setting, phrase, phr_size, type);

  /* Phrase matches hash portion from setting. */
  if (retval == ARGON2_OK)
    {
      strcpy_or_abort (output, out_size, setting);
      return;
    }

  /* Setting is valid, but phrase does not match its hash portion. */
  if (retval == ARGON2_VERIFY_MISMATCH)
    return;


  /* Setting may be valid, but does not contain a hash portion.
     Proceed with calculating a new hash from the given setting. */
  struct argon2_crypt_ctx *crypt_ctx = scratch;
  uint32_t hashlen, random;

  /* Randomize output length of hash. */
  const uint32_t hashlenmin = 32;
  const uint32_t hashlenmax = (uint32_t) ((out_size - set_size - 2) * 3) >> 2;
  get_random_bytes (&random, sizeof (random));
  hashlen = random % (hashlenmax - hashlenmin + 1) + hashlenmin;

  /* Fix random output length of hash to not overflow out_size by accident. */
  while (hashlen > hashlenmin &&
         b64len(hashlen) > out_size - set_size - 2)
    --hashlen;

  /* Copy setting to writable buffer,
     as we are going to add a fake hash value to it. */
  strcpy_or_abort (crypt_ctx->setbuf, sizeof (crypt_ctx->setbuf), setting);

  /* Remove trailing dollar sign '$' from setting, if any. */
  if (setting[set_size - 1] == '$')
    crypt_ctx->setbuf[set_size - 1] = '\0';

  /* Append a fake hash to setting, as decode_string() always
     expects one to be present.  If setting would end with a
     hash portion already, we would not have reached this codepath.*/
  strcat (crypt_ctx->setbuf, "$dGVzdHN0cmluZ2luYmFzZTY0");

  /* Setup output buffers in argon2_ctx for decode_string().  */
  crypt_ctx->argon2_ctx.out     = crypt_ctx->ctx_out;
  crypt_ctx->argon2_ctx.outlen  = CRYPT_OUTPUT_SIZE;
  crypt_ctx->argon2_ctx.salt    = crypt_ctx->ctx_salt;
  crypt_ctx->argon2_ctx.saltlen = CRYPT_OUTPUT_SIZE;

  /* Decode setting into argon2_ctx and compute the hash for the
     given parameters.  Will error out early if setting is not
     valid for other reasons, but a missing hash portion. */
  if (!(decode_string (&crypt_ctx->argon2_ctx,
                       crypt_ctx->setbuf, type) == ARGON2_OK &&
        argon2_hash (crypt_ctx->argon2_ctx.t_cost, crypt_ctx->argon2_ctx.m_cost,
                     crypt_ctx->argon2_ctx.lanes, phrase, phr_size,
                     crypt_ctx->argon2_ctx.salt, crypt_ctx->argon2_ctx.saltlen,
                     NULL, hashlen, crypt_ctx->obuf, sizeof (crypt_ctx->obuf),
                     type, crypt_ctx->argon2_ctx.version) == ARGON2_OK))
    {
      errno = EINVAL;
      return;
    }

  strcpy_or_abort (output, out_size, crypt_ctx->obuf);
}

static void
gensalt_argon2_rn (unsigned long count,
                   const uint8_t *rbytes, size_t nrbytes,
                   uint8_t *output, size_t output_size,
                   argon2_type type)
{
  /* Sanity check. */
  if (nrbytes < 16)
    {
      errno = EINVAL;
      return;
    }

  argon2_context ctx;
  char obuf[CRYPT_OUTPUT_SIZE];

  /* Fake hashbytes for encode_string(). */
  const uint8_t outbytes[] = "0123456789ABCDEF";
  const uint8_t *outbptr = outbytes;

  /* Use default parameters, if count == 0. */
  if (count == 0)
    count = 0x00040808;

  /* Initialize buffers. */
  memset (&ctx, 0, sizeof (ctx));
  memset (obuf, 0, sizeof (obuf));

  /* Translate count to argon2_ctx parameters. */
  ctx.lanes   = ctx.threads = (count >> 16) & 0x0F;
  ctx.m_cost  = ARGON2_MIN_MEMORY * ctx.lanes * ((count >>  8) & 0xFF);
  ctx.t_cost  = count & 0xFF;
  ctx.version = ARGON2_VERSION_NUMBER;
  ctx.saltlen = (uint32_t) nrbytes;
  ctx.outlen  = sizeof (outbytes);
  /* Hackish way to to cast from const to non-const. */
  memcpy (&ctx.salt, &rbytes, sizeof (rbytes));
  memcpy (&ctx.out, &outbptr, sizeof (outbptr));

  const size_t setting_size =
    argon2_encodedlen(ctx.t_cost, ctx.m_cost, ctx.lanes,
                      ctx.saltlen, 0, type);

  /* Another sanity check. */
  if (output_size < setting_size ||
      CRYPT_GENSALT_OUTPUT_SIZE < setting_size)
    {
      errno = ERANGE;
      goto out;
    }

  /* Encode argon2_ctx to setting string. */
  if (encode_string (obuf, sizeof (obuf), &ctx, type) != ARGON2_OK)
    {
      errno = EINVAL;
      goto out;
    }

  /* Truncate setting to remove the fake hash, and copy to output. */
  *strrchr(obuf, '$') = '\0';
  strcpy_or_abort (output, output_size, obuf);

out:
  /* Clean up. */
  explicit_bzero (&ctx, sizeof (ctx));
  explicit_bzero (obuf, sizeof (obuf));
}

#if INCLUDE_argon2d

void
crypt_argon2d_rn (const char *phrase, size_t phr_size,
                  const char *setting, size_t set_size,
                  uint8_t *output, size_t out_size,
                  void *scratch, size_t scr_size)
{
  if (strncmp (setting, "$argon2d$", 9) != 0)
    {
      errno = EINVAL;
      return;
    }

  crypt_argon2_rn (phrase, phr_size,
                   setting, set_size,
                   output, out_size,
                   scratch, scr_size,
                   Argon2_d);
}

void
gensalt_argon2d_rn (unsigned long count,
                    const uint8_t *rbytes, size_t nrbytes,
                    uint8_t *output, size_t output_size)
{
  gensalt_argon2_rn (count,
                     rbytes, nrbytes,
                     output, output_size,
                     Argon2_d);
}

#endif /* INCLUDE_argon2d */

#if INCLUDE_argon2i

void
crypt_argon2i_rn (const char *phrase, size_t phr_size,
                  const char *setting, size_t set_size,
                  uint8_t *output, size_t out_size,
                  void *scratch, size_t scr_size)
{
  if (strncmp (setting, "$argon2i$", 9) != 0)
    {
      errno = EINVAL;
      return;
    }

  crypt_argon2_rn (phrase, phr_size,
                   setting, set_size,
                   output, out_size,
                   scratch, scr_size,
                   Argon2_i);
}

void
gensalt_argon2i_rn (unsigned long count,
                    const uint8_t *rbytes, size_t nrbytes,
                    uint8_t *output, size_t output_size)
{
  gensalt_argon2_rn (count,
                     rbytes, nrbytes,
                     output, output_size,
                     Argon2_i);
}

#endif /* INCLUDE_argon2i */

#if INCLUDE_argon2id

void
crypt_argon2id_rn (const char *phrase, size_t phr_size,
                  const char *setting, size_t set_size,
                  uint8_t *output, size_t out_size,
                  void *scratch, size_t scr_size)
{
  if (strncmp (setting, "$argon2id$", 10) != 0)
    {
      errno = EINVAL;
      return;
    }

  crypt_argon2_rn (phrase, phr_size,
                   setting, set_size,
                   output, out_size,
                   scratch, scr_size,
                   Argon2_id);
}

void
gensalt_argon2id_rn (unsigned long count,
                     const uint8_t *rbytes, size_t nrbytes,
                     uint8_t *output, size_t output_size)
{
  gensalt_argon2_rn (count,
                     rbytes, nrbytes,
                     output, output_size,
                     Argon2_id);
}

#endif /* INCLUDE_argon2id */
#endif /* INCLUDE_argon2 */

/* One way encryption based on SHA256 sum.

   Copyright (C) 2007-2017 Free Software Foundation, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include "crypt-port.h"
#include "crypt-private.h"
#include "alg-sha256.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#if INCLUDE_sha256

/* Define our magic string to mark salt for SHA256 "encryption"
   replacement.  */
static const char sha256_salt_prefix[] = "$5$";

/* Prefix for optional rounds specification.  */
static const char sha256_rounds_prefix[] = "rounds=";

/* Maximum salt string length.  */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN 1000
/* Maximum number of rounds.  */
#define ROUNDS_MAX 999999999

/* The maximum possible length of a SHA256-hashed password string,
   including the terminating NUL character.  Prefix (including its NUL)
   + rounds tag ("rounds=$" = "rounds=\0") + strlen(ROUNDS_MAX)
   + salt (up to SALT_LEN_MAX chars) + '$' + hash (43 chars).  */

#define LENGTH_OF_NUMBER(n) (sizeof #n - 1)

#define SHA256_HASH_LENGTH \
  (sizeof (sha256_salt_prefix) + sizeof (sha256_rounds_prefix) + \
   LENGTH_OF_NUMBER (ROUNDS_MAX) + SALT_LEN_MAX + 1 + 43)

static_assert (SHA256_HASH_LENGTH <= CRYPT_OUTPUT_SIZE,
               "CRYPT_OUTPUT_SIZE is too small for SHA256");

/* A sha256_buffer holds all of the sensitive intermediate data.  */
struct sha256_buffer
{
  struct sha256_ctx ctx;
  uint8_t result[32];
  uint8_t p_bytes[32];
  uint8_t s_bytes[32];
};

static_assert (sizeof (struct sha256_buffer) <= ALG_SPECIFIC_SIZE,
               "ALG_SPECIFIC_SIZE is too small for SHA256");


/* Table with characters for base64 transformation.  */
static const char b64t[] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* Subroutine of _xcrypt_crypt_sha256_rn: Feed CTX with LEN bytes of a
   virtual byte sequence consisting of BLOCK repeated over and over
   indefinitely.  */
static void
sha256_process_recycled_bytes (unsigned char block[32], size_t len,
                               struct sha256_ctx *ctx)
{
  size_t cnt;
  for (cnt = len; cnt >= 32; cnt -= 32)
    sha256_process_bytes (block, 32, ctx);
  sha256_process_bytes (block, cnt, ctx);
}

void
crypt_sha256_rn (const char *phrase, size_t phr_size,
                 const char *setting, size_t ARG_UNUSED (set_size),
                 uint8_t *output, size_t out_size,
                 void *scratch, size_t scr_size)
{
  /* This shouldn't ever happen, but...  */
  if (out_size < SHA256_HASH_LENGTH
      || scr_size < sizeof (struct sha256_buffer))
    {
      errno = ERANGE;
      return;
    }

  struct sha256_buffer *buf = scratch;
  struct sha256_ctx *ctx = &buf->ctx;
  uint8_t *result = buf->result;
  uint8_t *p_bytes = buf->p_bytes;
  uint8_t *s_bytes = buf->s_bytes;
  char *cp = (char *)output;
  const char *salt = setting;

  size_t salt_size;
  size_t cnt;
  /* Default number of rounds.  */
  size_t rounds = ROUNDS_DEFAULT;
  bool rounds_custom = false;

  /* Find beginning of salt string.  The prefix should normally always
     be present.  Just in case it is not.  */
  if (strncmp (sha256_salt_prefix, salt, sizeof (sha256_salt_prefix) - 1) == 0)
    /* Skip salt prefix.  */
    salt += sizeof (sha256_salt_prefix) - 1;

  if (strncmp (salt, sha256_rounds_prefix, sizeof (sha256_rounds_prefix) - 1)
      == 0)
    {
      const char *num = salt + sizeof (sha256_rounds_prefix) - 1;
      /* Do not allow an explicit setting of zero rounds, nor of the
         default number of rounds, nor leading zeroes on the rounds.  */
      if (!(*num >= '1' && *num <= '9'))
        {
          errno = EINVAL;
          return;
        }

      errno = 0;
      char *endp;
      rounds = strtoul (num, &endp, 10);
      if (endp == num || *endp != '$'
          || rounds < ROUNDS_MIN
          || rounds > ROUNDS_MAX
          || errno)
        {
          errno = EINVAL;
          return;
        }
      salt = endp + 1;
      rounds_custom = true;
    }

  salt_size = strspn (salt, b64t);
  if (salt[salt_size] && salt[salt_size] != '$')
    {
      errno = EINVAL;
      return;
    }
  if (salt_size > SALT_LEN_MAX)
    salt_size = SALT_LEN_MAX;

  /* Compute alternate SHA256 sum with input PHRASE, SALT, and PHRASE.  The
     final result will be added to the first context.  */
  sha256_init_ctx (ctx);

  /* Add phrase.  */
  sha256_process_bytes (phrase, phr_size, ctx);

  /* Add salt.  */
  sha256_process_bytes (salt, salt_size, ctx);

  /* Add phrase again.  */
  sha256_process_bytes (phrase, phr_size, ctx);

  /* Now get result of this (32 bytes).  */
  sha256_finish_ctx (ctx, result);

  /* Prepare for the real work.  */
  sha256_init_ctx (ctx);

  /* Add the phrase string.  */
  sha256_process_bytes (phrase, phr_size, ctx);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */
  sha256_process_bytes (salt, salt_size, ctx);

  /* Add for any character in the phrase one byte of the alternate sum.  */
  for (cnt = phr_size; cnt > 32; cnt -= 32)
    sha256_process_bytes (result, 32, ctx);
  sha256_process_bytes (result, cnt, ctx);

  /* Take the binary representation of the length of the phrase and for every
     1 add the alternate sum, for every 0 the phrase.  */
  for (cnt = phr_size; cnt > 0; cnt >>= 1)
    if ((cnt & 1) != 0)
      sha256_process_bytes (result, 32, ctx);
    else
      sha256_process_bytes (phrase, phr_size, ctx);

  /* Create intermediate result.  */
  sha256_finish_ctx (ctx, result);

  /* Start computation of P byte sequence.  */
  sha256_init_ctx (ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < phr_size; ++cnt)
    sha256_process_bytes (phrase, phr_size, ctx);

  /* Finish the digest.  */
  sha256_finish_ctx (ctx, p_bytes);

  /* Start computation of S byte sequence.  */
  sha256_init_ctx (ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < (size_t) 16 + (size_t) result[0]; ++cnt)
    sha256_process_bytes (salt, salt_size, ctx);

  /* Finish the digest.  */
  sha256_finish_ctx (ctx, s_bytes);

  /* Repeatedly run the collected hash value through SHA256 to burn
     CPU cycles.  */
  for (cnt = 0; cnt < rounds; ++cnt)
    {
      /* New context.  */
      sha256_init_ctx (ctx);

      /* Add phrase or last result.  */
      if ((cnt & 1) != 0)
        sha256_process_recycled_bytes (p_bytes, phr_size, ctx);
      else
        sha256_process_bytes (result, 32, ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        sha256_process_recycled_bytes (s_bytes, salt_size, ctx);

      /* Add phrase for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        sha256_process_recycled_bytes (p_bytes, phr_size, ctx);

      /* Add phrase or last result.  */
      if ((cnt & 1) != 0)
        sha256_process_bytes (result, 32, ctx);
      else
        sha256_process_recycled_bytes (p_bytes, phr_size, ctx);

      /* Create intermediate result.  */
      sha256_finish_ctx (ctx, result);
    }

  /* Now we can construct the result string.  It consists of four
     parts, one of which is optional.  We already know that there
     is sufficient space at CP for the longest possible result string.  */
  memcpy (cp, sha256_salt_prefix, sizeof (sha256_salt_prefix) - 1);
  cp += sizeof (sha256_salt_prefix) - 1;

  if (rounds_custom)
    {
      int n = snprintf (cp,
                        SHA256_HASH_LENGTH - (sizeof (sha256_salt_prefix) - 1),
                        "%s%zu$", sha256_rounds_prefix, rounds);
      cp += n;
    }

  memcpy (cp, salt, salt_size);
  cp += salt_size;
  *cp++ = '$';

#define b64_from_24bit(B2, B1, B0, N)                   \
  do {                                                  \
    unsigned int w = ((((unsigned int)(B2)) << 16) |    \
                      (((unsigned int)(B1)) << 8) |     \
                      ((unsigned int)(B0)));            \
    int n = (N);                                        \
    while (n-- > 0)                                     \
      {                                                 \
        *cp++ = b64t[w & 0x3f];                         \
        w >>= 6;                                        \
      }                                                 \
  } while (0)

  b64_from_24bit (result[0], result[10], result[20], 4);
  b64_from_24bit (result[21], result[1], result[11], 4);
  b64_from_24bit (result[12], result[22], result[2], 4);
  b64_from_24bit (result[3], result[13], result[23], 4);
  b64_from_24bit (result[24], result[4], result[14], 4);
  b64_from_24bit (result[15], result[25], result[5], 4);
  b64_from_24bit (result[6], result[16], result[26], 4);
  b64_from_24bit (result[27], result[7], result[17], 4);
  b64_from_24bit (result[18], result[28], result[8], 4);
  b64_from_24bit (result[9], result[19], result[29], 4);
  b64_from_24bit (0, result[31], result[30], 3);

  *cp = '\0';
}

void
gensalt_sha256_rn (unsigned long count,
                   const uint8_t *rbytes, size_t nrbytes,
                   uint8_t *output, size_t output_size)
{
  gensalt_sha_rn ('5', SALT_LEN_MAX, ROUNDS_DEFAULT, ROUNDS_MIN, ROUNDS_MAX,
                  count, rbytes, nrbytes, output, output_size);
}

#endif

/* One way encryption based on SHA512 sum.

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
#include "alg-sha512.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#if INCLUDE_sha512

/* Define our magic string to mark salt for SHA512 "encryption"
   replacement.  */
static const char sha512_salt_prefix[] = "$6$";

/* Prefix for optional rounds specification.  */
static const char sha512_rounds_prefix[] = "rounds=";

/* Maximum salt string length.  */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN 1000
/* Maximum number of rounds.  */
#define ROUNDS_MAX 999999999

/* The maximum possible length of a SHA512-hashed password string,
   including the terminating NUL character.  Prefix (including its NUL)
   + rounds tag ("rounds=$" = "rounds=\0") + strlen(ROUNDS_MAX)
   + salt (up to SALT_LEN_MAX chars) + '$' + hash (86 chars).  */

#define LENGTH_OF_NUMBER(n) (sizeof #n - 1)

#define SHA512_HASH_LENGTH \
  (sizeof (sha512_salt_prefix) + sizeof (sha512_rounds_prefix) + \
   LENGTH_OF_NUMBER (ROUNDS_MAX) + SALT_LEN_MAX + 1 + 86)

static_assert (SHA512_HASH_LENGTH <= CRYPT_OUTPUT_SIZE,
               "CRYPT_OUTPUT_SIZE is too small for SHA512");

/* A sha512_buffer holds all of the sensitive intermediate data.  */
struct sha512_buffer
{
  struct sha512_ctx ctx;
  uint8_t result[64];
  uint8_t p_bytes[64];
  uint8_t s_bytes[64];
};

static_assert (sizeof (struct sha512_buffer) <= ALG_SPECIFIC_SIZE,
               "ALG_SPECIFIC_SIZE is too small for SHA512");


/* Table with characters for base64 transformation.  */
static const char b64t[] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* Subroutine of _xcrypt_crypt_sha512_rn: Feed CTX with LEN bytes of a
   virtual byte sequence consisting of BLOCK repeated over and over
   indefinitely.  */
static void
sha512_process_recycled_bytes (unsigned char block[64], size_t len,
                               struct sha512_ctx *ctx)
{
  size_t cnt;
  for (cnt = len; cnt >= 64; cnt -= 64)
    sha512_process_bytes (block, 64, ctx);
  sha512_process_bytes (block, cnt, ctx);
}

void
crypt_sha512_rn (const char *phrase, size_t phr_size,
                 const char *setting, size_t ARG_UNUSED (set_size),
                 uint8_t *output, size_t out_size,
                 void *scratch, size_t scr_size)
{
  /* This shouldn't ever happen, but...  */
  if (out_size < SHA512_HASH_LENGTH
      || scr_size < sizeof (struct sha512_buffer))
    {
      errno = ERANGE;
      return;
    }

  struct sha512_buffer *buf = scratch;
  struct sha512_ctx *ctx = &buf->ctx;
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
  if (strncmp (sha512_salt_prefix, salt, sizeof (sha512_salt_prefix) - 1) == 0)
    /* Skip salt prefix.  */
    salt += sizeof (sha512_salt_prefix) - 1;

  if (strncmp (salt, sha512_rounds_prefix, sizeof (sha512_rounds_prefix) - 1)
      == 0)
    {
      const char *num = salt + sizeof (sha512_rounds_prefix) - 1;
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
  phr_size = strlen (phrase);

  /* Compute alternate SHA512 sum with input PHRASE, SALT, and PHRASE.  The
     final result will be added to the first context.  */
  sha512_init_ctx (ctx);

  /* Add phrase.  */
  sha512_process_bytes (phrase, phr_size, ctx);

  /* Add salt.  */
  sha512_process_bytes (salt, salt_size, ctx);

  /* Add phrase again.  */
  sha512_process_bytes (phrase, phr_size, ctx);

  /* Now get result of this (64 bytes) and add it to the other
     context.  */
  sha512_finish_ctx (ctx, result);

  /* Prepare for the real work.  */
  sha512_init_ctx (ctx);

  /* Add the phrase string.  */
  sha512_process_bytes (phrase, phr_size, ctx);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */
  sha512_process_bytes (salt, salt_size, ctx);

  /* Add for any character in the phrase one byte of the alternate sum.  */
  for (cnt = phr_size; cnt > 64; cnt -= 64)
    sha512_process_bytes (result, 64, ctx);
  sha512_process_bytes (result, cnt, ctx);

  /* Take the binary representation of the length of the phrase and for every
     1 add the alternate sum, for every 0 the phrase.  */
  for (cnt = phr_size; cnt > 0; cnt >>= 1)
    if ((cnt & 1) != 0)
      sha512_process_bytes (result, 64, ctx);
    else
      sha512_process_bytes (phrase, phr_size, ctx);

  /* Create intermediate result.  */
  sha512_finish_ctx (ctx, result);

  /* Start computation of P byte sequence.  */
  sha512_init_ctx (ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < phr_size; ++cnt)
    sha512_process_bytes (phrase, phr_size, ctx);

  /* Finish the digest.  */
  sha512_finish_ctx (ctx, p_bytes);

  /* Start computation of S byte sequence.  */
  sha512_init_ctx (ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < (size_t) 16 + (size_t) result[0]; ++cnt)
    sha512_process_bytes (salt, salt_size, ctx);

  /* Finish the digest.  */
  sha512_finish_ctx (ctx, s_bytes);

  /* Repeatedly run the collected hash value through SHA512 to burn
     CPU cycles.  */
  for (cnt = 0; cnt < rounds; ++cnt)
    {
      /* New context.  */
      sha512_init_ctx (ctx);

      /* Add phrase or last result.  */
      if ((cnt & 1) != 0)
        sha512_process_recycled_bytes (p_bytes, phr_size, ctx);
      else
        sha512_process_bytes (result, 64, ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        sha512_process_recycled_bytes (s_bytes, salt_size, ctx);

      /* Add phrase for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        sha512_process_recycled_bytes (p_bytes, phr_size, ctx);

      /* Add phrase or last result.  */
      if ((cnt & 1) != 0)
        sha512_process_bytes (result, 64, ctx);
      else
        sha512_process_recycled_bytes (p_bytes, phr_size, ctx);

      /* Create intermediate result.  */
      sha512_finish_ctx (ctx, result);
    }

  /* Now we can construct the result string.  It consists of four
     parts, one of which is optional.  We already know that buflen is
     at least sha512_hash_length, therefore none of the string bashing
     below can overflow the buffer. */

  memcpy (cp, sha512_salt_prefix, sizeof (sha512_salt_prefix) - 1);
  cp += sizeof (sha512_salt_prefix) - 1;

  if (rounds_custom)
    {
      int n = snprintf (cp,
                        SHA512_HASH_LENGTH - (sizeof (sha512_salt_prefix) - 1),
                        "%s%zu$", sha512_rounds_prefix, rounds);
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

  b64_from_24bit (result[0], result[21], result[42], 4);
  b64_from_24bit (result[22], result[43], result[1], 4);
  b64_from_24bit (result[44], result[2], result[23], 4);
  b64_from_24bit (result[3], result[24], result[45], 4);
  b64_from_24bit (result[25], result[46], result[4], 4);
  b64_from_24bit (result[47], result[5], result[26], 4);
  b64_from_24bit (result[6], result[27], result[48], 4);
  b64_from_24bit (result[28], result[49], result[7], 4);
  b64_from_24bit (result[50], result[8], result[29], 4);
  b64_from_24bit (result[9], result[30], result[51], 4);
  b64_from_24bit (result[31], result[52], result[10], 4);
  b64_from_24bit (result[53], result[11], result[32], 4);
  b64_from_24bit (result[12], result[33], result[54], 4);
  b64_from_24bit (result[34], result[55], result[13], 4);
  b64_from_24bit (result[56], result[14], result[35], 4);
  b64_from_24bit (result[15], result[36], result[57], 4);
  b64_from_24bit (result[37], result[58], result[16], 4);
  b64_from_24bit (result[59], result[17], result[38], 4);
  b64_from_24bit (result[18], result[39], result[60], 4);
  b64_from_24bit (result[40], result[61], result[19], 4);
  b64_from_24bit (result[62], result[20], result[41], 4);
  b64_from_24bit (0, 0, result[63], 2);

  *cp = '\0';
}

void
gensalt_sha512_rn (unsigned long count,
                   const uint8_t *rbytes, size_t nrbytes,
                   uint8_t *output, size_t output_size)
{
  gensalt_sha_rn ('6', SALT_LEN_MAX, ROUNDS_DEFAULT, ROUNDS_MIN, ROUNDS_MAX,
                  count, rbytes, nrbytes, output, output_size);
}

#endif

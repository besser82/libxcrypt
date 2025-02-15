/*
 * Copyright (C) 2024 Tianjia Zhang
 * All rights reserved.
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
#include "alg-sm3.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#if INCLUDE_sm3crypt

/* Define our magic string to mark salt for SM3 "encryption"
   replacement.  */
static const char sm3_salt_prefix[] = "$sm3$";

/* Prefix for optional rounds specification.  */
static const char sm3_rounds_prefix[] = "rounds=";

/* Maximum salt string length.  */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN 1000
/* Maximum number of rounds.  */
#define ROUNDS_MAX 999999999

/* The maximum possible length of a SM3-hashed password string,
   including the terminating NUL character.  Prefix (including its NUL)
   + rounds tag ("rounds=$" = "rounds=\0") + strlen(ROUNDS_MAX)
   + salt (up to SALT_LEN_MAX chars) + '$' + hash (43 chars).  */

#define LENGTH_OF_NUMBER(n) (sizeof #n - 1)

#define SM3_HASH_LENGTH \
  (sizeof (sm3_salt_prefix) + sizeof (sm3_rounds_prefix) + \
   LENGTH_OF_NUMBER (ROUNDS_MAX) + SALT_LEN_MAX + 1 + 43)

static_assert (SM3_HASH_LENGTH <= CRYPT_OUTPUT_SIZE,
               "CRYPT_OUTPUT_SIZE is too small for SM3");

/* A sm3_buffer holds all of the sensitive intermediate data.  */
struct sm3_buffer
{
  sm3_ctx ctx;
  uint8_t result[32];
  uint8_t p_bytes[32];
  uint8_t s_bytes[32];
};

static_assert (sizeof (struct sm3_buffer) <= ALG_SPECIFIC_SIZE,
               "ALG_SPECIFIC_SIZE is too small for SM3");


/* Feed CTX with LEN bytes of a virtual byte sequence consisting of
   BLOCK repeated over and over indefinitely.  */
static void
sm3_update_recycled (sm3_ctx *ctx,
                     unsigned char block[32], size_t len)
{
  size_t cnt;
  for (cnt = len; cnt >= 32; cnt -= 32)
    sm3_update (ctx, block, 32);
  sm3_update (ctx, block, cnt);
}

void
crypt_sm3crypt_rn (const char *phrase, size_t phr_size,
                   const char *setting, size_t ARG_UNUSED (set_size),
                   uint8_t *output, size_t out_size,
                   void *scratch, size_t scr_size)
{
  /* This shouldn't ever happen, but...  */
  if (out_size < SM3_HASH_LENGTH
      || scr_size < sizeof (struct sm3_buffer))
    {
      errno = ERANGE;
      return;
    }

  struct sm3_buffer *buf = scratch;
  sm3_ctx *ctx = &buf->ctx;
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
  if (strncmp (sm3_salt_prefix, salt, sizeof (sm3_salt_prefix) - 1) == 0)
    /* Skip salt prefix.  */
    salt += sizeof (sm3_salt_prefix) - 1;

  if (strncmp (salt, sm3_rounds_prefix, sizeof (sm3_rounds_prefix) - 1)
      == 0)
    {
      const char *num = salt + sizeof (sm3_rounds_prefix) - 1;
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

  /* The salt ends at the next '$' or the end of the string.
     Ensure ':' does not appear in the salt (it is used as a separator in /etc/passwd).
     Also check for '\n', as in /etc/passwd the whole parameters of the user data must
     be on a single line. */
  salt_size = strcspn (salt, "$:\n");
  if (!(salt[salt_size] == '$' || !salt[salt_size]))
    {
      errno = EINVAL;
      return;
    }

  /* Ensure we do not use more salt than SALT_LEN_MAX. */
  if (salt_size > SALT_LEN_MAX)
    salt_size = SALT_LEN_MAX;

  /* Compute alternate SM3 sum with input PHRASE, SALT, and PHRASE.  The
     final result will be added to the first context.  */
  sm3_init (ctx);

  /* Add phrase.  */
  sm3_update (ctx, phrase, phr_size);

  /* Add salt.  */
  sm3_update (ctx, salt, salt_size);

  /* Add phrase again.  */
  sm3_update (ctx, phrase, phr_size);

  /* Now get result of this (32 bytes).  */
  sm3_final (result, ctx);

  /* Prepare for the real work.  */
  sm3_init (ctx);

  /* Add the phrase string.  */
  sm3_update (ctx, phrase, phr_size);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */
  sm3_update (ctx, salt, salt_size);

  /* Add for any character in the phrase one byte of the alternate sum.  */
  for (cnt = phr_size; cnt > 32; cnt -= 32)
    sm3_update (ctx, result, 32);
  sm3_update (ctx, result, cnt);

  /* Take the binary representation of the length of the phrase and for every
     1 add the alternate sum, for every 0 the phrase.  */
  for (cnt = phr_size; cnt > 0; cnt >>= 1)
    if ((cnt & 1) != 0)
      sm3_update (ctx, result, 32);
    else
      sm3_update (ctx, phrase, phr_size);

  /* Create intermediate result.  */
  sm3_final (result, ctx);

  /* Start computation of P byte sequence.  */
  sm3_init (ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < phr_size; ++cnt)
    sm3_update (ctx, phrase, phr_size);

  /* Finish the digest.  */
  sm3_final (p_bytes, ctx);

  /* Start computation of S byte sequence.  */
  sm3_init (ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < (size_t) 16 + (size_t) result[0]; ++cnt)
    sm3_update (ctx, salt, salt_size);

  /* Finish the digest.  */
  sm3_final (s_bytes, ctx);

  /* Repeatedly run the collected hash value through SM3 to burn
     CPU cycles.  */
  for (cnt = 0; cnt < rounds; ++cnt)
    {
      /* New context.  */
      sm3_init (ctx);

      /* Add phrase or last result.  */
      if ((cnt & 1) != 0)
        sm3_update_recycled (ctx, p_bytes, phr_size);
      else
        sm3_update (ctx, result, 32);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        sm3_update_recycled (ctx, s_bytes, salt_size);

      /* Add phrase for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        sm3_update_recycled (ctx, p_bytes, phr_size);

      /* Add phrase or last result.  */
      if ((cnt & 1) != 0)
        sm3_update (ctx, result, 32);
      else
        sm3_update_recycled (ctx, p_bytes, phr_size);

      /* Create intermediate result.  */
      sm3_final (result, ctx);
    }

  /* Now we can construct the result string.  It consists of four
     parts, one of which is optional.  We already know that there
     is sufficient space at CP for the longest possible result string.  */
  memcpy (cp, sm3_salt_prefix, sizeof (sm3_salt_prefix) - 1);
  cp += sizeof (sm3_salt_prefix) - 1;

  if (rounds_custom)
    {
      int n = snprintf (cp, SM3_HASH_LENGTH - (sizeof (sm3_salt_prefix) - 1),
                        "%s%zu$", sm3_rounds_prefix, rounds);
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
gensalt_sm3crypt_rn (unsigned long count,
                     const uint8_t *rbytes, size_t nrbytes,
                     uint8_t *output, size_t output_size)
{
  /* We will use more rbytes if available, but at least this much is
     required.  */
  if (nrbytes < 3)
    {
      errno = EINVAL;
      return;
    }

  if (count == 0)
    count = ROUNDS_DEFAULT;
  if (count < ROUNDS_MIN)
    count = ROUNDS_MIN;
  if (count > ROUNDS_MAX)
    count = ROUNDS_MAX;

  /* Compute how much space we need.  */
  size_t output_len = 8; /* $x$ssss\0 */
  if (count != ROUNDS_DEFAULT)
    {
      output_len += 9; /* rounds=1$ */
      for (unsigned long ceiling = 10; ceiling < count; ceiling *= 10)
        output_len += 1;
    }
  if (output_size < output_len)
    {
      errno = ERANGE;
      return;
    }

  size_t written;
  if (count == ROUNDS_DEFAULT)
    {
      output[0] = '$';
      output[1] = 's';
      output[2] = 'm';
      output[3] = '3';
      output[4] = '$';
      written = 5;
    }
  else
    written = (size_t) snprintf ((char *)output, output_size,
                                 "$sm3$rounds=%lu$", count);

  /* The length calculation above should ensure that this is always true.  */
  assert (written + 5 < output_size);

  size_t used_rbytes = 0;
  while (written + 5 < output_size &&
         used_rbytes + 3 < nrbytes &&
         (used_rbytes * 4 / 3) < SALT_LEN_MAX)
    {
      unsigned long value =
        ((unsigned long) (unsigned char) rbytes[used_rbytes + 0] <<  0) |
        ((unsigned long) (unsigned char) rbytes[used_rbytes + 1] <<  8) |
        ((unsigned long) (unsigned char) rbytes[used_rbytes + 2] << 16);

      output[written + 0] = ascii64[value & 0x3f];
      output[written + 1] = ascii64[(value >> 6) & 0x3f];
      output[written + 2] = ascii64[(value >> 12) & 0x3f];
      output[written + 3] = ascii64[(value >> 18) & 0x3f];

      written += 4;
      used_rbytes += 3;
    }

  output[written] = '\0';
}

#endif

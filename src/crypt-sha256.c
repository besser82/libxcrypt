/* One way encryption based on SHA256 sum.
   Copyright (C) 2007 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2007.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include "alg-sha256.h"
#include "crypt-private.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

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

static const size_t sha256_hash_length =
  sizeof (sha256_salt_prefix) + sizeof (sha256_rounds_prefix) +
  LENGTH_OF_NUMBER (ROUNDS_MAX) + SALT_LEN_MAX + 1 + 43;

/* Table with characters for base64 transformation.  */
static const char b64t[64] =
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

char *
crypt_sha256_rn (const char *key, const char *salt,
                 char *buffer, size_t buflen)
{
  unsigned char alt_result[32];
  unsigned char temp_result[32];
  struct sha256_ctx ctx;
  struct sha256_ctx alt_ctx;
  size_t salt_len;
  size_t key_len;
  size_t cnt;
  char *cp;
  unsigned char p_bytes[32];
  unsigned char s_bytes[32];
  /* Default number of rounds.  */
  size_t rounds = ROUNDS_DEFAULT;
  bool rounds_custom = false;

  if (buflen < sha256_hash_length)
    {
      /* Not enough space to store the hashed password (in the worst case).  */
      errno = ERANGE;
      return 0;
    }

  /* Find beginning of salt string.  The prefix should normally always
     be present.  Just in case it is not.  */
  if (strncmp (sha256_salt_prefix, salt, sizeof (sha256_salt_prefix) - 1) == 0)
    /* Skip salt prefix.  */
    salt += sizeof (sha256_salt_prefix) - 1;

  if (strncmp (salt, sha256_rounds_prefix, sizeof (sha256_rounds_prefix) - 1)
      == 0)
    {
      const char *num = salt + sizeof (sha256_rounds_prefix) - 1;
      char *endp;
      unsigned long int srounds = strtoul (num, &endp, 10);
      if (*endp == '$')
        {
          salt = endp + 1;
          rounds = MAX (ROUNDS_MIN, MIN (srounds, ROUNDS_MAX));
          rounds_custom = true;
        }
    }

  salt_len = MIN (strcspn (salt, "$"), SALT_LEN_MAX);
  key_len = strlen (key);

  /* Prepare for the real work.  */
  sha256_init_ctx (&ctx);

  /* Add the key string.  */
  sha256_process_bytes (key, key_len, &ctx);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */
  sha256_process_bytes (salt, salt_len, &ctx);


  /* Compute alternate SHA256 sum with input KEY, SALT, and KEY.  The
     final result will be added to the first context.  */
  sha256_init_ctx (&alt_ctx);

  /* Add key.  */
  sha256_process_bytes (key, key_len, &alt_ctx);

  /* Add salt.  */
  sha256_process_bytes (salt, salt_len, &alt_ctx);

  /* Add key again.  */
  sha256_process_bytes (key, key_len, &alt_ctx);

  /* Now get result of this (32 bytes) and add it to the other
     context.  */
  sha256_finish_ctx (&alt_ctx, alt_result);

  /* Add for any character in the key one byte of the alternate sum.  */
  for (cnt = key_len; cnt > 32; cnt -= 32)
    sha256_process_bytes (alt_result, 32, &ctx);
  sha256_process_bytes (alt_result, cnt, &ctx);

  /* Take the binary representation of the length of the key and for every
     1 add the alternate sum, for every 0 the key.  */
  for (cnt = key_len; cnt > 0; cnt >>= 1)
    if ((cnt & 1) != 0)
      sha256_process_bytes (alt_result, 32, &ctx);
    else
      sha256_process_bytes (key, key_len, &ctx);

  /* Create intermediate result.  */
  sha256_finish_ctx (&ctx, alt_result);

  /* Start computation of P byte sequence.  */
  sha256_init_ctx (&alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < key_len; ++cnt)
    sha256_process_bytes (key, key_len, &alt_ctx);

  /* Finish the digest.  */
  sha256_finish_ctx (&alt_ctx, p_bytes);

  /* Start computation of S byte sequence.  */
  sha256_init_ctx (&alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < (size_t) 16 + (size_t) alt_result[0]; ++cnt)
    sha256_process_bytes (salt, salt_len, &alt_ctx);

  /* Finish the digest.  */
  sha256_finish_ctx (&alt_ctx, s_bytes);

  /* Repeatedly run the collected hash value through SHA256 to burn
     CPU cycles.  */
  for (cnt = 0; cnt < rounds; ++cnt)
    {
      /* New context.  */
      sha256_init_ctx (&ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha256_process_recycled_bytes (p_bytes, key_len, &ctx);
      else
        sha256_process_bytes (alt_result, 32, &ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        sha256_process_recycled_bytes (s_bytes, salt_len, &ctx);

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        sha256_process_recycled_bytes (p_bytes, key_len, &ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha256_process_bytes (alt_result, 32, &ctx);
      else
        sha256_process_recycled_bytes (p_bytes, key_len, &ctx);

      /* Create intermediate result.  */
      sha256_finish_ctx (&ctx, alt_result);
    }

  /* Now we can construct the result string.  It consists of four
     parts, one of which is optional.  We already know that buflen is
     at least sha256_hash_length, therefore none of the string bashing
     below can overflow the buffer. */
  memcpy (buffer, sha256_salt_prefix, sizeof (sha256_salt_prefix) - 1);
  cp = buffer + sizeof (sha256_salt_prefix) - 1;
  buflen -= sizeof (sha256_salt_prefix) - 1;

  if (rounds_custom)
    {
      int n = snprintf (cp, buflen, "%s%zu$",
                        sha256_rounds_prefix, rounds);
      cp += n;
    }

  memcpy (cp, salt, salt_len);
  cp += salt_len;
  *cp++ = '$';

#define b64_from_24bit(B2, B1, B0, N)                                         \
  do {                                                                        \
    unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);                       \
    int n = (N);                                                              \
    while (n-- > 0)                                                           \
      {                                                                       \
        *cp++ = b64t[w & 0x3f];                                               \
        w >>= 6;                                                              \
      }                                                                       \
  } while (0)

  b64_from_24bit (alt_result[0], alt_result[10], alt_result[20], 4);
  b64_from_24bit (alt_result[21], alt_result[1], alt_result[11], 4);
  b64_from_24bit (alt_result[12], alt_result[22], alt_result[2], 4);
  b64_from_24bit (alt_result[3], alt_result[13], alt_result[23], 4);
  b64_from_24bit (alt_result[24], alt_result[4], alt_result[14], 4);
  b64_from_24bit (alt_result[15], alt_result[25], alt_result[5], 4);
  b64_from_24bit (alt_result[6], alt_result[16], alt_result[26], 4);
  b64_from_24bit (alt_result[27], alt_result[7], alt_result[17], 4);
  b64_from_24bit (alt_result[18], alt_result[28], alt_result[8], 4);
  b64_from_24bit (alt_result[9], alt_result[19], alt_result[29], 4);
  b64_from_24bit (0, alt_result[31], alt_result[30], 3);

  *cp = '\0';

  /* Clear the buffer for the intermediate result so that people
     attaching to processes or reading core dumps cannot get any
     information.  We do it in this way to clear correct_words[]
     inside the SHA256 implementation as well.  */
  sha256_init_ctx (&ctx);
  sha256_finish_ctx (&ctx, alt_result);
  memset (temp_result, '\0', sizeof (temp_result));
  memset (p_bytes, '\0', sizeof (p_bytes));
  memset (s_bytes, '\0', sizeof (s_bytes));
  memset (&ctx, '\0', sizeof (ctx));
  memset (&alt_ctx, '\0', sizeof (alt_ctx));

  return buffer;
}

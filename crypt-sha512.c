/* One way encryption based on SHA512 sum.
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

#include "alg-sha512.h"
#include "crypt-private.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

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

static const size_t sha512_hash_length =
  sizeof (sha512_salt_prefix) + sizeof (sha512_rounds_prefix) +
  LENGTH_OF_NUMBER (ROUNDS_MAX) + SALT_LEN_MAX + 1 + 86;

/* Table with characters for base64 transformation.  */
static const char b64t[64] =
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

char *
crypt_sha512_rn (const char *key, const char *salt,
                 char *buffer, size_t buflen)
{
  unsigned char alt_result[64];
  unsigned char temp_result[64];
  struct sha512_ctx ctx;
  struct sha512_ctx alt_ctx;
  size_t salt_len;
  size_t key_len;
  size_t cnt;
  char *cp;
  unsigned char p_bytes[64];
  unsigned char s_bytes[64];
  /* Default number of rounds.  */
  size_t rounds = ROUNDS_DEFAULT;
  bool rounds_custom = false;

  if (buflen < sha512_hash_length)
    {
      /* Not enough space to store the hashed password (in the worst case).  */
      errno = ERANGE;
      return 0;
    }

  /* Find beginning of salt string.  The prefix should normally always
     be present.  Just in case it is not.  */
  if (strncmp (sha512_salt_prefix, salt, sizeof (sha512_salt_prefix) - 1) == 0)
    /* Skip salt prefix.  */
    salt += sizeof (sha512_salt_prefix) - 1;

  if (strncmp (salt, sha512_rounds_prefix, sizeof (sha512_rounds_prefix) - 1)
      == 0)
    {
      const char *num = salt + sizeof (sha512_rounds_prefix) - 1;
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
  sha512_init_ctx (&ctx);

  /* Add the key string.  */
  sha512_process_bytes (key, key_len, &ctx);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */
  sha512_process_bytes (salt, salt_len, &ctx);


  /* Compute alternate SHA512 sum with input KEY, SALT, and KEY.  The
     final result will be added to the first context.  */
  sha512_init_ctx (&alt_ctx);

  /* Add key.  */
  sha512_process_bytes (key, key_len, &alt_ctx);

  /* Add salt.  */
  sha512_process_bytes (salt, salt_len, &alt_ctx);

  /* Add key again.  */
  sha512_process_bytes (key, key_len, &alt_ctx);

  /* Now get result of this (64 bytes) and add it to the other
     context.  */
  sha512_finish_ctx (&alt_ctx, alt_result);

  /* Add for any character in the key one byte of the alternate sum.  */
  for (cnt = key_len; cnt > 64; cnt -= 64)
    sha512_process_bytes (alt_result, 64, &ctx);
  sha512_process_bytes (alt_result, cnt, &ctx);

  /* Take the binary representation of the length of the key and for every
     1 add the alternate sum, for every 0 the key.  */
  for (cnt = key_len; cnt > 0; cnt >>= 1)
    if ((cnt & 1) != 0)
      sha512_process_bytes (alt_result, 64, &ctx);
    else
      sha512_process_bytes (key, key_len, &ctx);

  /* Create intermediate result.  */
  sha512_finish_ctx (&ctx, alt_result);

  /* Start computation of P byte sequence.  */
  sha512_init_ctx (&alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < key_len; ++cnt)
    sha512_process_bytes (key, key_len, &alt_ctx);

  /* Finish the digest.  */
  sha512_finish_ctx (&alt_ctx, p_bytes);

  /* Start computation of S byte sequence.  */
  sha512_init_ctx (&alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < (size_t) 16 + (size_t) alt_result[0]; ++cnt)
    sha512_process_bytes (salt, salt_len, &alt_ctx);

  /* Finish the digest.  */
  sha512_finish_ctx (&alt_ctx, s_bytes);

  /* Repeatedly run the collected hash value through SHA512 to burn
     CPU cycles.  */
  for (cnt = 0; cnt < rounds; ++cnt)
    {
      /* New context.  */
      sha512_init_ctx (&ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha512_process_recycled_bytes (p_bytes, key_len, &ctx);
      else
        sha512_process_bytes (alt_result, 64, &ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        sha512_process_recycled_bytes (s_bytes, salt_len, &ctx);

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        sha512_process_recycled_bytes (p_bytes, key_len, &ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha512_process_bytes (alt_result, 64, &ctx);
      else
        sha512_process_recycled_bytes (p_bytes, key_len, &ctx);

      /* Create intermediate result.  */
      sha512_finish_ctx (&ctx, alt_result);
    }

  /* Now we can construct the result string.  It consists of four
     parts, one of which is optional.  We already know that buflen is
     at least sha512_hash_length, therefore none of the string bashing
     below can overflow the buffer. */

  memcpy (buffer, sha512_salt_prefix, sizeof (sha512_salt_prefix) - 1);
  cp = buffer + sizeof (sha512_salt_prefix) - 1;
  buflen -= sizeof (sha512_salt_prefix) - 1;

  if (rounds_custom)
    {
      int n = snprintf (cp, buflen, "%s%zu$", sha512_rounds_prefix, rounds);
      cp += n;
    }

  memcpy (cp, salt, salt_len);
  cp += salt_len;
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

  b64_from_24bit (alt_result[0], alt_result[21], alt_result[42], 4);
  b64_from_24bit (alt_result[22], alt_result[43], alt_result[1], 4);
  b64_from_24bit (alt_result[44], alt_result[2], alt_result[23], 4);
  b64_from_24bit (alt_result[3], alt_result[24], alt_result[45], 4);
  b64_from_24bit (alt_result[25], alt_result[46], alt_result[4], 4);
  b64_from_24bit (alt_result[47], alt_result[5], alt_result[26], 4);
  b64_from_24bit (alt_result[6], alt_result[27], alt_result[48], 4);
  b64_from_24bit (alt_result[28], alt_result[49], alt_result[7], 4);
  b64_from_24bit (alt_result[50], alt_result[8], alt_result[29], 4);
  b64_from_24bit (alt_result[9], alt_result[30], alt_result[51], 4);
  b64_from_24bit (alt_result[31], alt_result[52], alt_result[10], 4);
  b64_from_24bit (alt_result[53], alt_result[11], alt_result[32], 4);
  b64_from_24bit (alt_result[12], alt_result[33], alt_result[54], 4);
  b64_from_24bit (alt_result[34], alt_result[55], alt_result[13], 4);
  b64_from_24bit (alt_result[56], alt_result[14], alt_result[35], 4);
  b64_from_24bit (alt_result[15], alt_result[36], alt_result[57], 4);
  b64_from_24bit (alt_result[37], alt_result[58], alt_result[16], 4);
  b64_from_24bit (alt_result[59], alt_result[17], alt_result[38], 4);
  b64_from_24bit (alt_result[18], alt_result[39], alt_result[60], 4);
  b64_from_24bit (alt_result[40], alt_result[61], alt_result[19], 4);
  b64_from_24bit (alt_result[62], alt_result[20], alt_result[41], 4);
  b64_from_24bit (0, 0, alt_result[63], 2);

  *cp = '\0';

  /* Clear the buffer for the intermediate result so that people
     attaching to processes or reading core dumps cannot get any
     information.  We do it in this way to clear correct_words[]
     inside the SHA512 implementation as well.  */
  sha512_init_ctx (&ctx);
  sha512_finish_ctx (&ctx, alt_result);
  memset (temp_result, '\0', sizeof (temp_result));
  memset (p_bytes, '\0', sizeof (p_bytes));
  memset (s_bytes, '\0', sizeof (s_bytes));
  memset (&ctx, '\0', sizeof (ctx));
  memset (&alt_ctx, '\0', sizeof (alt_ctx));

  return buffer;
}

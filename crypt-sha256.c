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

#define SHA256_HASH_LENGTH \
  (sizeof (sha256_salt_prefix) + sizeof (sha256_rounds_prefix) + \
   LENGTH_OF_NUMBER (ROUNDS_MAX) + SALT_LEN_MAX + 1 + 43)


/* A sha256_buffer holds the output plus all of the sensitive intermediate
   data.  It may have been allocated by application code, so it may not
   be properly aligned, and besides which SHA256_HASH_LENGTH may be odd, so
   we pad 'ctxbuf' enough to find a properly-aligned sha256_ctx within.  */
struct sha256_buffer
{
  char output[SHA256_HASH_LENGTH];
  uint8_t ctxbuf[sizeof (struct sha256_ctx) + alignof (struct sha256_ctx)];
  uint8_t result[32];
  uint8_t p_bytes[32];
  uint8_t s_bytes[32];
};

static inline struct sha256_ctx *
sha256_get_ctx (struct sha256_buffer *buf)
{
  uintptr_t ctxp = (uintptr_t) &buf->ctxbuf;
  uintptr_t align = alignof (struct sha256_ctx);
  ctxp = (ctxp + align - 1) & ~align;
  return (struct sha256_ctx *)ctxp;
}

static inline void
sha256_wipe_intermediate_data (struct sha256_buffer *buf)
{
  memset (((char *)buf) + offsetof (struct sha256_buffer, ctxbuf),
          0,
          sizeof (struct sha256_buffer) -
          offsetof (struct sha256_buffer, ctxbuf));
}


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
                 char *data, size_t size)
{
  /* Ensure we have enough space for a sha256_buffer in DATA.  */
  if (size < sizeof (struct sha256_buffer))
    {
      errno = ERANGE;
      return 0;
    }

  struct sha256_buffer *buf = (struct sha256_buffer *)data;
  struct sha256_ctx *ctx = sha256_get_ctx (buf);
  uint8_t *result = buf->result;
  uint8_t *p_bytes = buf->p_bytes;
  uint8_t *s_bytes = buf->s_bytes;
  char *cp = buf->output;

  size_t salt_len;
  size_t key_len;
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

  /* Compute alternate SHA256 sum with input KEY, SALT, and KEY.  The
     final result will be added to the first context.  */
  sha256_init_ctx (ctx);

  /* Add key.  */
  sha256_process_bytes (key, key_len, ctx);

  /* Add salt.  */
  sha256_process_bytes (salt, salt_len, ctx);

  /* Add key again.  */
  sha256_process_bytes (key, key_len, ctx);

  /* Now get result of this (32 bytes).  */
  sha256_finish_ctx (ctx, result);

  /* Prepare for the real work.  */
  sha256_init_ctx (ctx);

  /* Add the key string.  */
  sha256_process_bytes (key, key_len, ctx);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */
  sha256_process_bytes (salt, salt_len, ctx);

  /* Add for any character in the key one byte of the alternate sum.  */
  for (cnt = key_len; cnt > 32; cnt -= 32)
    sha256_process_bytes (result, 32, ctx);
  sha256_process_bytes (result, cnt, ctx);

  /* Take the binary representation of the length of the key and for every
     1 add the alternate sum, for every 0 the key.  */
  for (cnt = key_len; cnt > 0; cnt >>= 1)
    if ((cnt & 1) != 0)
      sha256_process_bytes (result, 32, ctx);
    else
      sha256_process_bytes (key, key_len, ctx);

  /* Create intermediate result.  */
  sha256_finish_ctx (ctx, result);

  /* Start computation of P byte sequence.  */
  sha256_init_ctx (ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < key_len; ++cnt)
    sha256_process_bytes (key, key_len, ctx);

  /* Finish the digest.  */
  sha256_finish_ctx (ctx, p_bytes);

  /* Start computation of S byte sequence.  */
  sha256_init_ctx (ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < (size_t) 16 + (size_t) result[0]; ++cnt)
    sha256_process_bytes (salt, salt_len, ctx);

  /* Finish the digest.  */
  sha256_finish_ctx (ctx, s_bytes);

  /* Repeatedly run the collected hash value through SHA256 to burn
     CPU cycles.  */
  for (cnt = 0; cnt < rounds; ++cnt)
    {
      /* New context.  */
      sha256_init_ctx (ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha256_process_recycled_bytes (p_bytes, key_len, ctx);
      else
        sha256_process_bytes (result, 32, ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        sha256_process_recycled_bytes (s_bytes, salt_len, ctx);

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        sha256_process_recycled_bytes (p_bytes, key_len, ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha256_process_bytes (result, 32, ctx);
      else
        sha256_process_recycled_bytes (p_bytes, key_len, ctx);

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

  sha256_wipe_intermediate_data (buf);
  return buf->output;
}

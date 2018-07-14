/* One way encryption based on the SHA256-based Unix crypt implementation.
 *
 * Written by Ulrich Drepper <drepper at redhat.com> in 2007 [1].
 * To the extent possible under law, Ulrich Drepper has waived all
 * copyright and related or neighboring rights to this work.
 *
 * See https://creativecommons.org/publicdomain/zero/1.0/ for further
 * details.
 *
 * This file is an except from [2], lines 648 up to 909.
 *
 * [1]  https://www.akkadia.org/drepper/sha-crypt.html
 * [2]  https://www.akkadia.org/drepper/SHA-crypt.txt
 */

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

static char *
sha256_crypt_r (const char *key, const char *salt, char *buffer, int buflen)
{
  unsigned char alt_result[32]
  __attribute__ ((__aligned__ (__alignof__ (uint32_t))));
  unsigned char temp_result[32]
  __attribute__ ((__aligned__ (__alignof__ (uint32_t))));
  struct sha256_ctx ctx;
  struct sha256_ctx alt_ctx;
  size_t salt_len;
  size_t key_len;
  size_t cnt;
  char *cp;
  char *copied_key = NULL;
  char *copied_salt = NULL;
  char *p_bytes;
  char *s_bytes;
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

  if ((key - (char *) 0) % __alignof__ (uint32_t) != 0)
    {
      char *tmp = (char *) alloca (key_len + __alignof__ (uint32_t));
      key = copied_key =
              memcpy (tmp + __alignof__ (uint32_t)
                      - (tmp - (char *) 0) % __alignof__ (uint32_t),
                      key, key_len);
    }

  if ((salt - (char *) 0) % __alignof__ (uint32_t) != 0)
    {
      char *tmp = (char *) alloca (salt_len + __alignof__ (uint32_t));
      salt = copied_salt =
               memcpy (tmp + __alignof__ (uint32_t)
                       - (tmp - (char *) 0) % __alignof__ (uint32_t),
                       salt, salt_len);
    }

  /* Prepare for the real work.  */
  sha256_init_ctx (&ctx);

  /* Add the key string.  */
  sha256_process_bytes (key, key_len, &ctx);

  /* The last part is the salt string.  This must be at most 16
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
  sha256_finish_ctx (&alt_ctx, temp_result);

  /* Create byte sequence P.  */
  cp = p_bytes = alloca (key_len);
  for (cnt = key_len; cnt >= 32; cnt -= 32)
    cp = mempcpy (cp, temp_result, 32);
  memcpy (cp, temp_result, cnt);

  /* Start computation of S byte sequence.  */
  sha256_init_ctx (&alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt)
    sha256_process_bytes (salt, salt_len, &alt_ctx);

  /* Finish the digest.  */
  sha256_finish_ctx (&alt_ctx, temp_result);

  /* Create byte sequence S.  */
  cp = s_bytes = alloca (salt_len);
  for (cnt = salt_len; cnt >= 32; cnt -= 32)
    cp = mempcpy (cp, temp_result, 32);
  memcpy (cp, temp_result, cnt);

  /* Repeatedly run the collected hash value through SHA256 to burn
     CPU cycles.  */
  for (cnt = 0; cnt < rounds; ++cnt)
    {
      /* New context.  */
      sha256_init_ctx (&ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha256_process_bytes (p_bytes, key_len, &ctx);
      else
        sha256_process_bytes (alt_result, 32, &ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        sha256_process_bytes (s_bytes, salt_len, &ctx);

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        sha256_process_bytes (p_bytes, key_len, &ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha256_process_bytes (alt_result, 32, &ctx);
      else
        sha256_process_bytes (p_bytes, key_len, &ctx);

      /* Create intermediate result.  */
      sha256_finish_ctx (&ctx, alt_result);
    }

  /* Now we can construct the result string.  It consists of three
     parts.  */
  cp = stpncpy (buffer, sha256_salt_prefix, MAX (0, buflen));
  buflen -= sizeof (sha256_salt_prefix) - 1;

  if (rounds_custom)
    {
      int n = snprintf (cp, MAX (0, buflen), "%s%zu$",
                        sha256_rounds_prefix, rounds);
      cp += n;
      buflen -= n;
    }

  cp = stpncpy (cp, salt, MIN ((size_t) MAX (0, buflen), salt_len));
  buflen -= MIN ((size_t) MAX (0, buflen), salt_len);

  if (buflen > 0)
    {
      *cp++ = '$';
      --buflen;
    }

#define b64_from_24bit(B2, B1, B0, N)					      \
  do {									      \
    unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);			      \
    int n = (N);							      \
    while (n-- > 0 && buflen > 0)					      \
      {									      \
	*cp++ = b64t[w & 0x3f];						      \
	--buflen;							      \
	w >>= 6;							      \
      }									      \
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
  if (buflen <= 0)
    {
      errno = ERANGE;
      buffer = NULL;
    }
  else
    *cp = '\0';		/* Terminate the string.  */

  /* Clear the buffer for the intermediate result so that people
     attaching to processes or reading core dumps cannot get any
     information.  We do it in this way to clear correct_words[]
     inside the SHA256 implementation as well.  */
  sha256_init_ctx (&ctx);
  sha256_finish_ctx (&ctx, alt_result);
  memset (temp_result, '\0', sizeof (temp_result));
  memset (p_bytes, '\0', key_len);
  memset (s_bytes, '\0', salt_len);
  memset (&ctx, '\0', sizeof (ctx));
  memset (&alt_ctx, '\0', sizeof (alt_ctx));
  if (copied_key != NULL)
    memset (copied_key, '\0', key_len);
  if (copied_salt != NULL)
    memset (copied_salt, '\0', salt_len);

  return buffer;
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

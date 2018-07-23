/* One way encryption based on MD5 sum.
   Compatible with the behavior of MD5 crypt introduced in FreeBSD 2.0.

   Copyright (C) 1996-2017 Free Software Foundation, Inc.

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
#include "alg-md5.h"

#include <errno.h>

#if INCLUDE_md5

/* Define our magic string to mark salt for MD5 "encryption"
   replacement.  This is meant to be the same as for other MD5 based
   encryption implementations.  */
static const char md5_salt_prefix[] = "$1$";

/* Table with characters for base64 transformation.  */
static const char b64t[] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* The maximum length of an MD5 salt string (just the actual salt, not
   the entire prefix).  */
#define SALT_LEN_MAX 8

/* The length of an MD5-hashed password string, including the
   terminating NUL character.  Prefix (including its NUL) + 8 bytes of
   salt + separator + 22 bytes of hashed password.  */
#define MD5_HASH_LENGTH \
  (sizeof (md5_salt_prefix) + SALT_LEN_MAX + 1 + 22)

static_assert (MD5_HASH_LENGTH <= CRYPT_OUTPUT_SIZE,
               "CRYPT_OUTPUT_SIZE is too small for MD5");

/* An md5_buffer holds all of the sensitive intermediate data.  */
struct md5_buffer
{
  struct md5_ctx ctx;
  uint8_t result[16];
};

static_assert (sizeof (struct md5_buffer) <= ALG_SPECIFIC_SIZE,
               "ALG_SPECIFIC_SIZE is too small for MD5");


/* This entry point is equivalent to the `crypt' function in Unix
   libcs.  */
void
crypt_md5_rn (const char *phrase, size_t phr_size,
              const char *setting, size_t ARG_UNUSED (set_size),
              uint8_t *output, size_t out_size,
              void *scratch, size_t scr_size)
{
  /* This shouldn't ever happen, but...  */
  if (out_size < MD5_HASH_LENGTH || scr_size < sizeof (struct md5_buffer))
    {
      errno = ERANGE;
      return;
    }

  struct md5_buffer *buf = scratch;
  struct md5_ctx *ctx = &buf->ctx;
  uint8_t *result = buf->result;
  char *cp = (char *)output;
  const char *salt = setting;

  size_t salt_size;
  size_t cnt;

  /* Find beginning of salt string.  The prefix should normally always
     be present.  Just in case it is not.  */
  if (strncmp (md5_salt_prefix, salt, sizeof (md5_salt_prefix) - 1) == 0)
    /* Skip salt prefix.  */
    salt += sizeof (md5_salt_prefix) - 1;

  salt_size = strspn (salt, b64t);
  if (salt[salt_size] && salt[salt_size] != '$')
    {
      errno = EINVAL;
      return;
    }
  if (salt_size > SALT_LEN_MAX)
    salt_size = SALT_LEN_MAX;

  /* Compute alternate MD5 sum with input PHRASE, SALT, and PHRASE.  The
     final result will be added to the first context.  */
  md5_init_ctx (ctx);

  /* Add phrase.  */
  md5_process_bytes (phrase, phr_size, ctx);

  /* Add salt.  */
  md5_process_bytes (salt, salt_size, ctx);

  /* Add phrase again.  */
  md5_process_bytes (phrase, phr_size, ctx);

  /* Now get result of this (16 bytes).  */
  md5_finish_ctx (ctx, result);

  /* Prepare for the real work.  */
  md5_init_ctx (ctx);

  /* Add the phrase string.  */
  md5_process_bytes (phrase, phr_size, ctx);

  /* Because the SALT argument need not always have the salt prefix we
     add it separately.  */
  md5_process_bytes (md5_salt_prefix, sizeof (md5_salt_prefix) - 1, ctx);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */
  md5_process_bytes (salt, salt_size, ctx);


  /* Add for any character in the phrase one byte of the alternate sum.  */
  for (cnt = phr_size; cnt > 16; cnt -= 16)
    md5_process_bytes (result, 16, ctx);
  md5_process_bytes (result, cnt, ctx);

  /* For the following code we need a NUL byte.  */
  *result = '\0';

  /* The original implementation now does something weird: for every 1
     bit in the phrase the first 0 is added to the buffer, for every 0
     bit the first character of the phrase.  This does not seem to be
     what was intended but we have to follow this to be compatible.  */
  for (cnt = phr_size; cnt > 0; cnt >>= 1)
    md5_process_bytes ((cnt & 1) != 0 ? (const char *) result : phrase, 1,
                       ctx);

  /* Create intermediate result.  */
  md5_finish_ctx (ctx, result);

  /* Now comes another weirdness.  In fear of password crackers here
     comes a quite long loop which just processes the output of the
     previous round again.  We cannot ignore this here.  */
  for (cnt = 0; cnt < 1000; ++cnt)
    {
      /* New context.  */
      md5_init_ctx (ctx);

      /* Add phrase or last result.  */
      if ((cnt & 1) != 0)
        md5_process_bytes (phrase, phr_size, ctx);
      else
        md5_process_bytes (result, 16, ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        md5_process_bytes (salt, salt_size, ctx);

      /* Add phrase for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        md5_process_bytes (phrase, phr_size, ctx);

      /* Add phrase or last result.  */
      if ((cnt & 1) != 0)
        md5_process_bytes (result, 16, ctx);
      else
        md5_process_bytes (phrase, phr_size, ctx);

      /* Create intermediate result.  */
      md5_finish_ctx (ctx, result);
    }

  /* Now we can construct the result string.  It consists of three
     parts.  We already know that there is enough space at CP.  */
  memcpy (cp, md5_salt_prefix, sizeof (md5_salt_prefix) - 1);
  cp += sizeof (md5_salt_prefix) - 1;

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


  b64_from_24bit (result[0], result[6], result[12], 4);
  b64_from_24bit (result[1], result[7], result[13], 4);
  b64_from_24bit (result[2], result[8], result[14], 4);
  b64_from_24bit (result[3], result[9], result[15], 4);
  b64_from_24bit (result[4], result[10], result[5], 4);
  b64_from_24bit (0, 0, result[11], 2);

  *cp = '\0';
}

void
gensalt_md5_rn (unsigned long count,
                const uint8_t *rbytes, size_t nrbytes,
                uint8_t *output, size_t output_size)
{
  gensalt_sha_rn ('1', 8, 1000, 1000, 1000,
                  count, rbytes, nrbytes, output, output_size);
}

#endif

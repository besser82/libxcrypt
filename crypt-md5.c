/* One way encryption based on MD5 sum.
   Compatible with the behavior of MD5 crypt introduced in FreeBSD 2.0.
   Copyright (C) 1996, 1997, 1999, 2000, 2001, 2002, 2004
   Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.

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

#include "alg-md5.h"
#include "crypt-private.h"

#include <errno.h>
#include <string.h>


/* Define our magic string to mark salt for MD5 "encryption"
   replacement.  This is meant to be the same as for other MD5 based
   encryption implementations.  */
static const char md5_salt_prefix[] = "$1$";

/* Table with characters for base64 transformation.  */
static const char b64t[64] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* The maximum length of an MD5 salt string (just the actual salt, not
   the entire prefix).  */
#define SALT_LEN_MAX 8

/* The length of an MD5-hashed password string, including the
   terminating NUL character.  Prefix (including its NUL) + 8 bytes of
   salt + separator + 22 bytes of hashed password.  */
#define MD5_HASH_LENGTH \
  (sizeof (md5_salt_prefix) + SALT_LEN_MAX + 1 + 22)

/* An md5_buffer holds the output plus all of the sensitive intermediate
   data.  It may have been allocated by application code, so it may not
   be properly aligned, and besides which MD5_HASH_LENGTH may be odd, so
   we pad 'ctxbuf' and 'altctxbuf' enough to find a properly-aligned
   md5_ctx within.  */
struct md5_buffer
{
  char output[MD5_HASH_LENGTH];
  uint8_t ctxbuf[sizeof (struct md5_ctx) + alignof (struct md5_ctx)];
  uint8_t altctxbuf[sizeof (struct md5_ctx) + alignof (struct md5_ctx)];
  uint8_t alt_result[16];
};

static inline struct md5_ctx *
md5_get_ctx (struct md5_buffer *buf)
{
  uintptr_t ctxp = (uintptr_t) &buf->ctxbuf;
  uintptr_t align = alignof (struct md5_ctx);
  ctxp = (ctxp + align - 1) & ~align;
  return (struct md5_ctx *)ctxp;
}

static inline struct md5_ctx *
md5_get_alt_ctx (struct md5_buffer *buf)
{
  uintptr_t ctxp = (uintptr_t) &buf->altctxbuf;
  uintptr_t align = alignof (struct md5_ctx);
  ctxp = (ctxp + align - 1) & ~align;
  return (struct md5_ctx *)ctxp;
}

static inline void
md5_wipe_intermediate_data (struct md5_buffer *buf)
{
  memset (((char *)buf) + offsetof (struct md5_buffer, ctxbuf),
          0,
          sizeof (struct md5_buffer) - offsetof (struct md5_buffer, ctxbuf));
}

/* This entry point is equivalent to the `crypt' function in Unix
   libcs.  */
char *
crypt_md5_rn (const char *key, const char *salt,
              char *data, size_t size)
{
  /* Ensure we have enough space for an md5_buffer in DATA.  */
  if (size < sizeof (struct md5_buffer))
    {
      errno = ERANGE;
      return 0;
    }

  struct md5_buffer *buf = (struct md5_buffer *)data;
  struct md5_ctx *ctx = md5_get_ctx (buf);
  struct md5_ctx *alt_ctx = md5_get_alt_ctx (buf);
  uint8_t *alt_result = buf->alt_result;
  char *cp = buf->output;
  size_t salt_len;
  size_t key_len;
  size_t cnt;

  /* Find beginning of salt string.  The prefix should normally always
     be present.  Just in case it is not.  */
  if (strncmp (md5_salt_prefix, salt, sizeof (md5_salt_prefix) - 1) == 0)
    /* Skip salt prefix.  */
    salt += sizeof (md5_salt_prefix) - 1;

  salt_len = strcspn (salt, "$");
  if (salt_len > SALT_LEN_MAX)
    salt_len = SALT_LEN_MAX;
  key_len = strlen (key);

  /* Prepare for the real work.  */
  md5_init_ctx (ctx);

  /* Add the key string.  */
  md5_process_bytes (key, key_len, ctx);

  /* Because the SALT argument need not always have the salt prefix we
     add it separately.  */
  md5_process_bytes (md5_salt_prefix, sizeof (md5_salt_prefix) - 1, ctx);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */
  md5_process_bytes (salt, salt_len, ctx);


  /* Compute alternate MD5 sum with input KEY, SALT, and KEY.  The
     final result will be added to the first context.  */
  md5_init_ctx (alt_ctx);

  /* Add key.  */
  md5_process_bytes (key, key_len, alt_ctx);

  /* Add salt.  */
  md5_process_bytes (salt, salt_len, alt_ctx);

  /* Add key again.  */
  md5_process_bytes (key, key_len, alt_ctx);

  /* Now get result of this (16 bytes) and add it to the other
     context.  */
  md5_finish_ctx (alt_ctx, alt_result);

  /* Add for any character in the key one byte of the alternate sum.  */
  for (cnt = key_len; cnt > 16; cnt -= 16)
    md5_process_bytes (alt_result, 16, ctx);
  md5_process_bytes (alt_result, cnt, ctx);

  /* For the following code we need a NUL byte.  */
  *alt_result = '\0';

  /* The original implementation now does something weird: for every 1
     bit in the key the first 0 is added to the buffer, for every 0
     bit the first character of the key.  This does not seem to be
     what was intended but we have to follow this to be compatible.  */
  for (cnt = key_len; cnt > 0; cnt >>= 1)
    md5_process_bytes ((cnt & 1) != 0 ? (const char *) alt_result : key, 1,
                         ctx);

  /* Create intermediate result.  */
  md5_finish_ctx (ctx, alt_result);

  /* Now comes another weirdness.  In fear of password crackers here
     comes a quite long loop which just processes the output of the
     previous round again.  We cannot ignore this here.  */
  for (cnt = 0; cnt < 1000; ++cnt)
    {
      /* New context.  */
      md5_init_ctx (ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        md5_process_bytes (key, key_len, ctx);
      else
        md5_process_bytes (alt_result, 16, ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        md5_process_bytes (salt, salt_len, ctx);

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        md5_process_bytes (key, key_len, ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        md5_process_bytes (alt_result, 16, ctx);
      else
        md5_process_bytes (key, key_len, ctx);

      /* Create intermediate result.  */
      md5_finish_ctx (ctx, alt_result);
    }

  /* Now we can construct the result string.  It consists of three
     parts.  We already know that there is enough space at CP.  */
  memcpy (cp, md5_salt_prefix, sizeof (md5_salt_prefix) - 1);
  cp += sizeof (md5_salt_prefix) - 1;

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


  b64_from_24bit (alt_result[0], alt_result[6], alt_result[12], 4);
  b64_from_24bit (alt_result[1], alt_result[7], alt_result[13], 4);
  b64_from_24bit (alt_result[2], alt_result[8], alt_result[14], 4);
  b64_from_24bit (alt_result[3], alt_result[9], alt_result[15], 4);
  b64_from_24bit (alt_result[4], alt_result[10], alt_result[5], 4);
  b64_from_24bit (0, 0, alt_result[11], 2);

  *cp = '\0';

  md5_wipe_intermediate_data (buf);
  return buf->output;
}

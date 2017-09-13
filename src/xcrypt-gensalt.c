/*
 * Written by Solar Designer and placed in the public domain.
 * See bcrypt.c for more information.
 *
 * This file contains salt generation functions for the traditional and
 * other common crypt(3) algorithms, except for bcrypt which is defined
 * entirely in bcrypt.c.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "xcrypt-private.h"

static const unsigned char _xcrypt_itoa64[64 + 1] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

char *
_xcrypt_gensalt_traditional_rn (unsigned long count,
                                const char *input, int size, char *output,
                                int output_size)
{
  if (size < 2 || output_size < 2 + 1 || (count && count != 25))
    {
      if (output_size > 0)
        output[0] = '\0';
      errno = ((output_size < 2 + 1) ? ERANGE : EINVAL);
      return NULL;
    }

  output[0] = _xcrypt_itoa64[(unsigned int) input[0] & 0x3f];
  output[1] = _xcrypt_itoa64[(unsigned int) input[1] & 0x3f];
  output[2] = '\0';

  return output;
}

char *
_xcrypt_gensalt_extended_rn (unsigned long count,
                             const char *input, int size, char *output,
                             int output_size)
{
  unsigned long value;

/* Even iteration counts make it easier to detect weak DES keys from a look
 * at the hash, so they should be avoided */
  if (size < 3 || output_size < 1 + 4 + 4 + 1 ||
      (count && (count > 0xffffff || !(count & 1))))
    {
      if (output_size > 0)
        output[0] = '\0';
      errno = ((output_size < 1 + 4 + 4 + 1) ? ERANGE : EINVAL);
      return NULL;
    }

  if (!count)
    count = 725;

  output[0] = '_';
  output[1] = _xcrypt_itoa64[count & 0x3f];
  output[2] = _xcrypt_itoa64[(count >> 6) & 0x3f];
  output[3] = _xcrypt_itoa64[(count >> 12) & 0x3f];
  output[4] = _xcrypt_itoa64[(count >> 18) & 0x3f];
  value = (unsigned long) (unsigned char) input[0] |
    ((unsigned long) (unsigned char) input[1] << 8) |
    ((unsigned long) (unsigned char) input[2] << 16);
  output[5] = _xcrypt_itoa64[value & 0x3f];
  output[6] = _xcrypt_itoa64[(value >> 6) & 0x3f];
  output[7] = _xcrypt_itoa64[(value >> 12) & 0x3f];
  output[8] = _xcrypt_itoa64[(value >> 18) & 0x3f];
  output[9] = '\0';

  return output;
}

char *
_xcrypt_gensalt_md5_rn (unsigned long count __attribute__ ((unused)),
                        const char *input, int size,
                        char *output, int output_size)
{
  unsigned long value;

  if (size < 3 || output_size < 3 + 4 + 1)
    {
      if (output_size > 0)
        output[0] = '\0';
      errno = ERANGE;
      return NULL;
    }

  output[0] = '$';
  output[1] = '1';
  output[2] = '$';
  value = (unsigned long) (unsigned char) input[0] |
    ((unsigned long) (unsigned char) input[1] << 8) |
    ((unsigned long) (unsigned char) input[2] << 16);
  output[3] = _xcrypt_itoa64[value & 0x3f];
  output[4] = _xcrypt_itoa64[(value >> 6) & 0x3f];
  output[5] = _xcrypt_itoa64[(value >> 12) & 0x3f];
  output[6] = _xcrypt_itoa64[(value >> 18) & 0x3f];
  output[7] = '\0';

  if (size >= 6 && output_size >= 3 + 4 + 4 + 1)
    {
      value = (unsigned long) (unsigned char) input[3] |
        ((unsigned long) (unsigned char) input[4] << 8) |
        ((unsigned long) (unsigned char) input[5] << 16);
      output[7] = _xcrypt_itoa64[value & 0x3f];
      output[8] = _xcrypt_itoa64[(value >> 6) & 0x3f];
      output[9] = _xcrypt_itoa64[(value >> 12) & 0x3f];
      output[10] = _xcrypt_itoa64[(value >> 18) & 0x3f];
      output[11] = '\0';
    }

  return output;
}

char *
_xcrypt_gensalt_sha256_rn (unsigned long count, const char *input, int size,
                           char *output, int output_size)
{
  unsigned long value;
  char *buf;
  char buf2[12];

  if (count > 0)
    {
      if (asprintf (&buf, "$5$rounds=%ld$", count) < 0)
        {
          if (output_size > 0)
            output[0] = '\0';
          errno = ENOMEM;
          return NULL;
        }
    }
  else
    {
      if (asprintf (&buf, "$5$") < 0)
        {
          if (output_size > 0)
            output[0] = '\0';
          errno = ENOMEM;
          return NULL;
        }
    }

  if (size < 3 || output_size < (int) strlen (buf) + 4 + 1)
    {
      free (buf);
      if (output_size > 0)
        output[0] = '\0';
      errno = ERANGE;
      return NULL;
    }

  value = (unsigned long) (unsigned char) input[0] |
    ((unsigned long) (unsigned char) input[1] << 8) |
    ((unsigned long) (unsigned char) input[2] << 16);
  buf2[0] = _xcrypt_itoa64[value & 0x3f];
  buf2[1] = _xcrypt_itoa64[(value >> 6) & 0x3f];
  buf2[2] = _xcrypt_itoa64[(value >> 12) & 0x3f];
  buf2[3] = _xcrypt_itoa64[(value >> 18) & 0x3f];
  buf2[4] = '\0';

  if (size >= 6 && output_size >= (int) strlen (buf) + 4 + 4 + 1)
    {
      value = (unsigned long) (unsigned char) input[3] |
        ((unsigned long) (unsigned char) input[4] << 8) |
        ((unsigned long) (unsigned char) input[5] << 16);
      buf2[4] = _xcrypt_itoa64[value & 0x3f];
      buf2[5] = _xcrypt_itoa64[(value >> 6) & 0x3f];
      buf2[6] = _xcrypt_itoa64[(value >> 12) & 0x3f];
      buf2[7] = _xcrypt_itoa64[(value >> 18) & 0x3f];
      buf2[8] = '\0';
    }

  snprintf (output, output_size, "%s%s", buf, buf2);
  free (buf);

  return output;
}

char *
_xcrypt_gensalt_sha512_rn (unsigned long count, const char *input, int size,
                           char *output, int output_size)
{
  unsigned long value;
  char *buf;
  char buf2[12];

  if (count > 0)
    {
      if (asprintf (&buf, "$6$rounds=%ld$", count) < 0)
        {
          if (output_size > 0)
            output[0] = '\0';
          errno = ENOMEM;
          return NULL;
        }
    }
  else
    {
      if (asprintf (&buf, "$6$") < 0)
        {
          if (output_size > 0)
            output[0] = '\0';
          errno = ENOMEM;
          return NULL;
        }
    }

  if (size < 3 || output_size < (int) strlen (buf) + 4 + 1)
    {
      free (buf);
      if (output_size > 0)
        output[0] = '\0';
      errno = ERANGE;
      return NULL;
    }

  value = (unsigned long) (unsigned char) input[0] |
    ((unsigned long) (unsigned char) input[1] << 8) |
    ((unsigned long) (unsigned char) input[2] << 16);
  buf2[0] = _xcrypt_itoa64[value & 0x3f];
  buf2[1] = _xcrypt_itoa64[(value >> 6) & 0x3f];
  buf2[2] = _xcrypt_itoa64[(value >> 12) & 0x3f];
  buf2[3] = _xcrypt_itoa64[(value >> 18) & 0x3f];
  buf2[4] = '\0';

  if (size >= 6 && output_size >= (int) strlen (buf) + 4 + 4 + 1)
    {
      value = (unsigned long) (unsigned char) input[3] |
        ((unsigned long) (unsigned char) input[4] << 8) |
        ((unsigned long) (unsigned char) input[5] << 16);
      buf2[4] = _xcrypt_itoa64[value & 0x3f];
      buf2[5] = _xcrypt_itoa64[(value >> 6) & 0x3f];
      buf2[6] = _xcrypt_itoa64[(value >> 12) & 0x3f];
      buf2[7] = _xcrypt_itoa64[(value >> 18) & 0x3f];
      buf2[8] = '\0';
    }

  snprintf (output, output_size, "%s%s", buf, buf2);
  free (buf);

  return output;
}

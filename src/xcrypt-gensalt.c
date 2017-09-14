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

static char *
_xcrypt_gensalt_sha_rn (char tag, unsigned long count,
                        const char *input, int size,
                        char *output, int output_size)
{
  unsigned long value;
  char raw_salt[9];
  int written;

  if (output_size < 1)
    {
      errno = ERANGE;
      return NULL;
    }
  if (output_size < 7)
    {
      output[0] = '\0';
      errno = ERANGE;
      return NULL;
    }

  value = (unsigned long) (unsigned char) input[0] |
    ((unsigned long) (unsigned char) input[1] << 8) |
    ((unsigned long) (unsigned char) input[2] << 16);
  raw_salt[0] = _xcrypt_itoa64[value & 0x3f];
  raw_salt[1] = _xcrypt_itoa64[(value >> 6) & 0x3f];
  raw_salt[2] = _xcrypt_itoa64[(value >> 12) & 0x3f];
  raw_salt[3] = _xcrypt_itoa64[(value >> 18) & 0x3f];
  raw_salt[4] = '\0';

  if (size >= 6)
    {
      value = (unsigned long) (unsigned char) input[3] |
        ((unsigned long) (unsigned char) input[4] << 8) |
        ((unsigned long) (unsigned char) input[5] << 16);
      raw_salt[4] = _xcrypt_itoa64[value & 0x3f];
      raw_salt[5] = _xcrypt_itoa64[(value >> 6) & 0x3f];
      raw_salt[6] = _xcrypt_itoa64[(value >> 12) & 0x3f];
      raw_salt[7] = _xcrypt_itoa64[(value >> 18) & 0x3f];
      raw_salt[8] = '\0';
    }

  if (count > 0)
    {
      written = snprintf (output, output_size, "$%c$rounds=%ld$%s",
                          tag, count, raw_salt);
      if (written > 0 && written <= output_size)
        return output;

      if (raw_salt[4] != '\0')
        {
          /* The output didn't fit.  Try truncating the salt to four
             characters.  */
          raw_salt[4] = '\0';
          written = snprintf (output, output_size, "$%c$rounds=%ld$%s",
                              tag, count, raw_salt);
          if (written > 0 && written <= output_size)
            return output;
        }
    }
  else
    {
      written = snprintf (output, output_size, "$%c$%s", tag, raw_salt);
      if (written > 0 && written <= output_size)
        return output;

      if (raw_salt[4] != '\0')
        {
          /* The output didn't fit.  Try truncating the salt to four
             characters.  */
          raw_salt[4] = '\0';
          written = snprintf (output, output_size, "$%c$%s", tag, raw_salt);
          if (written > 0 && written <= output_size)
            return output;
        }
    }

  output[0] = '\0';
  errno = ERANGE;
  return NULL;
}

char *
_xcrypt_gensalt_sha256_rn (unsigned long count, const char *input, int size,
                           char *output, int output_size)
{
  return _xcrypt_gensalt_sha_rn ('5', count, input, size, output, output_size);
}

char *
_xcrypt_gensalt_sha512_rn (unsigned long count, const char *input, int size,
                           char *output, int output_size)
{
  return _xcrypt_gensalt_sha_rn ('6', count, input, size, output, output_size);
}

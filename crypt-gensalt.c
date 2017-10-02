/*
 * Written by Solar Designer and placed in the public domain.
 * See bcrypt.c for more information.
 *
 * This file contains salt generation functions for the traditional and
 * other common crypt(3) algorithms, except for bcrypt which is defined
 * entirely in bcrypt.c.
 */

#include "crypt-port.h"
#include "crypt-private.h"

#include <errno.h>
#include <stdio.h>

static const unsigned char _xcrypt_itoa64[64 + 1] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#if ENABLE_WEAK_HASHES
uint8_t *
gensalt_des_trd_rn (unsigned long count,
                    const uint8_t *rbytes, size_t nrbytes,
                    uint8_t *output, size_t output_size)
{
  if (output_size < 3)
    {
      errno = ERANGE;
      return NULL;
    }

  if (nrbytes < 2 || (count != 0 && count != 25))
    {
      errno = EINVAL;
      return NULL;
    }

  output[0] = _xcrypt_itoa64[(unsigned int) rbytes[0] & 0x3f];
  output[1] = _xcrypt_itoa64[(unsigned int) rbytes[1] & 0x3f];
  output[2] = '\0';

  return output;
}

uint8_t *
gensalt_des_xbsd_rn (unsigned long count,
                    const uint8_t *rbytes, size_t nrbytes,
                    uint8_t *output, size_t output_size)
{
  if (output_size < 1 + 4 + 4 + 1)
    {
      errno = ERANGE;
      return NULL;
    }

  if (count == 0)
    count = 725;

  /* Even iteration counts make it easier to detect weak DES keys from a look
     at the hash, so they should be avoided.  */
  if (nrbytes < 3 || count > 0xffffff || count % 2 == 0)
    {
      errno = EINVAL;
      return NULL;
    }

  unsigned long value =
    ((unsigned long) (unsigned char) rbytes[0] <<  0) |
    ((unsigned long) (unsigned char) rbytes[1] <<  8) |
    ((unsigned long) (unsigned char) rbytes[2] << 16);

  output[0] = '_';

  output[1] = _xcrypt_itoa64[(count >>  0) & 0x3f];
  output[2] = _xcrypt_itoa64[(count >>  6) & 0x3f];
  output[3] = _xcrypt_itoa64[(count >> 12) & 0x3f];
  output[4] = _xcrypt_itoa64[(count >> 18) & 0x3f];

  output[5] = _xcrypt_itoa64[(value >>  0) & 0x3f];
  output[6] = _xcrypt_itoa64[(value >>  6) & 0x3f];
  output[7] = _xcrypt_itoa64[(value >> 12) & 0x3f];
  output[8] = _xcrypt_itoa64[(value >> 18) & 0x3f];

  output[9] = '\0';

  return output;
}

uint8_t *
gensalt_md5_rn (unsigned long count,
                const uint8_t *rbytes, size_t nrbytes,
                uint8_t *output, size_t output_size)
{
  unsigned long value;

  if (output_size < 3 + 4 + 1)
    {
      errno = ERANGE;
      return NULL;
    }

  if (nrbytes < 3 || (count != 0 && count != 1000))
    {
      errno = EINVAL;
      return NULL;
    }

  output[0] = '$';
  output[1] = '1';
  output[2] = '$';

  value = (unsigned long) (unsigned char) rbytes[0] |
    ((unsigned long) (unsigned char) rbytes[1] << 8) |
    ((unsigned long) (unsigned char) rbytes[2] << 16);
  output[3] = _xcrypt_itoa64[value & 0x3f];
  output[4] = _xcrypt_itoa64[(value >> 6) & 0x3f];
  output[5] = _xcrypt_itoa64[(value >> 12) & 0x3f];
  output[6] = _xcrypt_itoa64[(value >> 18) & 0x3f];
  output[7] = '\0';

  if (nrbytes >= 6 && output_size >= 3 + 4 + 4 + 1)
    {
      value = (unsigned long) (unsigned char) rbytes[3] |
        ((unsigned long) (unsigned char) rbytes[4] << 8) |
        ((unsigned long) (unsigned char) rbytes[5] << 16);
      output[7] = _xcrypt_itoa64[value & 0x3f];
      output[8] = _xcrypt_itoa64[(value >> 6) & 0x3f];
      output[9] = _xcrypt_itoa64[(value >> 12) & 0x3f];
      output[10] = _xcrypt_itoa64[(value >> 18) & 0x3f];
      output[11] = '\0';
    }

  return output;
}
#endif

static uint8_t *
gensalt_sha_rn (char tag, unsigned long count,
                const uint8_t *rbytes, size_t nrbytes,
                uint8_t *output, size_t output_size)
{
  unsigned long value;
  unsigned char raw_salt[9];
  int written;

  if (output_size < 3 + 4 + 1)
    {
      errno = ERANGE;
      return NULL;
    }

  if (nrbytes < 3 || count > 999999999)
    {
      errno = EINVAL;
      return NULL;
    }

  value = (unsigned long) (unsigned char) rbytes[0] |
    ((unsigned long) (unsigned char) rbytes[1] << 8) |
    ((unsigned long) (unsigned char) rbytes[2] << 16);
  raw_salt[0] = _xcrypt_itoa64[value & 0x3f];
  raw_salt[1] = _xcrypt_itoa64[(value >> 6) & 0x3f];
  raw_salt[2] = _xcrypt_itoa64[(value >> 12) & 0x3f];
  raw_salt[3] = _xcrypt_itoa64[(value >> 18) & 0x3f];
  raw_salt[4] = '\0';

  if (nrbytes >= 6)
    {
      value = (unsigned long) (unsigned char) rbytes[3] |
        ((unsigned long) (unsigned char) rbytes[4] << 8) |
        ((unsigned long) (unsigned char) rbytes[5] << 16);
      raw_salt[4] = _xcrypt_itoa64[value & 0x3f];
      raw_salt[5] = _xcrypt_itoa64[(value >> 6) & 0x3f];
      raw_salt[6] = _xcrypt_itoa64[(value >> 12) & 0x3f];
      raw_salt[7] = _xcrypt_itoa64[(value >> 18) & 0x3f];
      raw_salt[8] = '\0';
    }

  if (count > 0)
    {
      written = snprintf ((char *)output, (size_t)output_size,
                          "$%c$rounds=%lu$%s",
                          tag, count, raw_salt);
      if (written > 0 && (size_t)written <= output_size)
        return output;

      if (raw_salt[4] != '\0')
        {
          /* The output didn't fit.  Try truncating the salt to four
             characters.  */
          raw_salt[4] = '\0';
          written = snprintf ((char *)output, (size_t)output_size,
                              "$%c$rounds=%lu$%s",
                              tag, count, raw_salt);
          if (written > 0 && (size_t)written <= output_size)
            return output;
        }
    }
  else
    {
      written = snprintf ((char *)output, (size_t)output_size,
                          "$%c$%s", tag, raw_salt);
      if (written > 0 && (size_t)written <= output_size)
        return output;

      if (raw_salt[4] != '\0')
        {
          /* The output didn't fit.  Try truncating the salt to four
             characters.  */
          raw_salt[4] = '\0';
          written = snprintf ((char *)output, (size_t)output_size,
                              "$%c$%s", tag, raw_salt);
          if (written > 0 && (size_t)written <= output_size)
            return output;
        }
    }

  /* we know we do have enough space for this */
  output[0] = '*';
  output[1] = '0';
  output[2] = '\0';
  errno = ERANGE;
  return NULL;
}

uint8_t *
gensalt_sha256_rn (unsigned long count,
                   const uint8_t *rbytes, size_t nrbytes,
                   uint8_t *output, size_t output_size)
{
  return gensalt_sha_rn ('5', count, rbytes, nrbytes, output, output_size);
}

uint8_t *
gensalt_sha512_rn (unsigned long count,
                   const uint8_t *rbytes, size_t nrbytes,
                   uint8_t *output, size_t output_size)
{
  return gensalt_sha_rn ('6', count, rbytes, nrbytes, output, output_size);
}

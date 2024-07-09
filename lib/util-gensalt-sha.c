/*
 * Written by Solar Designer and placed in the public domain.
 * See crypt-bcrypt.c for more information.
 *
 * This file contains setting-string generation code shared among the
 * MD5, SHA256, and SHA512 hash algorithms, which use very similar
 * setting formats.  Setting-string generation for bcrypt and DES is
 * entirely in crypt-bcrypt.c and crypt-des.c respectively.
 */

#include "crypt-port.h"

#include <errno.h>
#include <stdio.h>

#if INCLUDE_md5crypt || INCLUDE_sha256crypt || INCLUDE_sha512crypt || INCLUDE_sm3crypt

void
gensalt_sha_rn (const char *tag, size_t maxsalt, unsigned long defcount,
                unsigned long mincount, unsigned long maxcount,
                unsigned long count,
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
    count = defcount;
  if (count < mincount)
    count = mincount;
  if (count > maxcount)
    count = maxcount;

  /* Compute how much space we need.  */
  size_t output_len = 8; /* $x$ssss\0 */
  if (count != defcount)
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
  if (count == defcount)
    {
      written = (size_t) snprintf ((char *)output, output_size, "$%s$", tag);
    }
  else
    written = (size_t) snprintf ((char *)output, output_size,
                                 "$%s$rounds=%lu$", tag, count);

  /* The length calculation above should ensure that this is always true.  */
  assert (written + 5 < output_size);

  size_t used_rbytes = 0;
  while (written + 5 < output_size &&
         used_rbytes + 3 < nrbytes &&
         (used_rbytes * 4 / 3) < maxsalt)
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

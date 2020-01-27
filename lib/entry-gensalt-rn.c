/* High-level libcrypt interfaces.

   Copyright 2007-2020 Thorsten Kukuk, Zack Weinberg, Björn Esser

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
#include "crypt-symver.h"

#if INCLUDE_crypt_gensalt_rn || INCLUDE_crypt_gensalt_ra

#include "crypt.h"
#include "crypt-hashes.h"
#include "crypt-internal.h"

#include <errno.h>

char *
crypt_gensalt_internal (const char *prefix, unsigned long count,
                        const char *rbytes, int nrbytes, char *output,
                        int output_size)
{
  make_failure_token ("", output, output_size);

  /* Individual gensalt functions will check for adequate space for
     their own breed of setting, but the shortest possible one is
     three bytes (DES two-character salt + NUL terminator) and we
     also want to rule out negative numbers early.  */
  if (output_size < 3)
    {
      errno = ERANGE;
      return 0;
    }

  /* If the prefix is 0, that means to use the current best default.
     Note that this is different from the behavior when the prefix is
     "", which selects DES.  HASH_ALGORITHM_DEFAULT is not defined when
     the current default algorithm was disabled at configure time.  */
  if (!prefix)
    {
#if defined HASH_ALGORITHM_DEFAULT
      prefix = HASH_ALGORITHM_DEFAULT;
#else
      errno = EINVAL;
      return 0;
#endif
    }

  const struct hashfn *h = get_hashfn (prefix);
  if (!h)
    {
      errno = EINVAL;
      return 0;
    }

  char internal_rbytes[UCHAR_MAX];
  /* typeof (internal_nrbytes) == typeof (h->nrbytes).  */
  unsigned char internal_nrbytes = 0;

  /* If rbytes is 0, read random bytes from the operating system if
     possible.  */
  if (!rbytes)
    {
      if (!get_random_bytes (internal_rbytes, h->nrbytes))
        return 0;

      rbytes = internal_rbytes;
      nrbytes = internal_nrbytes = h->nrbytes;
    }

  h->gensalt (count,
              (const unsigned char *)rbytes, (size_t)nrbytes,
              (unsigned char *)output, (size_t)output_size);

  if (internal_nrbytes)
    XCRYPT_SECURE_MEMSET (internal_rbytes, internal_nrbytes);

  return output[0] == '*' ? 0 : output;
}
#endif

#if INCLUDE_crypt_gensalt_rn
strong_alias (crypt_gensalt_internal, crypt_gensalt_rn);
SYMVER_crypt_gensalt_rn;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt_gensalt_rn && INCLUDE_crypt_gensalt_r
strong_alias (crypt_gensalt_internal, crypt_gensalt_r);
SYMVER_crypt_gensalt_r;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt_gensalt_rn && INCLUDE_xcrypt_gensalt_r
strong_alias (crypt_gensalt_internal, xcrypt_gensalt_r);
SYMVER_xcrypt_gensalt_r;
#endif

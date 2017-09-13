/*
 * UFC-crypt: ultra fast crypt(3) implementation
 *
 * Copyright (C) 1991, 1992, 1993, 1996 Free Software Foundation, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; see the file COPYING.LIB.  If not,
 * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * @(#)crypt.c  2.25 12/20/96
 *
 * Semiportable C version
 *
 */

#include "xcrypt-private.h"
#include "crypt-private.h"

#if !UFC_USE_64BIT

/*
 * 32 bit version
 */

#define SBA(sb, v) (*(uint32_t*)((char*)(sb)+(v)))

void
_ufc_doit_r (uint_fast32_t itr, struct crypt_data *restrict __data,
             uint_fast32_t *res)
{
  int i;
  uint32_t s, *k;
  uint32_t *sb01 = (uint32_t *) __data->sb0;
  uint32_t *sb23 = (uint32_t *) __data->sb2;
  uint32_t l1, l2, r1, r2;

  l1 = (uint32_t) res[0];
  l2 = (uint32_t) res[1];
  r1 = (uint32_t) res[2];
  r2 = (uint32_t) res[3];

  while (itr--)
    {
      k = (uint32_t *) __data->keysched;
      for (i = 8; i--;)
        {
          s = *k++ ^ r1;
          l1 ^= SBA (sb01, s & 0xffff); l2 ^= SBA (sb01, (s & 0xffff) + 4);
          l1 ^= SBA (sb01, s >>= 16  ); l2 ^= SBA (sb01, (s         ) + 4);
          s = *k++ ^ r2;
          l1 ^= SBA (sb23, s & 0xffff); l2 ^= SBA (sb23, (s & 0xffff) + 4);
          l1 ^= SBA (sb23, s >>= 16  ); l2 ^= SBA (sb23, (s         ) + 4);

          s = *k++ ^ l1;
          r1 ^= SBA (sb01, s & 0xffff); r2 ^= SBA (sb01, (s & 0xffff) + 4);
          r1 ^= SBA (sb01, s >>= 16  ); r2 ^= SBA (sb01, (s         ) + 4);
          s = *k++ ^ l2;
          r1 ^= SBA (sb23, s & 0xffff); r2 ^= SBA (sb23, (s & 0xffff) + 4);
          r1 ^= SBA (sb23, s >>= 16  ); r2 ^= SBA (sb23, (s         ) + 4);
        }
      s = l1;
      l1 = r1;
      r1 = s;
      s = l2;
      l2 = r2;
      r2 = s;
    }
  res[0] = l1;
  res[1] = l2;
  res[2] = r1;
  res[3] = r2;
}

#else

/*
 * 64 bit version
 */

#define SBA(sb, v) (*(uint64_t*)((char*)(sb)+(v)))

void
_ufc_doit_r (uint_fast32_t itr, struct crypt_data *restrict __data,
             uint_fast32_t *res)
{
  int i;
  uint64_t l, r, s, *k;
  uint64_t *sb01 = (uint64_t *) __data->sb0;
  uint64_t *sb23 = (uint64_t *) __data->sb2;

  l = (((uint64_t) res[0]) << 32) | ((uint64_t) res[1]);
  r = (((uint64_t) res[2]) << 32) | ((uint64_t) res[3]);

  while (itr--)
    {
      k = (uint64_t *) __data->keysched;
      for (i = 8; i--;)
        {
          s = *k++ ^ r;
          l ^= SBA (sb23, (s       ) & 0xffff);
          l ^= SBA (sb23, (s >>= 16) & 0xffff);
          l ^= SBA (sb01, (s >>= 16) & 0xffff);
          l ^= SBA (sb01, (s >>= 16)         );

          s = *k++ ^ l;
          r ^= SBA (sb23, (s       ) & 0xffff);
          r ^= SBA (sb23, (s >>= 16) & 0xffff);
          r ^= SBA (sb01, (s >>= 16) & 0xffff);
          r ^= SBA (sb01, (s >>= 16)         );
        }
      s = l;
      l = r;
      r = s;
    }

  res[0] = l >> 32;
  res[1] = l & 0xffffffff;
  res[2] = r >> 32;
  res[3] = r & 0xffffffff;
}

#endif

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
 * Obsolete DES symmetric cipher primitives - not to be used in new code
 */

#include "xcrypt-private.h"
#include "crypt-obsolete.h"
#include "des.h"


/*
 * UNIX encrypt function. Takes a bitvector
 * represented by one byte per bit and
 * encrypt/decrypt according to edflag
 */

void
__encrypt_r (char *__block, int __edflag,
             struct crypt_data *restrict __data)
{
  uint_fast32_t l1, l2, r1, r2, res[4];
  int i;
#if !UFC_USE_64BIT
  uint32_t *kt;
  kt = (uint32_t *) __data->keysched;
#else
  uint64_t *kt;
  kt = (uint64_t *) __data->keysched;
#endif

  /*
   * Undo any salt changes to E expansion
   */
  _ufc_setup_salt_r ("..", __data);

  /*
   * Reverse key table if
   * changing operation (encrypt/decrypt)
   */
  if ((__edflag == 0) != (__data->direction == 0))
    {
      for (i = 0; i < 8; i++)
        {
#if !UFC_USE_64BIT
          uint32_t x;
          x = kt[2 * (15 - i)];
          kt[2 * (15 - i)] = kt[2 * i];
          kt[2 * i] = x;

          x = kt[2 * (15 - i) + 1];
          kt[2 * (15 - i) + 1] = kt[2 * i + 1];
          kt[2 * i + 1] = x;
#else
          uint64_t x;
          x = kt[15 - i];
          kt[15 - i] = kt[i];
          kt[i] = x;
#endif
        }
      __data->direction = __edflag;
    }

  /*
   * Do initial permutation + E expansion
   */
  i = 0;
  for (l1 = 0; i < 24; i++)
    {
      if (__block[initial_perm[esel[i] - 1] - 1])
        l1 |= bitmask[i];
    }
  for (l2 = 0; i < 48; i++)
    {
      if (__block[initial_perm[esel[i] - 1] - 1])
        l2 |= bitmask[i - 24];
    }

  i = 0;
  for (r1 = 0; i < 24; i++)
    {
      if (__block[initial_perm[esel[i] - 1 + 32] - 1])
        r1 |= bitmask[i];
    }
  for (r2 = 0; i < 48; i++)
    {
      if (__block[initial_perm[esel[i] - 1 + 32] - 1])
        r2 |= bitmask[i - 24];
    }

  /*
   * Do DES inner loops + final conversion
   */
  res[0] = l1;
  res[1] = l2;
  res[2] = r1;
  res[3] = r2;
  _ufc_doit_r ((uint_fast32_t) 1, __data, &res[0]);

  /*
   * Do final permutations
   */
  _ufc_dofinalperm_r (res, __data);

  /*
   * And convert to bit array
   */
  l1 = res[0];
  r1 = res[1];
  for (i = 0; i < 32; i++)
    {
      *__block++ = (l1 & longmask[i]) != 0;
    }
  for (i = 0; i < 32; i++)
    {
      *__block++ = (r1 & longmask[i]) != 0;
    }
}

weak_alias (__encrypt_r, encrypt_r)
extern void __encrypt (char *__block, int __edflag);

void __encrypt (char *__block, int __edflag)
{
  __encrypt_r (__block, __edflag, &_ufc_foobar);
}

weak_alias (__encrypt, encrypt)

/*
 * UNIX setkey function. Take a 64 bit DES
 * key and setup the machinery.
 */
void
__setkey_r (const char *__key, struct crypt_data *restrict __data)
{
  int i, j;
  unsigned char c;
  unsigned char ktab[8];

  _ufc_setup_salt_r ("..", __data);     /* be sure we're initialized */

  for (i = 0; i < 8; i++)
    {
      for (j = 0, c = 0; j < 8; j++)
        c = c << 1 | *__key++;
      ktab[i] = c >> 1;
    }
  _ufc_mk_keytab_r ((char *) ktab, __data);
}

weak_alias (__setkey_r, setkey_r)
extern void __setkey (const char *__key);

void __setkey (const char *__key)
{
  __setkey_r (__key, &_ufc_foobar);
}

weak_alias (__setkey, setkey)


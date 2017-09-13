/*
 * UFC-crypt: ultra fast crypt(3) implementation
 *
 * Copyright (C) 1991-2007 Free Software Foundation, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; see the file COPYING.LIB.  If not,
 * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * @(#)crypt.c  2.25 12/20/96
 * @(#)crypt_util.c     2.56 12/20/96
 *
 */

#include "xcrypt-private.h"
#include "des.h"

#include <string.h>

/* Prototypes for local functions.  */
#if !UFC_USE_64BIT
static void shuffle_sb (uint32_t * k, uint_fast32_t saltbits);
#else
static void shuffle_sb (uint64_t * k, uint_fast32_t saltbits);
#endif

#define ascii_to_bin(c) ((c)>='a'?(c-59):(c)>='A'?((c)-53):(c)-'.')
#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')

/* lookup a 6 bit value in sbox */

#define s_lookup(i,s) sbox[(i)][(((s)>>4) & 0x2)|((s) & 0x1)][((s)>>1) & 0xf];

/*
 * Initialize unit - may be invoked directly
 * by fcrypt users.
 */

void
__init_des_r (struct crypt_data *restrict __data)

{
  int sg;

#if !UFC_USE_64BIT
  uint32_t *sb[4];
  sb[0] = (uint32_t *) __data->sb0;
  sb[1] = (uint32_t *) __data->sb1;
  sb[2] = (uint32_t *) __data->sb2;
  sb[3] = (uint32_t *) __data->sb3;
#else
  uint64_t *sb[4];
  sb[0] = (uint64_t *) __data->sb0;
  sb[1] = (uint64_t *) __data->sb1;
  sb[2] = (uint64_t *) __data->sb2;
  sb[3] = (uint64_t *) __data->sb3;
#endif

  /*
   * Create the sb tables:
   *
   * For each 12 bit segment of an 48 bit intermediate
   * result, the sb table precomputes the two 4 bit
   * values of the sbox lookups done with the two 6
   * bit halves, shifts them to their proper place,
   * sends them through perm32 and finally E expands
   * them so that they are ready for the next
   * DES round.
   *
   */

  memset (__data->sb0, 0, sizeof (__data->sb0));
  memset (__data->sb1, 0, sizeof (__data->sb1));
  memset (__data->sb2, 0, sizeof (__data->sb2));
  memset (__data->sb3, 0, sizeof (__data->sb3));

  for (sg = 0; sg < 4; sg++)
    {
      int j1, j2;
      int s1, s2;

      for (j1 = 0; j1 < 64; j1++)
        {
          s1 = s_lookup (2 * sg, j1);
          for (j2 = 0; j2 < 64; j2++)
            {
              uint_fast32_t to_permute, inx;

              s2 = s_lookup (2 * sg + 1, j2);
              to_permute = (((uint_fast32_t) s1 << 4) |
                            (uint_fast32_t) s2) << (24 - 8 * (uint_fast32_t) sg);

#if !UFC_USE_64BIT
              inx = ((j1 << 6) | j2) << 1;
              sb[sg][inx] = eperm32tab[0][(to_permute >> 24) & 0xff][0];
              sb[sg][inx + 1] = eperm32tab[0][(to_permute >> 24) & 0xff][1];
              sb[sg][inx] |= eperm32tab[1][(to_permute >> 16) & 0xff][0];
              sb[sg][inx + 1] |= eperm32tab[1][(to_permute >> 16) & 0xff][1];
              sb[sg][inx] |= eperm32tab[2][(to_permute >> 8) & 0xff][0];
              sb[sg][inx + 1] |= eperm32tab[2][(to_permute >> 8) & 0xff][1];
              sb[sg][inx] |= eperm32tab[3][(to_permute) & 0xff][0];
              sb[sg][inx + 1] |= eperm32tab[3][(to_permute) & 0xff][1];
#else
              inx = ((j1 << 6) | j2);
              sb[sg][inx] =
                ((uint64_t) eperm32tab[0][(to_permute >> 24) & 0xff][0] << 32) |
                (uint64_t) eperm32tab[0][(to_permute >> 24) & 0xff][1];
              sb[sg][inx] |=
                ((uint64_t) eperm32tab[1][(to_permute >> 16) & 0xff][0] << 32) |
                (uint64_t) eperm32tab[1][(to_permute >> 16) & 0xff][1];
              sb[sg][inx] |=
                ((uint64_t) eperm32tab[2][(to_permute >> 8) & 0xff][0] << 32) |
                (uint64_t) eperm32tab[2][(to_permute >> 8) & 0xff][1];
              sb[sg][inx] |=
                ((uint64_t) eperm32tab[3][(to_permute) & 0xff][0] << 32) |
                (uint64_t) eperm32tab[3][(to_permute) & 0xff][1];
#endif
            }
        }
    }

  __data->current_saltbits = 0;
  __data->current_salt[0] = 0;
  __data->current_salt[1] = 0;
  __data->initialized++;
}

void
__init_des (void)
{
  __init_des_r (&_ufc_foobar);
}

/*
 * Process the elements of the sb table permuting the
 * bits swapped in the expansion by the current salt.
 */

#if !UFC_USE_64BIT
static void
shuffle_sb (uint32_t *k, uint_fast32_t saltbits)
{
  uint_fast32_t j;
  uint32_t x;
  for (j = 4096; j--;)
    {
      x = (k[0] ^ k[1]) & (uint32_t) saltbits;
      *k++ ^= x;
      *k++ ^= x;
    }
}
#else
static void
shuffle_sb (uint64_t *k, uint_fast32_t saltbits)
{
  uint_fast32_t j;
  uint64_t x;
  for (j = 4096; j--;)
    {
      x = ((*k >> 32) ^ *k) & (uint64_t) saltbits;
      *k++ ^= (x << 32) | x;
    }
}
#endif

/*
 * Setup the unit for a new salt
 * Hopefully we'll not see a new salt in each crypt call.
 */

void
_ufc_setup_salt_r (const char *s, struct crypt_data *restrict __data)
{
  uint_fast32_t i, j, saltbits;

  if (__data->initialized == 0)
    __init_des_r (__data);

  if (s[0] == __data->current_salt[0] && s[1] == __data->current_salt[1])
    return;
  __data->current_salt[0] = s[0];
  __data->current_salt[1] = s[1];

  /*
   * This is the only crypt change to DES:
   * entries are swapped in the expansion table
   * according to the bits set in the salt.
   */
  saltbits = 0;
  for (i = 0; i < 2; i++)
    {
      long c = ascii_to_bin (s[i]);
      for (j = 0; j < 6; j++)
        {
          if ((c >> j) & 0x1)
            saltbits |= bitmask[6 * i + j];
        }
    }

  /*
   * Permute the sb table values
   * to reflect the changed e
   * selection table
   */
#if !UFC_USE_64BIT
#define LONGG uint32_t*
#else
#define LONGG uint64_t*
#endif

  shuffle_sb ((LONGG) __data->sb0, __data->current_saltbits ^ saltbits);
  shuffle_sb ((LONGG) __data->sb1, __data->current_saltbits ^ saltbits);
  shuffle_sb ((LONGG) __data->sb2, __data->current_saltbits ^ saltbits);
  shuffle_sb ((LONGG) __data->sb3, __data->current_saltbits ^ saltbits);

  __data->current_saltbits = saltbits;
}

void
_ufc_mk_keytab_r (const char *key, struct crypt_data *restrict __data)
{
  uint_fast32_t v1, v2;
  const uint_fast32_t *k1;
  int i;
#if !UFC_USE_64BIT
  uint32_t v, *k2;
  k2 = (uint32_t *) __data->keysched;
#else
  uint64_t v, *k2;
  k2 = (uint64_t *) __data->keysched;
#endif

  v1 = v2 = 0;
  k1 = &do_pc1[0][0][0];
  for (i = 8; i--;)
    {
      v1 |= k1[*key & 0x7f];
      k1 += 128;
      v2 |= k1[*key++ & 0x7f];
      k1 += 128;
    }

  for (i = 0; i < 16; i++)
    {
      k1 = &do_pc2[0][0];

      v1 = (v1 << rots[i]) | (v1 >> (28 - rots[i]));
      v = k1[(v1 >> 21) & 0x7f];
      k1 += 128;
      v |= k1[(v1 >> 14) & 0x7f];
      k1 += 128;
      v |= k1[(v1 >> 7) & 0x7f];
      k1 += 128;
      v |= k1[(v1) & 0x7f];
      k1 += 128;

#if !UFC_USE_64BIT
      *k2++ = (v | 0x00008000);
      v = 0;
#else
      v = (v << 32);
#endif

      v2 = (v2 << rots[i]) | (v2 >> (28 - rots[i]));
      v |= k1[(v2 >> 21) & 0x7f];
      k1 += 128;
      v |= k1[(v2 >> 14) & 0x7f];
      k1 += 128;
      v |= k1[(v2 >> 7) & 0x7f];
      k1 += 128;
      v |= k1[(v2) & 0x7f];

#if !UFC_USE_64BIT
      *k2++ = (v | 0x00008000);
#else
      *k2++ = v | 0x0000800000008000l;
#endif
    }

  __data->direction = 0;
}

/*
 * Undo an extra E selection and do final permutations
 */

void
_ufc_dofinalperm_r (uint_fast32_t *res, struct crypt_data *restrict __data)
{
  uint_fast32_t v1, v2, x;
  uint_fast32_t l1, l2, r1, r2;

  l1 = res[0];
  l2 = res[1];
  r1 = res[2];
  r2 = res[3];

  x = (l1 ^ l2) & __data->current_saltbits;
  l1 ^= x;
  l2 ^= x;
  x = (r1 ^ r2) & __data->current_saltbits;
  r1 ^= x;
  r2 ^= x;

  v1 = v2 = 0;
  l1 >>= 3;
  l2 >>= 3;
  r1 >>= 3;
  r2 >>= 3;

  v1 |= efp[15][r2 & 0x3f][0];
  v2 |= efp[15][r2 & 0x3f][1];
  v1 |= efp[14][(r2 >>= 6) & 0x3f][0];
  v2 |= efp[14][r2 & 0x3f][1];
  v1 |= efp[13][(r2 >>= 10) & 0x3f][0];
  v2 |= efp[13][r2 & 0x3f][1];
  v1 |= efp[12][(r2 >>= 6) & 0x3f][0];
  v2 |= efp[12][r2 & 0x3f][1];

  v1 |= efp[11][r1 & 0x3f][0];
  v2 |= efp[11][r1 & 0x3f][1];
  v1 |= efp[10][(r1 >>= 6) & 0x3f][0];
  v2 |= efp[10][r1 & 0x3f][1];
  v1 |= efp[9][(r1 >>= 10) & 0x3f][0];
  v2 |= efp[9][r1 & 0x3f][1];
  v1 |= efp[8][(r1 >>= 6) & 0x3f][0];
  v2 |= efp[8][r1 & 0x3f][1];

  v1 |= efp[7][l2 & 0x3f][0];
  v2 |= efp[7][l2 & 0x3f][1];
  v1 |= efp[6][(l2 >>= 6) & 0x3f][0];
  v2 |= efp[6][l2 & 0x3f][1];
  v1 |= efp[5][(l2 >>= 10) & 0x3f][0];
  v2 |= efp[5][l2 & 0x3f][1];
  v1 |= efp[4][(l2 >>= 6) & 0x3f][0];
  v2 |= efp[4][l2 & 0x3f][1];

  v1 |= efp[3][l1 & 0x3f][0];
  v2 |= efp[3][l1 & 0x3f][1];
  v1 |= efp[2][(l1 >>= 6) & 0x3f][0];
  v2 |= efp[2][l1 & 0x3f][1];
  v1 |= efp[1][(l1 >>= 10) & 0x3f][0];
  v2 |= efp[1][l1 & 0x3f][1];
  v1 |= efp[0][(l1 >>= 6) & 0x3f][0];
  v2 |= efp[0][l1 & 0x3f][1];

  res[0] = v1;
  res[1] = v2;
}

/*
 * crypt only: convert from 64 bit to 11 bit ASCII
 * prefixing with the salt
 */

void
_ufc_output_conversion_r (uint_fast32_t v1, uint_fast32_t v2, const char *salt,
                          struct crypt_data *restrict __data)
{
  int i, s, shf;

  __data->crypt_3_buf[0] = salt[0];
  __data->crypt_3_buf[1] = salt[1] ? salt[1] : salt[0];

  for (i = 0; i < 5; i++)
    {
      shf = (26 - 6 * i);       /* to cope with MSC compiler bug */
      __data->crypt_3_buf[i + 2] = bin_to_ascii ((v1 >> shf) & 0x3f);
    }

  s = (v2 & 0xf) << 2;
  v2 = (v2 >> 2) | ((v1 & 0x3) << 30);

  for (i = 5; i < 10; i++)
    {
      shf = (56 - 6 * i);
      __data->crypt_3_buf[i + 2] = bin_to_ascii ((v2 >> shf) & 0x3f);
    }

  __data->crypt_3_buf[12] = bin_to_ascii (s);
  __data->crypt_3_buf[13] = 0;
}

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

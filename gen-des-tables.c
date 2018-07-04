/*
 * FreeSec: libcrypt for NetBSD
 *
 * Copyright (c) 1994 David Burren
 * All rights reserved.
 *
 * Adapted for FreeBSD-2.0 by Geoffrey M. Rehmet
 *	this file should now *only* export crypt(), in order to make
 *	binaries of libcrypt exportable from the USA
 *
 * Adapted for FreeBSD-4.0 by Mark R V Murray
 *	this file should now *only* export crypt_des(), in order to make
 *	a module that can be optionally included in libcrypt.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of other contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This is an original implementation of the DES and the crypt(3) interfaces
 * by David Burren <davidb@werj.com.au>.
 */

/*
 * This program can regenerate the tables in alg-des-tables.c.
 * It is preserved as documentation, but it should no longer be
 * necessary to run it.
 */

#include "crypt-port.h"

#include <inttypes.h>
#include <stdio.h>

static const uint8_t	IP[64] =
{
  58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
  62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
  57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
  61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7
};

static uint8_t	inv_key_perm[64];
static const uint8_t	key_perm[56] =
{
  57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
  10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
  14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

static uint8_t	inv_comp_perm[56];
static const uint8_t	comp_perm[48] =
{
  14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
  23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

/*
 *	No E box is used, as it's replaced by some ANDs, shifts, and ORs.
 */

static uint8_t	u_sbox[8][64];
static const uint8_t	sbox[8][64] =
{
  {
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
    0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
    4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
  },
  {
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
    3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
    0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
  },
  {
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
    1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
  },
  {
    7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
    3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
  },
  {
    2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
    4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
  },
  {
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
    9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
    4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
  },
  {
    4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
    1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
    6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
  },
  {
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
    1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
    7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
    2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
  }
};

static uint8_t	un_pbox[32];
static const uint8_t	pbox[32] =
{
  16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
  2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

static const uint32_t	*bits28, *bits24;
static uint8_t		init_perm[64], final_perm[64];

static const uint32_t	bits32[32] =
{
  0x80000000, 0x40000000, 0x20000000, 0x10000000,
  0x08000000, 0x04000000, 0x02000000, 0x01000000,
  0x00800000, 0x00400000, 0x00200000, 0x00100000,
  0x00080000, 0x00040000, 0x00020000, 0x00010000,
  0x00008000, 0x00004000, 0x00002000, 0x00001000,
  0x00000800, 0x00000400, 0x00000200, 0x00000100,
  0x00000080, 0x00000040, 0x00000020, 0x00000010,
  0x00000008, 0x00000004, 0x00000002, 0x00000001
};

static const uint8_t bits8[8] =
{ 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };

static uint8_t m_sbox_[4][4096];
static uint32_t	ip_maskl_[8][256], ip_maskr_[8][256];
static uint32_t	fp_maskl_[8][256], fp_maskr_[8][256];
static uint32_t	key_perm_maskl_[8][128], key_perm_maskr_[8][128];
static uint32_t	comp_maskl_[8][128], comp_maskr_[8][128];
static uint32_t	psbox_[4][256];

static void
des_init(void)
{
  int	i, j, b, k, inbit, obit;
  uint32_t	*p, *il, *ir, *fl, *fr;

  bits24 = (bits28 = bits32 + 4) + 4;

  /*
   * Invert the S-boxes, reordering the input bits.
   */
  for (i = 0; i < 8; i++)
    for (j = 0; j < 64; j++)
      {
        b = (j & 0x20) | ((j & 1) << 4) | ((j >> 1) & 0xf);
        u_sbox[i][j] = sbox[i][b];
      }

  /*
   * Convert the inverted S-boxes into 4 arrays of 8 bits.
   * Each will handle 12 bits of the S-box input.
   */
  for (b = 0; b < 4; b++)
    for (i = 0; i < 64; i++)
      for (j = 0; j < 64; j++)
        m_sbox_[b][(i << 6) | j] =
          (uint8_t)((u_sbox[(b << 1)][i] << 4) |
                    u_sbox[(b << 1) + 1][j]);

  /*
   * Set up the initial & final permutations into a useful form, and
   * initialise the inverted key permutation.
   */
  for (i = 0; i < 64; i++)
    {
      final_perm[i] = (uint8_t)(IP[i] - 1);
      init_perm[final_perm[i]] = (uint8_t)i;
      inv_key_perm[i] = 255;
    }

  /*
   * Invert the key permutation and initialise the inverted key
   * compression permutation.
   */
  for (i = 0; i < 56; i++)
    {
      inv_key_perm[key_perm[i] - 1] = (uint8_t)i;
      inv_comp_perm[i] = 255;
    }

  /*
   * Invert the key compression permutation.
   */
  for (i = 0; i < 48; i++)
    {
      inv_comp_perm[comp_perm[i] - 1] = (uint8_t)i;
    }

  /*
   * Set up the OR-mask arrays for the initial and final permutations,
   * and for the key initial and compression permutations.
   */
  for (k = 0; k < 8; k++)
    {
      for (i = 0; i < 256; i++)
        {
          *(il = &ip_maskl_[k][i]) = 0L;
          *(ir = &ip_maskr_[k][i]) = 0L;
          *(fl = &fp_maskl_[k][i]) = 0L;
          *(fr = &fp_maskr_[k][i]) = 0L;
          for (j = 0; j < 8; j++)
            {
              inbit = 8 * k + j;
              if (i & bits8[j])
                {
                  if ((obit = init_perm[inbit]) < 32)
                    *il |= bits32[obit];
                  else
                    *ir |= bits32[obit-32];
                  if ((obit = final_perm[inbit]) < 32)
                    *fl |= bits32[obit];
                  else
                    *fr |= bits32[obit - 32];
                }
            }
        }
      for (i = 0; i < 128; i++)
        {
          *(il = &key_perm_maskl_[k][i]) = 0L;
          *(ir = &key_perm_maskr_[k][i]) = 0L;
          for (j = 0; j < 7; j++)
            {
              inbit = 8 * k + j;
              if (i & bits8[j + 1])
                {
                  if ((obit = inv_key_perm[inbit]) == 255)
                    continue;
                  if (obit < 28)
                    *il |= bits28[obit];
                  else
                    *ir |= bits28[obit - 28];
                }
            }
          *(il = &comp_maskl_[k][i]) = 0L;
          *(ir = &comp_maskr_[k][i]) = 0L;
          for (j = 0; j < 7; j++)
            {
              inbit = 7 * k + j;
              if (i & bits8[j + 1])
                {
                  if ((obit=inv_comp_perm[inbit]) == 255)
                    continue;
                  if (obit < 24)
                    *il |= bits24[obit];
                  else
                    *ir |= bits24[obit - 24];
                }
            }
        }
    }

  /*
   * Invert the P-box permutation, and convert into OR-masks for
   * handling the output of the S-box arrays setup above.
   */
  for (i = 0; i < 32; i++)
    un_pbox[pbox[i] - 1] = (uint8_t)i;

  for (b = 0; b < 4; b++)
    for (i = 0; i < 256; i++)
      {
        *(p = &psbox_[b][i]) = 0L;
        for (j = 0; j < 8; j++)
          {
            if (i & bits8[j])
              *p |= bits32[un_pbox[8 * b + j]];
          }
      }
}

static void
write_table_u8(size_t m, size_t n, const uint8_t *tbl, const char *name)
{
  printf("\nconst uint8_t %s[%zu][%zu] = {\n", name, m, n);
  for (size_t i = 0; i < m; i++)
    {
      fputs("  {", stdout);
      for (size_t j = 0; j < n; j++)
        {
          if (j % 12 == 0)
            fputs("\n   ", stdout);
          printf(" 0x%02x,", (unsigned int)tbl[i*n + j]);
        }
      puts("\n  },");
    }
  puts("};");
}

static void
write_table_u32(size_t m, size_t n, const uint32_t *tbl, const char *name)
{
  printf("\nconst uint32_t %s[%zu][%zu] = {\n", name, m, n);
  for (size_t i = 0; i < m; i++)
    {
      fputs("  {", stdout);
      for (size_t j = 0; j < n; j++)
        {
          if (j % 6 == 0)
            fputs("\n   ", stdout);
          printf(" 0x%08"PRIx32",", tbl[i*n + j]);
        }
      puts("\n  },");
    }
  puts("};");
}

int
main(void)
{
  des_init();

  write_table_u8(4, 4096, &m_sbox_[0][0], "m_sbox");

  write_table_u32(8, 256, &ip_maskl_[0][0], "ip_maskl");
  write_table_u32(8, 256, &ip_maskr_[0][0], "ip_maskr");
  write_table_u32(8, 256, &fp_maskl_[0][0], "fp_maskl");
  write_table_u32(8, 256, &fp_maskr_[0][0], "fp_maskr");

  write_table_u32(8, 128, &key_perm_maskl_[0][0], "key_perm_maskl");
  write_table_u32(8, 128, &key_perm_maskr_[0][0], "key_perm_maskr");
  write_table_u32(8, 128, &comp_maskl_[0][0], "comp_maskl");
  write_table_u32(8, 128, &comp_maskr_[0][0], "comp_maskr");

  write_table_u32(4, 256, &psbox_[0][0], "psbox");
}

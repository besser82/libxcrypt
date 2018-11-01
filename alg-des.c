/*
 * FreeSec: libcrypt for NetBSD
 *
 * Copyright (c) 1994 David Burren
 * All rights reserved.
 *
 * Adapted for FreeBSD-2.0 by Geoffrey M. Rehmet
 *      this file should now *only* export crypt(), in order to make
 *      binaries of libcrypt exportable from the USA
 *
 * Adapted for FreeBSD-4.0 by Mark R V Murray
 *      this file should now *only* export crypt_des(), in order to make
 *      a module that can be optionally included in libcrypt.
 *
 * Adapted for libxcrypt by Zack Weinberg, 2017
 *      writable global data eliminated; type-punning eliminated;
 *      des_init() run at build time (see des-mktables.c);
 *      made into a libxcrypt algorithm module (see des-crypt.c);
 *      functionality required to support the legacy encrypt() and
 *      setkey() primitives re-exposed (see des-obsolete.c).
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
 *
 * An excellent reference on the underlying algorithm (and related
 * algorithms) is:
 *
 *      B. Schneier, Applied Cryptography: protocols, algorithms,
 *      and source code in C, John Wiley & Sons, 1994.
 *
 * Note that in that book's description of DES the lookups for the initial,
 * pbox, and final permutations are inverted (this has been brought to the
 * attention of the author).  A list of errata for this book has been
 * posted to the sci.crypt newsgroup by the author and is available for FTP.
 */

#include "crypt-port.h"

#if INCLUDE_descrypt || INCLUDE_bigcrypt || INCLUDE_bsdicrypt

#include "alg-des.h"
#include "byteorder.h"

static const uint8_t key_shifts[16] =
{
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

void
des_set_key (struct des_ctx *restrict ctx,
             const unsigned char key[MIN_SIZE(8)])
{
  uint32_t rawkey0, rawkey1, k0, k1, t0, t1;
  int shifts, round;

  rawkey0 = be32_to_cpu (&key[0]);
  rawkey1 = be32_to_cpu (&key[4]);

  /* Do key permutation and split into two 28-bit subkeys.  */
  k0 = key_perm_maskl[0][(rawkey0 >> 25) & 0x7f]
       | key_perm_maskl[1][(rawkey0 >> 17) & 0x7f]
       | key_perm_maskl[2][(rawkey0 >> 9) & 0x7f]
       | key_perm_maskl[3][(rawkey0 >> 1) & 0x7f]
       | key_perm_maskl[4][(rawkey1 >> 25) & 0x7f]
       | key_perm_maskl[5][(rawkey1 >> 17) & 0x7f]
       | key_perm_maskl[6][(rawkey1 >> 9) & 0x7f]
       | key_perm_maskl[7][(rawkey1 >> 1) & 0x7f];
  k1 = key_perm_maskr[0][(rawkey0 >> 25) & 0x7f]
       | key_perm_maskr[1][(rawkey0 >> 17) & 0x7f]
       | key_perm_maskr[2][(rawkey0 >> 9) & 0x7f]
       | key_perm_maskr[3][(rawkey0 >> 1) & 0x7f]
       | key_perm_maskr[4][(rawkey1 >> 25) & 0x7f]
       | key_perm_maskr[5][(rawkey1 >> 17) & 0x7f]
       | key_perm_maskr[6][(rawkey1 >> 9) & 0x7f]
       | key_perm_maskr[7][(rawkey1 >> 1) & 0x7f];

  /* Rotate subkeys and do compression permutation.  */
  shifts = 0;
  for (round = 0; round < 16; round++)
    {
      shifts += key_shifts[round];

      t0 = (k0 << shifts) | (k0 >> (28 - shifts));
      t1 = (k1 << shifts) | (k1 >> (28 - shifts));

      ctx->keysl[round] =
        comp_maskl[0][(t0 >> 21) & 0x7f]
        | comp_maskl[1][(t0 >> 14) & 0x7f]
        | comp_maskl[2][(t0 >>  7) & 0x7f]
        | comp_maskl[3][(t0 >>  0) & 0x7f]
        | comp_maskl[4][(t1 >> 21) & 0x7f]
        | comp_maskl[5][(t1 >> 14) & 0x7f]
        | comp_maskl[6][(t1 >>  7) & 0x7f]
        | comp_maskl[7][(t1 >>  0) & 0x7f];

      ctx->keysr[round] =
        comp_maskr[0][(t0 >> 21) & 0x7f]
        | comp_maskr[1][(t0 >> 14) & 0x7f]
        | comp_maskr[2][(t0 >>  7) & 0x7f]
        | comp_maskr[3][(t0 >>  0) & 0x7f]
        | comp_maskr[4][(t1 >> 21) & 0x7f]
        | comp_maskr[5][(t1 >> 14) & 0x7f]
        | comp_maskr[6][(t1 >>  7) & 0x7f]
        | comp_maskr[7][(t1 >>  0) & 0x7f];
    }
}

void
des_set_salt (struct des_ctx *restrict ctx, uint32_t salt)
{
  uint32_t obit, saltbit, saltbits;
  int i;
  saltbits = 0L;
  saltbit = 1;
  obit = 0x800000;
  for (i = 0; i < 24; i++)
    {
      if (salt & saltbit)
        saltbits |= obit;
      saltbit <<= 1;
      obit >>= 1;
    }
  ctx->saltbits = saltbits;
}

void
des_crypt_block (struct des_ctx *restrict ctx,
                 unsigned char *out, const unsigned char *in,
                 unsigned int count, bool decrypt)
{
  uint32_t l_in, r_in, l_out, r_out;
  uint32_t l, r, *kl, *kr, *kl1, *kr1;
  uint32_t f, r48l, r48r;
  uint32_t saltbits = ctx->saltbits;
  int round, rk_step;

  /* Zero encryptions/decryptions doesn't make sense.  */
  if (count == 0)
    count = 1;

  if (decrypt)
    {
      kl1 = ctx->keysl + 15;
      kr1 = ctx->keysr + 15;
      rk_step = -1;
    }
  else
    {
      kl1 = ctx->keysl;
      kr1 = ctx->keysr;
      rk_step = 1;
    }

  /* Read the input, which is notionally in "big-endian" format.  */
  l_in = be32_to_cpu (in);
  r_in = be32_to_cpu (in + 4);

  /* Do initial permutation.  */
  l = ip_maskl[0][(l_in >> 24) & 0xff]
      | ip_maskl[1][(l_in >> 16) & 0xff]
      | ip_maskl[2][(l_in >>  8) & 0xff]
      | ip_maskl[3][(l_in >>  0) & 0xff]
      | ip_maskl[4][(r_in >> 24) & 0xff]
      | ip_maskl[5][(r_in >> 16) & 0xff]
      | ip_maskl[6][(r_in >>  8) & 0xff]
      | ip_maskl[7][(r_in >>  0) & 0xff];
  r = ip_maskr[0][(l_in >> 24) & 0xff]
      | ip_maskr[1][(l_in >> 16) & 0xff]
      | ip_maskr[2][(l_in >>  8) & 0xff]
      | ip_maskr[3][(l_in >>  0) & 0xff]
      | ip_maskr[4][(r_in >> 24) & 0xff]
      | ip_maskr[5][(r_in >> 16) & 0xff]
      | ip_maskr[6][(r_in >>  8) & 0xff]
      | ip_maskr[7][(r_in >>  0) & 0xff];

  do
    {
      kl = kl1;
      kr = kr1;
      round = 16;
      do
        {
          /* Expand R to 48 bits (simulate the E-box).  */
          r48l = ((r & 0x00000001) << 23)
                 | ((r & 0xf8000000) >>  9)
                 | ((r & 0x1f800000) >> 11)
                 | ((r & 0x01f80000) >> 13)
                 | ((r & 0x001f8000) >> 15);
          r48r = ((r & 0x0001f800) <<  7)
                 | ((r & 0x00001f80) <<  5)
                 | ((r & 0x000001f8) <<  3)
                 | ((r & 0x0000001f) <<  1)
                 | ((r & 0x80000000) >> 31);

          /* Apply salt and permuted round key.  */
          f = (r48l ^ r48r) & saltbits;
          r48l ^= f ^ *kl;
          r48r ^= f ^ *kr;
          kl += rk_step;
          kr += rk_step;

          /* Do sbox lookups (which shrink it back to 32 bits)
             and the pbox permutation at the same time.  */
          f = psbox[0][m_sbox[0][r48l >> 12]]
              | psbox[1][m_sbox[1][r48l & 0xfff]]
              | psbox[2][m_sbox[2][r48r >> 12]]
              | psbox[3][m_sbox[3][r48r & 0xfff]];

          /* Now that we've permuted things, complete f().  */
          f ^= l;
          l = r;
          r = f;
        }
      while (--round);

      r = l;
      l = f;
    }
  while (--count);

  /* Do final permutation (inverse of IP).  */
  l_out =
    fp_maskl[0][(l >> 24) & 0xff]
    | fp_maskl[1][(l >> 16) & 0xff]
    | fp_maskl[2][(l >>  8) & 0xff]
    | fp_maskl[3][(l >>  0) & 0xff]
    | fp_maskl[4][(r >> 24) & 0xff]
    | fp_maskl[5][(r >> 16) & 0xff]
    | fp_maskl[6][(r >>  8) & 0xff]
    | fp_maskl[7][(r >>  0) & 0xff];
  r_out =
    fp_maskr[0][(l >> 24) & 0xff]
    | fp_maskr[1][(l >> 16) & 0xff]
    | fp_maskr[2][(l >>  8) & 0xff]
    | fp_maskr[3][(l >>  0) & 0xff]
    | fp_maskr[4][(r >> 24) & 0xff]
    | fp_maskr[5][(r >> 16) & 0xff]
    | fp_maskr[6][(r >>  8) & 0xff]
    | fp_maskr[7][(r >>  0) & 0xff];

  cpu_to_be32 (out, l_out);
  cpu_to_be32 (out + 4, r_out);
}

#endif

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
 * Adapted for libxcrypt by Zack Weinberg, 2017
 *	see notes in des.c
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

#include "crypt-port.h"
#include "alg-des.h"

#include <errno.h>

#if INCLUDE_descrypt || INCLUDE_bsdicrypt || INCLUDE_bigcrypt

#define DES_TRD_OUTPUT_LEN 14                /* SShhhhhhhhhhh0 */
#define DES_EXT_OUTPUT_LEN 21                /* _CCCCSSSShhhhhhhhhhh0 */
#define DES_BIG_OUTPUT_LEN ((16*11) + 2 + 1) /* SS (hhhhhhhhhhh){1,16} 0 */

#define DES_MAX_OUTPUT_LEN \
  MAX (DES_TRD_OUTPUT_LEN, MAX (DES_EXT_OUTPUT_LEN, DES_BIG_OUTPUT_LEN))

static_assert (DES_MAX_OUTPUT_LEN <= CRYPT_OUTPUT_SIZE,
               "CRYPT_OUTPUT_SIZE is too small for DES");

/* A des_buffer holds all of the sensitive intermediate data used by
   crypt_des_*.  */

struct des_buffer
{
  struct des_ctx ctx;
  uint8_t keybuf[8];
  uint8_t pkbuf[8];
};

static_assert (sizeof (struct des_buffer) <= ALG_SPECIFIC_SIZE,
               "ALG_SPECIFIC_SIZE is too small for DES");


static inline int
ascii_to_bin(char ch)
{
  if (ch > 'z')
    return -1;
  if (ch >= 'a')
    return ch - 'a' + 38;
  if (ch > 'Z')
    return -1;
  if (ch >= 'A')
    return ch - 'A' + 12;
  if (ch > '9')
    return -1;
  if (ch >= '.')
    return ch - '.';
  return -1;
}

/* Generate an 11-character DES password hash into the buffer at
   OUTPUT, and nul-terminate it.  The salt and key have already been
   set.  The plaintext is 64 bits of zeroes, and the raw ciphertext is
   written to cbuf[].  */
static void
des_gen_hash (struct des_ctx *ctx, uint32_t count, uint8_t *output,
              uint8_t cbuf[8])
{
  uint8_t plaintext[8];
  XCRYPT_SECURE_MEMSET (plaintext, 8);
  des_crypt_block (ctx, cbuf, plaintext, count, false);

  /* Now encode the result.  */
  const uint8_t *sptr = cbuf;
  const uint8_t *end = sptr + 8;
  unsigned int c1, c2;

  do
    {
      c1 = *sptr++;
      *output++ = ascii64[c1 >> 2];
      c1 = (c1 & 0x03) << 4;
      if (sptr >= end)
        {
          *output++ = ascii64[c1];
          break;
        }

      c2 = *sptr++;
      c1 |= c2 >> 4;
      *output++ = ascii64[c1];
      c1 = (c2 & 0x0f) << 2;
      if (sptr >= end)
        {
          *output++ = ascii64[c1];
          break;
        }

      c2 = *sptr++;
      c1 |= c2 >> 6;
      *output++ = ascii64[c1];
      *output++ = ascii64[c2 & 0x3f];
    }
  while (sptr < end);
  *output = '\0';
}
#endif

#if INCLUDE_descrypt
/* The original UNIX DES-based password hash, no extensions.  */
void
crypt_descrypt_rn (const char *phrase, size_t ARG_UNUSED (phr_size),
                   const char *setting, size_t ARG_UNUSED (set_size),
                   uint8_t *output, size_t out_size,
                   void *scratch, size_t scr_size)
{
  /* This shouldn't ever happen, but...  */
  if (out_size < DES_TRD_OUTPUT_LEN || scr_size < sizeof (struct des_buffer))
    {
      errno = ERANGE;
      return;
    }

  struct des_buffer *buf = scratch;
  struct des_ctx *ctx = &buf->ctx;
  uint32_t salt = 0;
  uint8_t *keybuf = buf->keybuf, *pkbuf = buf->pkbuf;
  uint8_t *cp = output;
  int i;

  /* "old"-style: setting - 2 bytes of salt, phrase - up to 8 characters.
     Note: ascii_to_bin maps all byte values outside the ascii64
     alphabet to -1.  Do not read past the end of the string.  */
  i = ascii_to_bin (setting[0]);
  if (i < 0)
    {
      errno = EINVAL;
      return;
    }
  salt = (unsigned int)i;
  i = ascii_to_bin (setting[1]);
  if (i < 0)
    {
      errno = EINVAL;
      return;
    }
  salt |= ((unsigned int)i << 6);

  /* Write the canonical form of the salt to the output buffer.  We do
     this instead of copying from the setting because the setting
     might be catastrophically malformed (e.g. a 0- or 1-byte string;
     this could plausibly happen if e.g. login(8) doesn't special-case
     "*" or "!" in the password database).  */
  *cp++ = ascii64[salt & 0x3f];
  *cp++ = ascii64[(salt >> 6) & 0x3f];

  /* Copy the first 8 characters of the password into keybuf, shifting
     each character up by 1 bit and padding on the right with zeroes.  */
  for (i = 0; i < 8; i++)
    {
      keybuf[i] = (uint8_t)(*phrase << 1);
      if (*phrase)
        phrase++;
    }

  des_set_key (ctx, keybuf);
  des_set_salt (ctx, salt);
  des_gen_hash (ctx, 25, cp, pkbuf);
}
#endif

#if INCLUDE_bigcrypt
/* This algorithm is algorithm 0 (default) shipped with the C2 secure
   implementation of Digital UNIX.

   Disclaimer: This work is not based on the source code to Digital
   UNIX, nor am I (Andy Phillips) connected to Digital Equipment Corp,
   in any way other than as a customer. This code is based on
   published interfaces and reasonable guesswork.

   Description: The cleartext is divided into blocks of 8 characters
   or less. Each block is encrypted using the standard UNIX libc crypt
   function. The result of the encryption for one block provides the
   salt for the suceeding block.  The output is simply the
   concatenation of all the blocks.  Up to 16 blocks are supported
   (that is, the password can be no more than 128 characters long).

   Andy Phillips <atp@mssl.ucl.ac.uk>  */
void
crypt_bigcrypt_rn (const char *phrase, size_t phr_size,
                   const char *setting, size_t set_size,
                   uint8_t *output, size_t out_size,
                   void *scratch, size_t scr_size)
{
  /* descrypt and bigcrypt generate identical hashes when the phrase
     contains no more than 8 characters.  When the phrase is longer
     than 8 characters, descrypt would truncate it, and bigcrypt would
     generate a different, longer hash.  Therefore, when we encounter
     a phrase longer than 8 characters together with a short setting
     string, the appropriate behavior depends on whether descrypt is
     enabled.  When it is, forward to descrypt.  When it isn't, reject
     the operation.  */
  if (phr_size > 8 && set_size <= 13)
    {
#if INCLUDE_descrypt
      crypt_descrypt_rn (phrase, phr_size, setting, set_size,
                         output, out_size, scratch, scr_size);
#else
      errno = EINVAL;
#endif
      return;
    }

  /* This shouldn't ever happen, but...  */
  if (out_size < DES_BIG_OUTPUT_LEN || scr_size < sizeof (struct des_buffer))
    {
      errno = ERANGE;
      return;
    }

  struct des_buffer *buf = scratch;
  struct des_ctx *ctx = &buf->ctx;
  uint32_t salt = 0;
  uint8_t *keybuf = buf->keybuf, *pkbuf = buf->pkbuf;
  uint8_t *cp = output;
  int i, seg;

  /* The setting string is exactly the same as for a traditional DES
     hash.  */
  i = ascii_to_bin (setting[0]);
  if (i < 0)
    {
      errno = EINVAL;
      return;
    }
  salt = (unsigned int)i;
  i = ascii_to_bin (setting[1]);
  if (i < 0)
    {
      errno = EINVAL;
      return;
    }
  salt |= ((unsigned int)i << 6);

  *cp++ = ascii64[salt & 0x3f];
  *cp++ = ascii64[(salt >> 6) & 0x3f];

  for (seg = 0; seg < 16; seg++)
    {
      /* Copy and shift each block as for the traditional DES.  */
      for (i = 0; i < 8; i++)
        {
          keybuf[i] = (uint8_t)(*phrase << 1);
          if (*phrase)
            phrase++;
        }

      des_set_key (ctx, keybuf);
      des_set_salt (ctx, salt);
      des_gen_hash (ctx, 25, cp, pkbuf);

      if (*phrase == 0)
        break;

      /* change the salt (1st 2 chars of previous block) - this was found
         by dowsing - no need to check for invalid characters here */
      salt = (unsigned int)ascii_to_bin ((char)cp[0]);
      salt |= (unsigned int)ascii_to_bin ((char)cp[1]) << 6;
      cp += 11;
    }
}
#endif

#if INCLUDE_bsdicrypt
/* crypt_rn() entry point for BSD-style extended DES hashes.  These
   permit long passwords and have more salt and a controllable iteration
   count, but are still unacceptably weak by modern standards.  */
void
crypt_bsdicrypt_rn (const char *phrase, size_t ARG_UNUSED (phr_size),
                    const char *setting, size_t set_size,
                    uint8_t *output, size_t out_size,
                    void *scratch, size_t scr_size)
{
  /* This shouldn't ever happen, but...  */
  if (out_size < DES_EXT_OUTPUT_LEN || scr_size < sizeof (struct des_buffer))
    {
      errno = ERANGE;
      return;
    }

  /* If this is true, this function shouldn't have been called.
     Setting must be at least 9 bytes long, byte 10+ is ignored.  */
  if (*setting != '_' || set_size < 9)
    {
      errno = EINVAL;
      return;
    }

  struct des_buffer *buf = scratch;
  struct des_ctx *ctx = &buf->ctx;
  uint32_t count = 0, salt = 0;
  uint8_t *keybuf = buf->keybuf, *pkbuf = buf->pkbuf;
  uint8_t *cp = output;
  int i, x;

  /* "new"-style DES hash:
   	setting - underscore, 4 bytes of count, 4 bytes of salt
   	phrase - unlimited characters
   */
  for (i = 1; i < 5; i++)
    {
      x = ascii_to_bin(setting[i]);
      if (x < 0)
        {
          errno = EINVAL;
          return;
        }
      count |= (unsigned int)x << ((i - 1) * 6);
    }

  for (i = 5; i < 9; i++)
    {
      x = ascii_to_bin(setting[i]);
      if (x < 0)
        {
          errno = EINVAL;
          return;
        }
      salt |= (unsigned int)x << ((i - 5) * 6);
    }

  memcpy (cp, setting, 9);
  cp += 9;

  /* Fold passwords longer than 8 bytes into a single DES key using a
     procedure similar to a Merkle-Dåmgard hash construction.  Each
     block is shifted and padded, as for the traditional hash, then
     XORed with the output of the previous round (IV all bits zero),
     set as the DES key, and encrypted to produce the round output.
     The salt is zero throughout this procedure.  */
  des_set_salt (ctx, 0);
  XCRYPT_SECURE_MEMSET (pkbuf, 8);
  for (;;)
    {
      for (i = 0; i < 8; i++)
        {
          keybuf[i] = (uint8_t)(pkbuf[i] ^ (*phrase << 1));
          if (*phrase)
            phrase++;
        }
      des_set_key (ctx, keybuf);
      if (*phrase == 0)
        break;
      des_crypt_block (ctx, pkbuf, keybuf, 1, false);
    }

  /* Proceed as for the traditional DES hash.  */
  des_set_salt (ctx, salt);
  des_gen_hash (ctx, count, cp, pkbuf);
}
#endif

#if INCLUDE_descrypt || INCLUDE_bigcrypt
void
gensalt_descrypt_rn (unsigned long count,
                     const uint8_t *rbytes, size_t nrbytes,
                     uint8_t *output, size_t output_size)
{
  if (output_size < 3)
    {
      errno = ERANGE;
      return;
    }

  if (nrbytes < 2 || count != 0)
    {
      errno = EINVAL;
      return;
    }

  output[0] = ascii64[(unsigned int) rbytes[0] & 0x3f];
  output[1] = ascii64[(unsigned int) rbytes[1] & 0x3f];
  output[2] = '\0';
}
#if INCLUDE_bigcrypt
void
gensalt_bigcrypt_rn (unsigned long count,
                     const uint8_t *rbytes, size_t nrbytes,
                     uint8_t *output, size_t output_size)
{
#if !INCLUDE_descrypt
  /* We need descrypt + 12 bytes.  */
  if (output_size < 3 + 12)
    {
      errno = ERANGE;
      return;
    }
#endif

  /* Same setting string as descrypt, but...  */
  gensalt_descrypt_rn (count, rbytes, nrbytes, output, output_size);

#if !INCLUDE_descrypt
  /* ... add 12 trailing characters to signalize bigcrypt.  */
  XCRYPT_STRCPY_OR_ABORT (output + 2, output_size - 2, "............");
#endif
}
#endif
#endif

#if INCLUDE_bsdicrypt
void
gensalt_bsdicrypt_rn (unsigned long count,
                      const uint8_t *rbytes, size_t nrbytes,
                      uint8_t *output, size_t output_size)
{
  if (output_size < 1 + 4 + 4 + 1)
    {
      errno = ERANGE;
      return;
    }
  if (nrbytes < 3)
    {
      errno = EINVAL;
      return;
    }

  if (count == 0)
    count = 725;
  if (count > 0xffffff)
    count = 0xffffff;

  /* Even iteration counts make it easier to detect weak DES keys from a look
     at the hash, so they should be avoided.  */
  count |= 1;

  unsigned long value =
    ((unsigned long) (unsigned char) rbytes[0] <<  0) |
    ((unsigned long) (unsigned char) rbytes[1] <<  8) |
    ((unsigned long) (unsigned char) rbytes[2] << 16);

  output[0] = '_';

  output[1] = ascii64[(count >>  0) & 0x3f];
  output[2] = ascii64[(count >>  6) & 0x3f];
  output[3] = ascii64[(count >> 12) & 0x3f];
  output[4] = ascii64[(count >> 18) & 0x3f];

  output[5] = ascii64[(value >>  0) & 0x3f];
  output[6] = ascii64[(value >>  6) & 0x3f];
  output[7] = ascii64[(value >> 12) & 0x3f];
  output[8] = ascii64[(value >> 18) & 0x3f];

  output[9] = '\0';
}
#endif

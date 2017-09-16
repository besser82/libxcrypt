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

#include "des.h"
#include "xcrypt-private.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>

#define DES_TRD_OUTPUT_LEN 14                /* SShhhhhhhhhhh0 */
#define DES_EXT_OUTPUT_LEN 21                /* _CCCCSSSShhhhhhhhhhh0 */
#define DES_BIG_OUTPUT_LEN ((16*11) + 2 + 1) /* SS (hhhhhhhhhhh){1,16} 0 */

#define MAX(x,y) ((x)>(y)?(x):(y))

#define DES_MAX_OUTPUT_LEN \
  MAX (DES_TRD_OUTPUT_LEN, MAX (DES_EXT_OUTPUT_LEN, DES_BIG_OUTPUT_LEN))

/* A des_buffer holds the output plus all of the sensitive intermediate
   data.  It may have been allocated by application code, so it may not
   be properly aligned, and besides which DES_MAX_OUTPUT_LEN may be odd.
   The alignment requirement for a des_ctx is no more than
   sizeof(uint32_t), so allowing an extra sizeof(uint32_t) in ctxbuf
   permits us to find a properly-aligned des_ctx within.  */

struct des_buffer
{
  char output[DES_MAX_OUTPUT_LEN];
  uint8_t keybuf[8];
  uint8_t pkbuf[8];
  uint8_t ctxbuf[sizeof (struct des_ctx) + sizeof (uint32_t)];
};

static inline struct des_ctx *
des_get_ctx (struct des_buffer *buf)
{
  uintptr_t ctxp = (uintptr_t) &buf->ctxbuf;
  ctxp = (ctxp + sizeof (uint32_t) - 1) & ~(uintptr_t)sizeof (uint32_t);
  return (struct des_ctx *)ctxp;
}

static inline void
des_wipe_intermediate_data (struct des_buffer *buf)
{
  memset (((char *)buf) + offsetof (struct des_buffer, keybuf),
          0,
          sizeof (struct des_buffer) - offsetof (struct des_buffer, keybuf));
}

static const uint8_t ascii64[] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/* 0000000000111111111122222222223333333333444444444455555555556666 */
/* 0123456789012345678901234567890123456789012345678901234567890123 */

static inline int
ascii_to_bin(char ch)
{
  if (ch > 'z')
    return 0;
  if (ch >= 'a')
    return ch - 'a' + 38;
  if (ch > 'Z')
    return 0;
  if (ch >= 'A')
    return ch - 'A' + 12;
  if (ch > '9')
    return 0;
  if (ch >= '.')
    return ch - '.';
  return 0;
}

/* Generate an 11-character DES password hash into the buffer at
   OUTPUT, and nul-terminate it.  The salt and key have already been
   set.  The plaintext is 64 bits of zeroes, and the raw ciphertext is
   written to cbuf[].  */
static void
des_gen_hash (struct des_ctx *ctx, uint32_t count, char *output,
              uint8_t cbuf[8])
{
  uint8_t plaintext[8];
  memset (plaintext, 0, 8);
  des_crypt_block (ctx, cbuf, plaintext, count, false);

  /* Now encode the result.  */
  const unsigned char *sptr = cbuf;
  const unsigned char *end = sptr + 8;
  unsigned char *dptr = (unsigned char *)output;
  unsigned int c1, c2;

  do
    {
      c1 = *sptr++;
      *dptr++ = ascii64[c1 >> 2];
      c1 = (c1 & 0x03) << 4;
      if (sptr >= end)
        {
          *dptr++ = ascii64[c1];
          break;
        }

      c2 = *sptr++;
      c1 |= c2 >> 4;
      *dptr++ = ascii64[c1];
      c1 = (c2 & 0x0f) << 2;
      if (sptr >= end)
        {
          *dptr++ = ascii64[c1];
          break;
        }

      c2 = *sptr++;
      c1 |= c2 >> 6;
      *dptr++ = ascii64[c1];
      *dptr++ = ascii64[c2 & 0x3f];
    }
  while (sptr < end);
  *dptr = '\0';
}

/* The original UNIX DES-based password hash, no extensions.  */
static char *
crypt_des_trd_rn (const char *key, const char *setting,
                  char *data, size_t size)
{
  /* Ensure we have enough space for a des_buffer in DATA.  */
  if (size < sizeof (struct des_buffer))
    {
      errno = ERANGE;
      return 0;
    }

  struct des_buffer *buf = (struct des_buffer *)data;
  struct des_ctx *ctx = des_get_ctx (buf);
  uint32_t salt = 0;
  uint8_t *keybuf = buf->keybuf, *pkbuf = buf->pkbuf;
  char *output = buf->output;
  int i;

  /* "old"-style: setting - 2 bytes of salt, key - up to 8 characters.
     Note: ascii_to_bin maps all byte values outside the ascii64
     alphabet to zero.  Do not read past the end of the string.  */
  salt = ascii_to_bin (setting[0]);
  if (setting[0])
    salt |= ascii_to_bin (setting[1]) << 6;

  /* Write the canonical form of the salt to the output buffer.  We do
     this instead of copying from the setting because the setting
     might be catastrophically malformed (e.g. a 0- or 1-byte string;
     this could plausibly happen if e.g. login(8) doesn't special-case
     "*" or "!" in the password database).  */
  *output++ = ascii64[salt & 0x3f];
  *output++ = ascii64[(salt >> 6) & 0x3f];

  /* Copy the first 8 characters of the password into keybuf, shifting
     each character up by 1 bit and padding on the right with zeroes.  */
  for (i = 0; i < 8; i++)
    {
      keybuf[i] = *key << 1;
      if (*key)
        key++;
    }

  des_set_key (ctx, keybuf);
  des_set_salt (ctx, salt);
  des_gen_hash (ctx, 25, output, pkbuf);
  des_wipe_intermediate_data (buf);
  return buf->output;
}

/* This is called directly by the obsolete API functions bigcrypt()
   and bigcrypt_r().

   This algorithm is algorithm 0 (default) shipped with the C2 secure
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
char *
crypt_des_big_rn (const char *key, const char *setting,
                  char *data, size_t size)
{
  /* Ensure we have enough space for a des_buffer in DATA.  */
  if (size < sizeof (struct des_buffer))
    {
      errno = ERANGE;
      return 0;
    }

  struct des_buffer *buf = (struct des_buffer *)data;
  struct des_ctx *ctx = des_get_ctx (buf);
  uint32_t salt = 0;
  uint8_t *keybuf = buf->keybuf, *pkbuf = buf->pkbuf;
  char *output = buf->output;
  int i, seg;

  /* The setting string is exactly the same as for a traditional DES
     hash.  */
  salt = ascii_to_bin (setting[0]);
  if (setting[0])
    salt |= ascii_to_bin (setting[1]) << 6;

  *output++ = ascii64[salt & 0x3f];
  *output++ = ascii64[(salt >> 6) & 0x3f];

  for (seg = 0; seg < 16; seg++)
    {
      /* Copy and shift each block as for the traditional DES.  */
      for (i = 0; i < 8; i++)
        {
          keybuf[i] = *key << 1;
          if (*key)
            key++;
        }

      des_set_key (ctx, keybuf);
      des_set_salt (ctx, salt);
      des_gen_hash (ctx, 25, output, pkbuf);

      if (*key == 0)
        break;

      /* change the salt (1st 2 chars of previous block) - this was found
         by dowsing */
      salt = ascii_to_bin (output[0]);
      salt |= ascii_to_bin (output[1]) << 6;
      output += 11;
    }

  des_wipe_intermediate_data (buf);
  return buf->output;
}

/* crypt_rn() entry point for both the original UNIX password hash, with
   its 8-character length limit, and the "bigcrypt" extension to
   permit longer passwords.  */
char *
crypt_des_trd_or_big_rn (const char *key, const char *salt,
                         char *data, size_t size)
{
  if (strlen (salt) > 13)
    return crypt_des_big_rn (key, salt, data, size);
  else
    return crypt_des_trd_rn (key, salt, data, size);
}

/* crypt_rn() entry point for BSD-style extended DES hashes.  */
char *
crypt_des_xbsd_rn (const char *key, const char *setting,
                   char *data, size_t size)
{
  /* Ensure we have enough space for a des_buffer in DATA.  */
  if (size < sizeof (struct des_buffer))
    {
      errno = ERANGE;
      return 0;
    }

  /* If this is true, this function shouldn't have been called.  */
  if (*setting != '_')
    {
      errno = EINVAL;
      return 0;
    }

  struct des_buffer *buf = (struct des_buffer *)data;
  struct des_ctx *ctx = des_get_ctx (buf);
  uint32_t count = 0, salt = 0;
  uint8_t *keybuf = buf->keybuf, *pkbuf = buf->pkbuf;
  char *output = buf->output;
  int i;

  /* "new"-style DES hash:
   	setting - underscore, 4 bytes of count, 4 bytes of salt
   	key - unlimited characters
   */
  for (i = 1; i < 5; i++)
    count |= ascii_to_bin(setting[i]) << ((i - 1) * 6);

  for (i = 5; i < 9; i++)
    salt |= ascii_to_bin(setting[i]) << ((i - 5) * 6);

  memcpy (output, setting, 9);
  output += 9;

  /* Fold passwords longer than 8 bytes into a single DES key using a
     procedure similar to a Merkle-Dåmgard hash construction.  Each
     block is shifted and padded, as for the traditional hash, then
     XORed with the output of the previous round (IV all bits zero),
     set as the DES key, and encrypted to produce the round output.
     The salt is zero throughout this procedure.  */
  des_set_salt (ctx, 0);
  memset (pkbuf, 0, 8);
  for (;;)
    {
      for (i = 0; i < 8; i++)
        {
          keybuf[i] = pkbuf[i] ^ (*key << 1);
          if (*key)
            key++;
        }
      des_set_key (ctx, keybuf);
      if (*key == 0)
        break;
      des_crypt_block (ctx, pkbuf, keybuf, 1, false);
    }

  /* Proceed as for the traditional DES hash.  */
  des_set_salt (ctx, salt);
  des_gen_hash (ctx, count, output, pkbuf);
  des_wipe_intermediate_data (buf);
  return buf->output;
}

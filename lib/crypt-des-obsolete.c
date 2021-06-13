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
 * Adapted for libxcrypt by Björn Esser, 2019
 *	add function-stubs simply setting error to ENOSYS.
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

/* Obsolete DES symmetric cipher API - not to be used in new code.  */

#include "crypt-port.h"
#include "crypt-obsolete.h"
#include "alg-des.h"
#include <errno.h>

#if (INCLUDE_encrypt || INCLUDE_encrypt_r || INCLUDE_setkey || INCLUDE_setkey_r) && \
    !ENABLE_OBSOLETE_API_ENOSYS

static_assert(sizeof (struct des_ctx) + alignof (struct des_ctx)
              <= CRYPT_DATA_INTERNAL_SIZE,
              "crypt_data.internal is too small for struct des_ctx");

/* struct crypt_data is allocated by application code and contains
   only char-typed fields, so its 'internal' field may not be
   sufficiently aligned.  */
static inline struct des_ctx *
get_des_ctx (struct crypt_data *data)
{
  uintptr_t internalp = (uintptr_t) data->internal;
  const uintptr_t align = alignof (struct des_ctx);
  internalp = (internalp + align - 1) & ~(align - 1);
  return (struct des_ctx *)internalp;
}

/* For reasons lost in the mists of time, these functions operate on
   64-*byte* arrays, each of which should be either 0 or 1 - only the
   low bit of each byte is examined.  The DES primitives, much more
   sensibly, operate on 8-byte/64-*bit* arrays.  */

static void
unpack_bits (char bytev[64], const unsigned char bitv[8])
{
  unsigned char c;
  for (int i = 0; i < 8; i++)
    {
      c = bitv[i];
      for (int j = 0; j < 8; j++)
        bytev[i*8 + j] = (char)((c & (0x01 << (7 - j))) != 0);
    }
}

static void
pack_bits (unsigned char bitv[8], const char bytev[64])
{
  unsigned int c;
  for (int i = 0; i < 8; i++)
    {
      c = 0;
      for (int j = 0; j < 8; j++)
        {
          c <<= 1;
          c |= ((unsigned char)bytev[i*8 + j] & 0x01u);
        }
      bitv[i] = (unsigned char)c;
    }
}
#endif

/* Initialize DATA with a DES key, KEY, represented as a byte vector.  */
#if (INCLUDE_setkey_r || INCLUDE_setkey) && !ENABLE_OBSOLETE_API_ENOSYS
static void
do_setkey_r (const char *key, struct des_ctx *ctx)
{
  memset (ctx, 0, sizeof (struct des_ctx));
  des_set_salt (ctx, 0);

  unsigned char bkey[8];
  pack_bits (bkey, key);
  des_set_key (ctx, bkey);
}
#endif

#if INCLUDE_setkey_r
void
setkey_r (ARG_UNUSED (const char *key), ARG_UNUSED (struct crypt_data *data))
{
#if ENABLE_OBSOLETE_API_ENOSYS
  /* This function is not supported in this configuration.  */
  errno = ENOSYS;
#else
  do_setkey_r (key, get_des_ctx (data));
#endif
}
SYMVER_setkey_r;
#endif

/* Encrypt or decrypt one DES block, BLOCK, using the key schedule in
   DATA.  BLOCK is processed in place.  */
#if (INCLUDE_encrypt_r || INCLUDE_encrypt) && !ENABLE_OBSOLETE_API_ENOSYS
static void
do_encrypt_r (char *block, int edflag, struct des_ctx *ctx)
{
  unsigned char bin[8], bout[8];
  pack_bits (bin, block);
  des_crypt_block (ctx, bout, bin, 1, edflag != 0);
  unpack_bits (block, bout);
}
#endif

#if INCLUDE_encrypt_r
void
encrypt_r (char *block, ARG_UNUSED (int edflag),
           ARG_UNUSED (struct crypt_data *data))
{
#if ENABLE_OBSOLETE_API_ENOSYS
  /* Make sure sensitive data is erased in case
     case get_random_bytes() fails.  */
  explicit_bzero(block, 64);

  /* Overwrite sensitive data with random data.  */
  get_random_bytes(block, 64);

  /* This function is not supported in this configuration.  */
  errno = ENOSYS;
#else
  do_encrypt_r (block, edflag, get_des_ctx (data));
#endif
}
SYMVER_encrypt_r;
#endif

/* Even-more-deprecated-than-the-above nonreentrant versions.
   These use a separate state object from the main library's
   nonreentrant crypt().  Unlike with crypt() vs crypt_r(),
   these do not get their own file because they're not compiled
   into the static library anyway.  */

#if (INCLUDE_setkey || INCLUDE_encrypt) && !ENABLE_OBSOLETE_API_ENOSYS
static struct des_ctx nr_encrypt_ctx;
#endif

#if INCLUDE_setkey
void
setkey (ARG_UNUSED (const char *key))
{
#if ENABLE_OBSOLETE_API_ENOSYS
  /* This function is not supported in this configuration.  */
  errno = ENOSYS;
#else
  do_setkey_r (key, &nr_encrypt_ctx);
#endif
}
SYMVER_setkey;
#endif

#if INCLUDE_encrypt
void
encrypt (char *block, ARG_UNUSED (int edflag))
{
#if ENABLE_OBSOLETE_API_ENOSYS
  /* Make sure sensitive data is erased in case
     case get_random_bytes() fails.  */
  explicit_bzero(block, 64);

  /* Overwrite sensitive data with random data.  */
  get_random_bytes(block, 64);

  /* This function is not supported in this configuration.  */
  errno = ENOSYS;
#else
  do_encrypt_r (block, edflag, &nr_encrypt_ctx);
#endif
}
SYMVER_encrypt;
#endif

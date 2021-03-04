/* Obsolete DES symmetric cipher interfaces (encrypt_r, setkey_r).

   Copyright (c) 1994-2021 David Burren, Geoffrey M. Rehmet,
   Mark R V Murray, Zack Weinberg, and Björn Esser.
   Originally part of FreeSec (libcrypt for NetBSD).

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   3. Neither the name of the author nor the names of other contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND ANY
   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  */

#include "crypt-port.h"
#include "crypt-obsolete.h"
#include "alg-des.h"
#include <errno.h>

/* A program that uses encrypt_r necessarily uses setkey_r as well,
   and vice versa.  Therefore, we bend the usual 'one entry point per
   file' principle and have both encrypt_r and setkey_r in this file,
   and the cpp conditionals do not allow for only one of them being
   included in the library.  encrypt/setkey are implemented in terms
   of encrypt_r/setkey_r, so most of this code is enabled for either.  */

#if (INCLUDE_encrypt_r || INCLUDE_encrypt) && !ENABLE_OBSOLETE_API_ENOSYS

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
        bytev[i*8 + j] = (c & (0x01 << (7 - j))) != 0;
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

#if INCLUDE_encrypt_r || INCLUDE_encrypt
void
encrypt_r (char *block, ARG_UNUSED (int edflag),
           ARG_UNUSED (struct crypt_data *data))
{
#if ENABLE_OBSOLETE_API_ENOSYS
  /* Overwrite sensitive data with random data.  */
  get_random_bytes(block, 64);

  /* This function is not supported in this configuration.  */
  errno = ENOSYS;
#else
  unsigned char bin[8], bout[8];

  pack_bits (bin, block);
  des_crypt_block (get_des_ctx (data), bout, bin, 1, edflag != 0);
  unpack_bits (block, bout);

  explicit_bzero (bin, sizeof bin);
  explicit_bzero (bout, sizeof bout);
#endif
}

void
setkey_r (ARG_UNUSED (const char *key), ARG_UNUSED (struct crypt_data *data))
{
#if ENABLE_OBSOLETE_API_ENOSYS
  /* This function is not supported in this configuration.  */
  errno = ENOSYS;
#else
  struct des_ctx *ctx = get_des_ctx (data);
  memset (ctx, 0, sizeof (struct des_ctx));
  des_set_salt (ctx, 0);

  unsigned char bkey[8];
  pack_bits (bkey, key);
  des_set_key (ctx, bkey);
  explicit_bzero (bkey, sizeof bkey);
#endif
}
#endif

#if INCLUDE_encrypt_r
SYMVER_encrypt_r;
SYMVER_setkey_r;
#endif

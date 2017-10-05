/* Declaration of functions and data types used for SHA512 sum computing
   library functions.
   Copyright (C) 2007-2017 Free Software Foundation, Inc.

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

#ifndef _CRYPT_ALG_SHA512_H
#define _CRYPT_ALG_SHA512_H 1

/* Structure to save state of computation between the single steps.  */
struct sha512_ctx
{
  uint64_t H[8];

  uint64_t total[2];
  uint32_t buflen;
  unsigned char buffer[256];
};

/* Initialize structure containing state of computation.
   (FIPS 180-2: 5.3.3)  */
extern void sha512_init_ctx (struct sha512_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function) update the context for the next LEN bytes
   starting at BUFFER.  LEN does not need to be a multiple of 128.  */
extern void sha512_process_bytes (const void *buffer, size_t len,
                                  struct sha512_ctx *ctx);

/* Process the remaining bytes in the buffer and write the finalized
   hash to RESBUF, which should point to 64 bytes of storage.  */
extern void *sha512_finish_ctx (struct sha512_ctx *ctx, void *resbuf);

#endif /* alg-sha512.h */

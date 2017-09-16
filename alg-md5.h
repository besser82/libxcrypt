/* Declaration of functions and data types used for MD5 sum computing
   library functions.
   Copyright (C) 1995-1997,1999,2000,2001,2004,2005
      Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _CRYPT_ALG_MD5_H
#define _CRYPT_ALG_MD5_H 1

#include <stddef.h>
#include <stdint.h>

/* Structure to save state of computation between the single steps.  */
struct md5_ctx
{
  uint32_t A;
  uint32_t B;
  uint32_t C;
  uint32_t D;

  uint64_t total;
  uint32_t buflen;
  unsigned char buffer[128];
};

/* Initialize structure containing state of computation.
   (RFC 1321, 3.3: Step 3)  */
extern void md5_init_ctx (struct md5_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function) update the context for the next LEN bytes
   starting at BUFFER.  LEN does not need to be a multiple of 64.  */
extern void md5_process_bytes (const void *buffer, size_t len,
                               struct md5_ctx *ctx);

/* Process the remaining bytes in the buffer and write the finalized
   hash to RESBUF, which should point to 16 bytes of storage.  */
extern void *md5_finish_ctx (struct md5_ctx *ctx, void *resbuf);

#endif /* alg-md5.h */

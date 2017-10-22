/*
 * This is an implementation of the RSA Data Security, Inc.
 * MD4 Message-Digest Algorithm.
 *
 * Written by Solar Designer <solar@openwall.com> in 2001, and placed in
 * the public domain.  See md4.c for more information.
 */

#ifndef _CRYPT_ALG_MD4_H
#define _CRYPT_ALG_MD4_H 1

#include <stddef.h>
#include <stdint.h>

/* Structure to save state of computation between the single steps.  */
struct md4_ctx
{
  uint32_t lo, hi;
  uint32_t a, b, c, d;
  unsigned char buffer[64];
  uint32_t block[16];
};

/* Initialize structure containing state of computation.
   (RFC 1320, 3.3: Step 3)  */
extern void md4_init_ctx (struct md4_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function) update the context for the next LEN bytes
   starting at BUFFER.  LEN does not need to be a multiple of 64.  */
extern void md4_process_bytes (const void *buffer, struct md4_ctx *ctx, size_t size);

/* Process the remaining bytes in the buffer and write the finalized
   hash to RESBUF, which should point to 16 bytes of storage.  All
   data written to CTX is erased before returning from the function.  */
extern void *md4_finish_ctx (struct md4_ctx *ctx, void *resbuf);

#endif

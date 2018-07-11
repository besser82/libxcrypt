/*
 * MD4 (RFC-1320) message digest.
 * Modified from MD5 code by Andrey Panin <pazke@donpac.ru>
 *
 * Written by Solar Designer <solar@openwall.com> in 2001, and placed in
 * the public domain.  There's absolutely no warranty.
 *
 * This differs from Colin Plumb's older public domain implementation in
 * that no 32-bit integer data type is required, there's no compile-time
 * endianness configuration.
 * The primary goals are portability and ease of use.
 *
 * This implementation is meant to be fast, but not as fast as possible.
 * Some known optimizations are not included to reduce source code size
 * and avoid compile-time configuration.
 */

#include "crypt-port.h"
#include "alg-md4.h"
#include "byteorder.h"

#if INCLUDE_nthash

/*
 * The basic MD4 functions.
 */
#define F(x, y, z)  ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)  (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z)  ((x) ^ (y) ^ (z))

/*
 * The MD4 transformation for all four rounds.
 */
#define STEP(f, a, b, c, d, x, s) \
  (a) += f((b), (c), (d)) + (x);   \
  (a) = ((a) << (s)) | ((a) >> (32 - (s)))

/*
 * SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 *
 * The check for little-endian architectures which tolerate unaligned
 * memory accesses is just an optimization.  Nothing will break if it
 * doesn't work.
 */
#define SET(n) \
  (ctx->block[(n)] = le32_to_cpu (&ptr[(n) * 4]))
#define GET(n) \
  (ctx->block[(n)])

/*
 * This processes one or more 64-byte data blocks, but does NOT update
 * the bit counters.  There're no alignment requirements.
 */
static const unsigned char *
body (struct md4_ctx *ctx, const unsigned char *data, size_t size)
{
  const unsigned char *ptr;
  uint32_t a, b, c, d;
  uint32_t saved_a, saved_b, saved_c, saved_d;

  ptr = data;

  a = ctx->a;
  b = ctx->b;
  c = ctx->c;
  d = ctx->d;

  do
    {
      saved_a = a;
      saved_b = b;
      saved_c = c;
      saved_d = d;

      /* Round 1 */
      STEP(F, a, b, c, d, SET( 0),  3);
      STEP(F, d, a, b, c, SET( 1),  7);
      STEP(F, c, d, a, b, SET( 2), 11);
      STEP(F, b, c, d, a, SET( 3), 19);

      STEP(F, a, b, c, d, SET( 4),  3);
      STEP(F, d, a, b, c, SET( 5),  7);
      STEP(F, c, d, a, b, SET( 6), 11);
      STEP(F, b, c, d, a, SET( 7), 19);

      STEP(F, a, b, c, d, SET( 8),  3);
      STEP(F, d, a, b, c, SET( 9),  7);
      STEP(F, c, d, a, b, SET(10), 11);
      STEP(F, b, c, d, a, SET(11), 19);

      STEP(F, a, b, c, d, SET(12),  3);
      STEP(F, d, a, b, c, SET(13),  7);
      STEP(F, c, d, a, b, SET(14), 11);
      STEP(F, b, c, d, a, SET(15), 19);

      /* Round 2 */
      STEP(G, a, b, c, d, GET( 0) + 0x5A827999,  3);
      STEP(G, d, a, b, c, GET( 4) + 0x5A827999,  5);
      STEP(G, c, d, a, b, GET( 8) + 0x5A827999,  9);
      STEP(G, b, c, d, a, GET(12) + 0x5A827999, 13);

      STEP(G, a, b, c, d, GET( 1) + 0x5A827999,  3);
      STEP(G, d, a, b, c, GET( 5) + 0x5A827999,  5);
      STEP(G, c, d, a, b, GET( 9) + 0x5A827999,  9);
      STEP(G, b, c, d, a, GET(13) + 0x5A827999, 13);

      STEP(G, a, b, c, d, GET( 2) + 0x5A827999,  3);
      STEP(G, d, a, b, c, GET( 6) + 0x5A827999,  5);
      STEP(G, c, d, a, b, GET(10) + 0x5A827999,  9);
      STEP(G, b, c, d, a, GET(14) + 0x5A827999, 13);

      STEP(G, a, b, c, d, GET( 3) + 0x5A827999,  3);
      STEP(G, d, a, b, c, GET( 7) + 0x5A827999,  5);
      STEP(G, c, d, a, b, GET(11) + 0x5A827999,  9);
      STEP(G, b, c, d, a, GET(15) + 0x5A827999, 13);

      /* Round 3 */
      STEP(H, a, b, c, d, GET( 0) + 0x6ED9EBA1,  3);
      STEP(H, d, a, b, c, GET( 8) + 0x6ED9EBA1,  9);
      STEP(H, c, d, a, b, GET( 4) + 0x6ED9EBA1, 11);
      STEP(H, b, c, d, a, GET(12) + 0x6ED9EBA1, 15);

      STEP(H, a, b, c, d, GET( 2) + 0x6ED9EBA1,  3);
      STEP(H, d, a, b, c, GET(10) + 0x6ED9EBA1,  9);
      STEP(H, c, d, a, b, GET( 6) + 0x6ED9EBA1, 11);
      STEP(H, b, c, d, a, GET(14) + 0x6ED9EBA1, 15);

      STEP(H, a, b, c, d, GET( 1) + 0x6ED9EBA1,  3);
      STEP(H, d, a, b, c, GET( 9) + 0x6ED9EBA1,  9);
      STEP(H, c, d, a, b, GET( 5) + 0x6ED9EBA1, 11);
      STEP(H, b, c, d, a, GET(13) + 0x6ED9EBA1, 15);

      STEP(H, a, b, c, d, GET( 3) + 0x6ED9EBA1,  3);
      STEP(H, d, a, b, c, GET(11) + 0x6ED9EBA1,  9);
      STEP(H, c, d, a, b, GET( 7) + 0x6ED9EBA1, 11);
      STEP(H, b, c, d, a, GET(15) + 0x6ED9EBA1, 15);

      a += saved_a;
      b += saved_b;
      c += saved_c;
      d += saved_d;

      ptr += 64;
    }
  while (size -= 64);

  ctx->a = a;
  ctx->b = b;
  ctx->c = c;
  ctx->d = d;

  return ptr;
}

/* Put result from CTX in first 16 bytes following RESBUF.  The result
   will be in little endian byte order.  */
static void *
md4_read_ctx (struct md4_ctx *ctx, void *resbuf)
{
  unsigned char *buf = resbuf;
  cpu_to_le32 (buf +  0, ctx->a);
  cpu_to_le32 (buf +  4, ctx->b);
  cpu_to_le32 (buf +  8, ctx->c);
  cpu_to_le32 (buf + 12, ctx->d);
  XCRYPT_SECURE_MEMSET (ctx, sizeof(struct md4_ctx));
  return resbuf;
}

void
md4_init_ctx (struct md4_ctx *ctx)
{
  ctx->a = 0x67452301;
  ctx->b = 0xefcdab89;
  ctx->c = 0x98badcfe;
  ctx->d = 0x10325476;

  ctx->lo = 0;
  ctx->hi = 0;
}

void
md4_process_bytes (const void *buffer, struct md4_ctx *ctx, size_t size)
{
  uint32_t saved_lo;
  size_t used, free;

  saved_lo = ctx->lo;
  if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
    ctx->hi++;
  ctx->hi += (uint32_t)(size >> 29);

  used = saved_lo & 0x3f;

  if (used)
    {
      free = 64 - used;

      if (size < free)
        {
          memcpy(&ctx->buffer[used], buffer, size);
          return;
        }

      memcpy(&ctx->buffer[used], buffer, free);
      buffer = (const unsigned char *) buffer + free;
      size -= free;
      body(ctx, ctx->buffer, 64);
    }

  if (size >= 64)
    {
      buffer = body(ctx, buffer, size & ~(uint32_t)0x3f);
      size &= 0x3f;
    }

  memcpy(ctx->buffer, buffer, size);
}

void *
md4_finish_ctx (struct md4_ctx *ctx, void *resbuf)
{
  size_t used, free;

  used = ctx->lo & 0x3f;

  ctx->buffer[used++] = 0x80;

  free = 64 - used;

  if (free < 8)
    {
      XCRYPT_SECURE_MEMSET (&ctx->buffer[used], free);
      body(ctx, ctx->buffer, 64);
      used = 0;
      free = 64;
    }

  XCRYPT_SECURE_MEMSET (&ctx->buffer[used], free - 8);

  ctx->lo <<= 3;
  ctx->buffer[56] = (unsigned char)((ctx->lo) & 0xff);
  ctx->buffer[57] = (unsigned char)((ctx->lo >> 8) & 0xff);
  ctx->buffer[58] = (unsigned char)((ctx->lo >> 16) & 0xff);
  ctx->buffer[59] = (unsigned char)((ctx->lo >> 24) & 0xff);
  ctx->buffer[60] = (unsigned char)((ctx->hi) & 0xff);
  ctx->buffer[61] = (unsigned char)((ctx->hi >> 8) & 0xff);
  ctx->buffer[62] = (unsigned char)((ctx->hi >> 16) & 0xff);
  ctx->buffer[63] = (unsigned char)((ctx->hi >> 24) & 0xff);

  body(ctx, ctx->buffer, 64);

  return md4_read_ctx (ctx, resbuf);
}

#endif

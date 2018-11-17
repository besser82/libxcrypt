/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security, Inc.
 * MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Homepage:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 *
 * Author:
 * Alexander Peslyak, better known as Solar Designer <solar at openwall.com>
 *
 * This software was written by Alexander Peslyak in 2001.  No copyright is
 * claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2001 Alexander Peslyak and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 *
 * This differs from Colin Plumb's older public domain implementation in that
 * no exactly 32-bit integer data type is required (any 32-bit or wider
 * unsigned integer data type will do), there's no compile-time endianness
 * configuration, and the function prototypes match OpenSSL's.  No code from
 * Colin Plumb's implementation has been reused; this comment merely compares
 * the properties of the two independent implementations.
 *
 * The primary goals of this implementation are portability and ease of use.
 * It is meant to be fast, but not as fast as possible.  Some known
 * optimizations are not included to reduce source code size and avoid
 * compile-time configuration.
 */

#include "crypt-port.h"

#if INCLUDE_nt

#include "alg-md4.h"

/*
 * The basic MD4 functions.
 *
 * F and G are optimized compared to their RFC 1320 definitions, with the
 * optimization for F borrowed from Colin Plumb's MD5 implementation.
 */
#define MD4_F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define MD4_G(x, y, z)			(((x) & ((y) | (z))) | ((y) & (z)))
#define MD4_H(x, y, z)			((x) ^ (y) ^ (z))

/*
 * The MD4 transformation for all three rounds.
 */
#define MD4_STEP(f, a, b, c, d, x, s) \
	(a) += f((b), (c), (d)) + (x); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

/*
 * SET reads 4 input bytes in little-endian byte order and stores them in a
 * properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned memory
 * accesses is just an optimization.  Nothing will break if it fails to detect
 * a suitable architecture.
 *
 * Unfortunately, this optimization may be a C strict aliasing rules violation
 * if the caller's data buffer has effective type that cannot be aliased by
 * MD4_u32plus.  In practice, this problem may occur if these MD4 routines are
 * inlined into a calling function, or with future and dangerously advanced
 * link-time optimizations.  For the time being, keeping these MD4 routines in
 * their own translation unit avoids the problem.
 */
#if 0 /* defined(__i386__) || defined(__x86_64__) || defined(__vax__) */
#define MD4_SET(n) \
	(*(const MD4_u32plus *)&ptr[(n) * 4])
#define MD4_GET(n) \
	MD4_SET(n)
#else
#define MD4_SET(n) \
	(ctx->block[(n)] = \
	(MD4_u32plus)ptr[(n) * 4] | \
	((MD4_u32plus)ptr[(n) * 4 + 1] << 8) | \
	((MD4_u32plus)ptr[(n) * 4 + 2] << 16) | \
	((MD4_u32plus)ptr[(n) * 4 + 3] << 24))
#define MD4_GET(n) \
	(ctx->block[(n)])
#endif

/*
 * This processes one or more 64-byte data blocks, but does NOT update the bit
 * counters.  There are no alignment requirements.
 */
static const void *MD4_body(MD4_CTX *ctx, const void *data, unsigned long size)
{
	const unsigned char *ptr;
	MD4_u32plus a, b, c, d;
	MD4_u32plus saved_a, saved_b, saved_c, saved_d;
	const MD4_u32plus ac1 = 0x5a827999, ac2 = 0x6ed9eba1;

	ptr = (const unsigned char *)data;

	a = ctx->a;
	b = ctx->b;
	c = ctx->c;
	d = ctx->d;

	do {
		saved_a = a;
		saved_b = b;
		saved_c = c;
		saved_d = d;

/* Round 1 */
		MD4_STEP(MD4_F, a, b, c, d, MD4_SET(0), 3)
		MD4_STEP(MD4_F, d, a, b, c, MD4_SET(1), 7)
		MD4_STEP(MD4_F, c, d, a, b, MD4_SET(2), 11)
		MD4_STEP(MD4_F, b, c, d, a, MD4_SET(3), 19)
		MD4_STEP(MD4_F, a, b, c, d, MD4_SET(4), 3)
		MD4_STEP(MD4_F, d, a, b, c, MD4_SET(5), 7)
		MD4_STEP(MD4_F, c, d, a, b, MD4_SET(6), 11)
		MD4_STEP(MD4_F, b, c, d, a, MD4_SET(7), 19)
		MD4_STEP(MD4_F, a, b, c, d, MD4_SET(8), 3)
		MD4_STEP(MD4_F, d, a, b, c, MD4_SET(9), 7)
		MD4_STEP(MD4_F, c, d, a, b, MD4_SET(10), 11)
		MD4_STEP(MD4_F, b, c, d, a, MD4_SET(11), 19)
		MD4_STEP(MD4_F, a, b, c, d, MD4_SET(12), 3)
		MD4_STEP(MD4_F, d, a, b, c, MD4_SET(13), 7)
		MD4_STEP(MD4_F, c, d, a, b, MD4_SET(14), 11)
		MD4_STEP(MD4_F, b, c, d, a, MD4_SET(15), 19)

/* Round 2 */
		MD4_STEP(MD4_G, a, b, c, d, MD4_GET(0) + ac1, 3)
		MD4_STEP(MD4_G, d, a, b, c, MD4_GET(4) + ac1, 5)
		MD4_STEP(MD4_G, c, d, a, b, MD4_GET(8) + ac1, 9)
		MD4_STEP(MD4_G, b, c, d, a, MD4_GET(12) + ac1, 13)
		MD4_STEP(MD4_G, a, b, c, d, MD4_GET(1) + ac1, 3)
		MD4_STEP(MD4_G, d, a, b, c, MD4_GET(5) + ac1, 5)
		MD4_STEP(MD4_G, c, d, a, b, MD4_GET(9) + ac1, 9)
		MD4_STEP(MD4_G, b, c, d, a, MD4_GET(13) + ac1, 13)
		MD4_STEP(MD4_G, a, b, c, d, MD4_GET(2) + ac1, 3)
		MD4_STEP(MD4_G, d, a, b, c, MD4_GET(6) + ac1, 5)
		MD4_STEP(MD4_G, c, d, a, b, MD4_GET(10) + ac1, 9)
		MD4_STEP(MD4_G, b, c, d, a, MD4_GET(14) + ac1, 13)
		MD4_STEP(MD4_G, a, b, c, d, MD4_GET(3) + ac1, 3)
		MD4_STEP(MD4_G, d, a, b, c, MD4_GET(7) + ac1, 5)
		MD4_STEP(MD4_G, c, d, a, b, MD4_GET(11) + ac1, 9)
		MD4_STEP(MD4_G, b, c, d, a, MD4_GET(15) + ac1, 13)

/* Round 3 */
		MD4_STEP(MD4_H, a, b, c, d, MD4_GET(0) + ac2, 3)
		MD4_STEP(MD4_H, d, a, b, c, MD4_GET(8) + ac2, 9)
		MD4_STEP(MD4_H, c, d, a, b, MD4_GET(4) + ac2, 11)
		MD4_STEP(MD4_H, b, c, d, a, MD4_GET(12) + ac2, 15)
		MD4_STEP(MD4_H, a, b, c, d, MD4_GET(2) + ac2, 3)
		MD4_STEP(MD4_H, d, a, b, c, MD4_GET(10) + ac2, 9)
		MD4_STEP(MD4_H, c, d, a, b, MD4_GET(6) + ac2, 11)
		MD4_STEP(MD4_H, b, c, d, a, MD4_GET(14) + ac2, 15)
		MD4_STEP(MD4_H, a, b, c, d, MD4_GET(1) + ac2, 3)
		MD4_STEP(MD4_H, d, a, b, c, MD4_GET(9) + ac2, 9)
		MD4_STEP(MD4_H, c, d, a, b, MD4_GET(5) + ac2, 11)
		MD4_STEP(MD4_H, b, c, d, a, MD4_GET(13) + ac2, 15)
		MD4_STEP(MD4_H, a, b, c, d, MD4_GET(3) + ac2, 3)
		MD4_STEP(MD4_H, d, a, b, c, MD4_GET(11) + ac2, 9)
		MD4_STEP(MD4_H, c, d, a, b, MD4_GET(7) + ac2, 11)
		MD4_STEP(MD4_H, b, c, d, a, MD4_GET(15) + ac2, 15)

		a += saved_a;
		b += saved_b;
		c += saved_c;
		d += saved_d;

		ptr += 64;
	} while (size -= 64);

	ctx->a = a;
	ctx->b = b;
	ctx->c = c;
	ctx->d = d;

	return ptr;
}

void MD4_Init(MD4_CTX *ctx)
{
	ctx->a = 0x67452301;
	ctx->b = 0xefcdab89;
	ctx->c = 0x98badcfe;
	ctx->d = 0x10325476;

	ctx->lo = 0;
	ctx->hi = 0;
}

void MD4_Update(MD4_CTX *ctx, const void *data, size_t size)
{
	MD4_u32plus saved_lo;
	unsigned long used, available;

	saved_lo = ctx->lo;
	if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
		ctx->hi++;
	ctx->hi += (MD4_u32plus) size >> 29;

	used = saved_lo & 0x3f;

	if (used) {
		available = 64 - used;

		if (size < available) {
			memcpy(&ctx->buffer[used], data, size);
			return;
		}

		memcpy(&ctx->buffer[used], data, available);
		data = (const unsigned char *)data + available;
		size -= available;
		MD4_body(ctx, ctx->buffer, 64);
	}

	if (size >= 64) {
		data = MD4_body(ctx, data, size & ~(unsigned long)0x3f);
		size &= 0x3f;
	}

	memcpy(ctx->buffer, data, size);
}

#define MD4_OUT(dst, src) \
	(dst)[0] = (unsigned char)(src); \
	(dst)[1] = (unsigned char)((src) >> 8); \
	(dst)[2] = (unsigned char)((src) >> 16); \
	(dst)[3] = (unsigned char)((src) >> 24);

void MD4_Final(uint8_t result[16], MD4_CTX *ctx)
{
	unsigned long used, available;

	used = ctx->lo & 0x3f;

	ctx->buffer[used++] = 0x80;

	available = 64 - used;

	if (available < 8) {
		memset(&ctx->buffer[used], 0, available);
		MD4_body(ctx, ctx->buffer, 64);
		used = 0;
		available = 64;
	}

	memset(&ctx->buffer[used], 0, available - 8);

	ctx->lo <<= 3;
	MD4_OUT(&ctx->buffer[56], ctx->lo)
	MD4_OUT(&ctx->buffer[60], ctx->hi)

	MD4_body(ctx, ctx->buffer, 64);

	MD4_OUT(&result[0], ctx->a)
	MD4_OUT(&result[4], ctx->b)
	MD4_OUT(&result[8], ctx->c)
	MD4_OUT(&result[12], ctx->d)

	XCRYPT_SECURE_MEMSET(ctx, sizeof(*ctx));
}

#endif

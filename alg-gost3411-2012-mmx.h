/*
 * Copyright (c) 2013, Alexey Degtyarev <alexey@renatasystems.org>.
 * All rights reserved.
 *
 * $Id$
 */

#ifndef __GOST3411_HAS_MMX__
#error "MMX not enabled in config.h"
#endif

#include <mmintrin.h>

#ifdef __i386__
#define XLPS XLPS32
#else
#define XLPS XLPS64
#endif

#define XLOAD(x, y, xmm0, xmm1, xmm2, xmm3) { \
    const __m128i *px = (const __m128i *) &x[0]; \
    const __m128i *py = (const __m128i *) &y[0]; \
    xmm0 = _mm_xor_si128(px[0], py[0]); \
    xmm1 = _mm_xor_si128(px[1], py[1]); \
    xmm2 = _mm_xor_si128(px[2], py[2]); \
    xmm3 = _mm_xor_si128(px[3], py[3]); \
}

#define UNLOAD(P, xmm0, xmm1, xmm2, xmm3) { \
    __m128i *__m128p = (__m128i *) &P[0]; \
    _mm_store_si128(&__m128p[0], xmm0); \
    _mm_store_si128(&__m128p[1], xmm1); \
    _mm_store_si128(&__m128p[2], xmm2); \
    _mm_store_si128(&__m128p[3], xmm3); \
}

#define TRANSPOSE(xmm0, xmm1, xmm2, xmm3) { \
    __m128i txm0, txm1, txm2, txm3; \
    txm0 = _mm_unpacklo_epi8(xmm0, xmm1); \
    txm1 = _mm_unpackhi_epi8(xmm0, xmm1); \
    txm2 = _mm_unpacklo_epi8(xmm2, xmm3); \
    txm3 = _mm_unpackhi_epi8(xmm2, xmm3); \
    \
    xmm0 = _mm_unpacklo_epi8(txm0, txm1); \
    xmm1 = _mm_unpackhi_epi8(txm0, txm1); \
    xmm2 = _mm_unpacklo_epi8(txm2, txm3); \
    xmm3 = _mm_unpackhi_epi8(txm2, txm3); \
    \
    txm1 = _mm_unpackhi_epi32(xmm0, xmm2); \
    xmm0 = _mm_unpacklo_epi32(xmm0, xmm2); \
    xmm2 = _mm_unpacklo_epi32(xmm1, xmm3); \
    xmm3 = _mm_unpackhi_epi32(xmm1, xmm3); \
    xmm1 = txm1; \
}

#define XTRANSPOSE(x, y, z) { \
    __m128i xmm0, xmm1, xmm2, xmm3; \
    XLOAD(x, y, xmm0, xmm1, xmm2, xmm3); \
    TRANSPOSE(xmm0, xmm1, xmm2, xmm3); \
    UNLOAD(z, xmm0, xmm1, xmm2, xmm3); \
}
#define XLPS32(x, y, data) { \
    unsigned int xi; \
    unsigned char *p; \
    GOST3411_ALIGN(16) gost34112012_uint512_u buf; \
    __m64 mm0; \
    XTRANSPOSE(x, y, (&buf)); \
    p = (unsigned char *) &buf; \
    for (xi = 0; xi < 8; xi++) \
    { \
        mm0 = _mm_cvtsi64_m64(Ax[0][*(p++)]); \
        mm0 = _mm_xor_64(mm0, Ax[1][*(p++)]); \
        mm0 = _mm_xor_64(mm0, Ax[2][*(p++)]); \
        mm0 = _mm_xor_64(mm0, Ax[3][*(p++)]); \
        mm0 = _mm_xor_64(mm0, Ax[4][*(p++)]); \
        mm0 = _mm_xor_64(mm0, Ax[5][*(p++)]); \
        mm0 = _mm_xor_64(mm0, Ax[6][*(p++)]); \
        mm0 = _mm_xor_64(mm0, Ax[7][*(p++)]); \
        data->QWORD[xi] = (unsigned long long) mm0; \
    } \
}

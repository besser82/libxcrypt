/*
 * Copyright (c) 2013, Alexey Degtyarev <alexey@renatasystems.org>.
 * All rights reserved.
 *
 * GOST R 34.11-2012 core and API functions.
 *
 * $Id$
 */

#include "crypt-port.h"

#if INCLUDE_gost_yescrypt

#include "alg-gost3411-2012-core.h"

#pragma GCC diagnostic ignored "-Wcast-align"

#define BSWAP64(x) \
    (((x & 0xFF00000000000000ULL) >> 56) | \
     ((x & 0x00FF000000000000ULL) >> 40) | \
     ((x & 0x0000FF0000000000ULL) >> 24) | \
     ((x & 0x000000FF00000000ULL) >>  8) | \
     ((x & 0x00000000FF000000ULL) <<  8) | \
     ((x & 0x0000000000FF0000ULL) << 24) | \
     ((x & 0x000000000000FF00ULL) << 40) | \
     ((x & 0x00000000000000FFULL) << 56))

void
GOST34112012Cleanup(GOST34112012Context *CTX)
{
    XCRYPT_SECURE_MEMSET(CTX, sizeof (GOST34112012Context));
}

void
GOST34112012Init(GOST34112012Context *CTX, const unsigned int digest_size)
{
    unsigned int i;

    XCRYPT_SECURE_MEMSET(CTX, sizeof (GOST34112012Context));
    CTX->digest_size = digest_size;

    for (i = 0; i < 8; i++)
    {
        if (digest_size == 256)
            CTX->h.QWORD[i] = 0x0101010101010101ULL;
        else
            CTX->h.QWORD[i] = 0x00ULL;
    }
}

static inline void
pad(GOST34112012Context *CTX)
{
    if (CTX->bufsize > 63)
        return;

    XCRYPT_SECURE_MEMSET(CTX->buffer + CTX->bufsize,
        sizeof(CTX->buffer) - CTX->bufsize);

    CTX->buffer[CTX->bufsize] = 0x01;
}

static inline void
add512(const uint512_u *x, const uint512_u *y, uint512_u *r)
{
#ifndef __GOST3411_BIG_ENDIAN__
    unsigned int CF;
    unsigned int i;

    CF = 0;
    for (i = 0; i < 8; i++)
    {
        const unsigned long long left = x->QWORD[i];
        unsigned long long sum;

        sum = left + y->QWORD[i] + CF;
        if (sum != left)
            CF = (sum < left);
        r->QWORD[i] = sum;
    }
#else
    const unsigned char *xp, *yp;
    unsigned char *rp;
    unsigned int i;
    int buf;

    xp = (const unsigned char *) &x[0];
    yp = (const unsigned char *) &y[0];
    rp = (unsigned char *) &r[0];

    buf = 0;
    for (i = 0; i < 64; i++)
    {
        buf = xp[i] + yp[i] + (buf >> 8);
        rp[i] = (unsigned char) buf & 0xFF;
    }
#endif
}

static void
g(uint512_u *h, const uint512_u *N, const unsigned char *m)
{
#ifdef __GOST3411_HAS_SSE2__
    __m128i xmm0, xmm2, xmm4, xmm6; /* XMMR0-quadruple */
    __m128i xmm1, xmm3, xmm5, xmm7; /* XMMR1-quadruple */
    unsigned int i;

    LOAD(N, xmm0, xmm2, xmm4, xmm6);
    XLPS128M(h, xmm0, xmm2, xmm4, xmm6);

    LOAD(m, xmm1, xmm3, xmm5, xmm7);
    XLPS128R(xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    for (i = 0; i < 11; i++)
        ROUND128(i, xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    XLPS128M((&C[11]), xmm0, xmm2, xmm4, xmm6);
    X128R(xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    X128M(h, xmm0, xmm2, xmm4, xmm6);
    X128M(m, xmm0, xmm2, xmm4, xmm6);

    UNLOAD(h, xmm0, xmm2, xmm4, xmm6);

    /* Restore the Floating-point status on the CPU */
    _mm_empty();
#else
    uint512_u Ki, data;
    unsigned int i;

    XLPS(h, N, (&data));

    /* Starting E() */
    Ki = data;
    XLPS((&Ki), ((const uint512_u *) &m[0]), (&data));

    for (i = 0; i < 11; i++)
        ROUND(i, (&Ki), (&data));

    XLPS((&Ki), (&C[11]), (&Ki));
    X((&Ki), (&data), (&data));
    /* E() done */

    X((&data), h, (&data));
    X((&data), ((const uint512_u *) &m[0]), h);
#endif
}

static inline void
stage2(GOST34112012Context *CTX, const unsigned char *data)
{
    uint512_u m;

    memcpy(&m, data, sizeof(m));
    g(&(CTX->h), &(CTX->N), (const unsigned char *)&m);

    add512(&(CTX->N), &buffer512, &(CTX->N));
    add512(&(CTX->Sigma), &m, &(CTX->Sigma));
}

static inline void
stage3(GOST34112012Context *CTX)
{
    uint512_u buf = {{ 0 }};

#ifndef __GOST3411_BIG_ENDIAN__
    buf.QWORD[0] = CTX->bufsize << 3;
#else
    buf.QWORD[0] = BSWAP64(CTX->bufsize << 3);
#endif

    pad(CTX);

    g(&(CTX->h), &(CTX->N), (const unsigned char *) &(CTX->buffer));

    add512(&(CTX->N), &buf, &(CTX->N));
    add512(&(CTX->Sigma), (const uint512_u *) &CTX->buffer[0],
           &(CTX->Sigma));

    g(&(CTX->h), &buffer0, (const unsigned char *) &(CTX->N));

    g(&(CTX->h), &buffer0, (const unsigned char *) &(CTX->Sigma));
    memcpy(&(CTX->hash), &(CTX->h), sizeof (uint512_u));
}

void
GOST34112012Update(GOST34112012Context *CTX, const unsigned char *data, size_t len)
{
    size_t chunksize;

    if (CTX->bufsize) {
        chunksize = 64 - CTX->bufsize;
        if (chunksize > len)
            chunksize = len;

        memcpy(&CTX->buffer[CTX->bufsize], data, chunksize);

        CTX->bufsize += chunksize;
        len -= chunksize;
        data += chunksize;

        if (CTX->bufsize == 64)
        {
            stage2(CTX, CTX->buffer);

            CTX->bufsize = 0;
        }
    }

    while (len > 63)
    {
        stage2(CTX, data);

        data += 64;
        len  -= 64;
    }

    if (len) {
        memcpy(&CTX->buffer, data, len);
        CTX->bufsize = len;
    }
}

void
GOST34112012Final(GOST34112012Context *CTX, unsigned char *digest)
{
    stage3(CTX);

    CTX->bufsize = 0;

    if (CTX->digest_size == 256)
        memcpy(digest, &(CTX->hash.QWORD[4]), 32);
    else
        memcpy(digest, &(CTX->hash.QWORD[0]), 64);

    GOST34112012Cleanup(CTX);
}

#endif /* INCLUDE_gost_yescrypt */

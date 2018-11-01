/*
 * Copyright (c) 2013, Alexey Degtyarev <alexey@renatasystems.org>.
 * All rights reserved.
 *
 * $Id$
 */

#ifndef _CRYPT_ALG_GOST3411_2012_CORE_H
#define _CRYPT_ALG_GOST3411_2012_CORE_H

#if defined _MSC_VER
#define GOST3411_ALIGN(x) __declspec(align(x))
#else
#define GOST3411_ALIGN(x) __attribute__ ((__aligned__(x)))
#endif

#if defined   __GOST3411_HAS_SSE41__
#include "alg-gost3411-2012-sse41.h"
#elif defined __GOST3411_HAS_SSE2__
#include "alg-gost3411-2012-sse2.h"
#elif defined __GOST3411_HAS_MMX__
#include "alg-gost3411-2012-mmx.h"
#else
#include "alg-gost3411-2012-ref.h"
#endif

GOST3411_ALIGN(16) typedef union gost34112012_uint512_u
{
    unsigned long long QWORD[8];
} gost34112012_uint512_u;

#include "alg-gost3411-2012-const.h"
#include "alg-gost3411-2012-precalc.h"

GOST3411_ALIGN(16) typedef struct GOST34112012Context
{
    GOST3411_ALIGN(16) unsigned char buffer[64];
    GOST3411_ALIGN(16) gost34112012_uint512_u hash;
    GOST3411_ALIGN(16) gost34112012_uint512_u h;
    GOST3411_ALIGN(16) gost34112012_uint512_u N;
    GOST3411_ALIGN(16) gost34112012_uint512_u Sigma;
    size_t bufsize;
    unsigned int digest_size;
} GOST34112012Context;

void GOST34112012Init(GOST34112012Context *CTX,
        const unsigned int digest_size);

void GOST34112012Update(GOST34112012Context *CTX, const unsigned char *data,
        size_t len);

void GOST34112012Final(GOST34112012Context *CTX, unsigned char *digest);

void GOST34112012Cleanup(GOST34112012Context *CTX);

#endif /* alg-gost3411-2012-core.h */

/*-
 * Copyright (c) 1998-1999 Whistle Communications, Inc.
 * Copyright (c) 1998-1999 Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 2003 Michael Bretterklieber
 * Copyright (c) 2017-2019 Björn Esser <besser82@fedoraproject.org>
 * Copyright (c) 2017-2019 Zack Weinberg <zackw at panix.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 */

#include "crypt-port.h"

#if INCLUDE_nt

#include "alg-md4.h"

#include <errno.h>
#include <stdlib.h>

#define MD4_HASHLEN        16

typedef struct
{
  MD4_CTX ctx;
  uint8_t unipw[CRYPT_MAX_PASSPHRASE_SIZE * 2];
  unsigned char hash[MD4_HASHLEN];
} crypt_nt_internal_t;

static_assert (sizeof (crypt_nt_internal_t) <= ALG_SPECIFIC_SIZE,
               "ALG_SPECIFIC_SIZE is too small for NTHASH.");

/*
 * NT HASH = md4(str2unicode(phrase))
 */

void
crypt_nt_rn (const char *phrase, size_t phr_size,
             const char *setting, size_t ARG_UNUSED (set_size),
             uint8_t *output, size_t out_size,
             void *scratch, size_t scr_size)
{
  static const char *magic = "$3$";
  static const uint8_t *hexconvtab = (const uint8_t*) "0123456789abcdef";

  if ((out_size < strlen (magic) + MD4_HASHLEN * 2 + 1) ||
      (scr_size < sizeof (crypt_nt_internal_t)))
    {
      errno = ERANGE;
      return;
    }

  if (strncmp (setting, magic, strlen (magic)))
    {
      errno = EINVAL;
      return;
    }

  crypt_nt_internal_t *intbuf = scratch;

  /* Convert the input to UCS-2LE, blindly assuming that it was
     IANA ISO_8859-1:1987 to begin with (i.e. 0x00 .. 0xFF
     encode U+0000 .. U+FFFF; technically this is a superset
     of the original ISO 8859.1).  Note that this does not
     U+0000-terminate intbuf->unipw.  */
  for (size_t i = 0; i < phr_size; i++)
    {
      intbuf->unipw[2*i    ] = (uint8_t)phrase[i];
      intbuf->unipw[2*i + 1] = 0x00;
    }

  /* Compute MD4 of Unicode password.  */
  MD4_Init (&intbuf->ctx);
  MD4_Update (&intbuf->ctx, intbuf->unipw, phr_size * 2);
  MD4_Final (intbuf->hash, &intbuf->ctx);

  /* Write the computed hash to the output buffer.  */
  output += XCRYPT_STRCPY_OR_ABORT (output, out_size, magic);
  *output++ = '$';
  for (size_t i = 0; i < MD4_HASHLEN; i++)
    {
      *output++ = hexconvtab[intbuf->hash[i] >> 4];
      *output++ = hexconvtab[intbuf->hash[i] & 0xf];
    }
  *output = '\0';
}

/* This function simply returns the magic string '$3$',
   so it can be used as SETTING for the crypt function.  */
void
gensalt_nt_rn (unsigned long count,
               ARG_UNUSED(const uint8_t *rbytes),
               ARG_UNUSED(size_t nrbytes),
               uint8_t *output,
               size_t o_size)
{
  const char *prefix = "$3$";

  /* Minimal O_SIZE to store the prefix.  */
  if (o_size < strlen (prefix) + 1)
    {
      errno = ERANGE;
      return;
    }

  if (count != 0)
    {
      errno = EINVAL;
      return;
    }

  XCRYPT_STRCPY_OR_ABORT (output, o_size, prefix);
}

#endif

/* Copyright (C) 2018 vt@altlinux.org
 * Copyright (C) 2018 Björn Esser besser82@fedoraproject.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
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

#if INCLUDE_gost_yescrypt

#include "alg-gost3411-2012-hmac.h"

#include <stdio.h>

static void
dumphex(const void *ptr, size_t size)
{
  size_t i;

  for (i = 0; i < size; i++)
    printf("%02x", ((const unsigned char *)ptr)[i]);
  printf("\n");
}

static int
test_gost2012_hmac(const char *subject, const char *k, size_t ksize,
                   const char *t, size_t tlen, const char *match)
{
  uint8_t digest[32];
  gost_hmac_256_t gostbuf;

  gost_hmac256((const uint8_t *)k, ksize,
               (const uint8_t *)t, tlen, digest, &gostbuf);

  if (memcmp(digest, match, sizeof(digest)))
    {
      fprintf(stderr, "ERROR: %s\n", subject);
      printf("   key: ");
      dumphex(k, ksize);
      printf("   t:   ");
      dumphex(t, tlen);
      printf("   hmac=");
      dumphex(digest, sizeof(digest));
      return 1;
    }
  else
    fprintf(stderr, "   ok: %s\n", subject);

  return 0;
}

int
main (void)
{
  int result = 0;

  result |= test_gost2012_hmac(
              "HMAC_GOSTR3411_2012_256 test vector from P 50.1.113-2016",
              "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
              "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", 32,
              "\x01\x26\xbd\xb8\x78\x00\xaf\x21\x43\x41\x45\x65\x63\x78\x01\x00", 16,
              "\xa1\xaa\x5f\x7d\xe4\x02\xd7\xb3\xd3\x23\xf2\x99\x1c\x8d\x45\x34"
              "\x01\x31\x37\x01\x0a\x83\x75\x4f\xd0\xaf\x6d\x7c\xd4\x92\x2e\xd9"
            );

  return result;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif /* INCLUDE_gost_yescrypt */

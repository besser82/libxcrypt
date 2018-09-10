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
test_gost2012_hash(const char *subject, const char *t, const char *match)
{
  size_t i;
  uint8_t digest[32];
  GOST34112012Context ctx;

  gost_hash256((const uint8_t *)t, strlen(t), digest, &ctx);

  char dgt[32 * 2 + 1];
  for (i = 0; i < sizeof(digest); i++)
    sprintf(&dgt[i * 2], "%02x", digest[i]);

  if (strcmp(dgt, match) != 0)
    {
      fprintf(stderr, "ERROR: %s\n", subject);
      printf("   t[%zu] = ", strlen(t));
      dumphex(t, strlen(t));
      printf("   digest(%zu) = %s",
             sizeof(digest), dgt);
      printf("   expected(%zu) = %s\n",
             strlen(match) / 2, match);
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

  result |= test_gost2012_hash(
              "test vector from example A.1 from GOST-34.11-2012",
              "012345678901234567890123456789012345678901234567890123456789012",
              "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");

  result |= !test_gost2012_hash(
              "false positive test vector",
              "012345678901234567890123456789012345678901234567890123456789012",
              "012345678901234567890123456789012345678901234567890123456789012");

  result |= test_gost2012_hash(
              "test vector from example A.2 from GOST-34.11-2012",
              "\xD1\xE5\x20\xE2\xE5\xF2\xF0\xE8\x2C\x20\xD1\xF2\xF0\xE8\xE1\xEE"
              "\xE6\xE8\x20\xE2\xED\xF3\xF6\xE8\x2C\x20\xE2\xE5\xFE\xF2\xFA\x20"
              "\xF1\x20\xEC\xEE\xF0\xFF\x20\xF1\xF2\xF0\xE5\xEB\xE0\xEC\xE8\x20"
              "\xED\xE0\x20\xF5\xF0\xE0\xE1\xF0\xFB\xFF\x20\xEF\xEB\xFA\xEA\xFB"
              "\x20\xC8\xE3\xEE\xF0\xE5\xE2\xFB",
              "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50");

  /* carry test */
  result |= test_gost2012_hash(
              "carry test vector from gost-engine",
              "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
              "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
              "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
              "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
              "\x16\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
              "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
              "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
              "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x16",
              "81bb632fa31fcc38b4c379a662dbc58b9bed83f50d3a1b2ce7271ab02d25babb");

  return result;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif /* INCLUDE_gost_yescrypt */

/*
 * Copyright (c) 2017, Björn Esser <besser82@fedoraproject.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "crypt-port.h"
#include "alg-sha1.h"
#include "alg-hmac-sha1.h"

#include <stdio.h>
#include <stdlib.h>

#if INCLUDE_sha1crypt

#define HASH_LENGTH 20

static char *
bin_to_char (char *buf, size_t bufsz, const char *data, size_t nbytes)
{
  size_t i;

  buf[0] = '\0';
  if (bufsz <= (nbytes * 2))
    return NULL;
  for (i = 0; i < nbytes; i++)
    {
      (void)sprintf (&buf[i*2], "%02x", (unsigned char)data[i]);
    }
  return buf;
}

static int
char_to_bin (char *buf, size_t bufsz, const char *data, size_t nbytes)
{
  size_t i;
  uint32_t c;

  if (nbytes < 1)
    nbytes = strlen (data);
  nbytes /= 2;
  if (bufsz <= nbytes)
    return 0;
  for (i = 0; i < nbytes; i++)
    {
      if (sscanf (&data[i*2], "%02x", &c) < 1)
        break;
      buf[i] = (char)(c & 0xff);
    }
  buf[i] = 0;
  return (int)i;
}

/*
 * If a test key or data starts with 0x we'll convert to binary.
 */
#define X2B(v, b) do { \
    if (memcmp (v, "0x", 2) == 0) { \
        v += 2; \
        char_to_bin (b, sizeof(b), v, strlen(v)); \
        v = b; \
    } \
} while (0)

/*
 * Run some of the known answer tests from RFC 2202.
 */
int
main (void)
{
  struct test_s
  {
    const char *key;
    const char *data;
    const char *expect;
    const size_t data_size;
  } tests[] =
  {
    {
      "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "Hi There",
      "0xb617318655057264e28bc0b6fb378c8ef146be00",
      8,
    },
    {
      "Jefe",
      "what do ya want for nothing?",
      "0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
      28,
    },
    {
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "0x125d7342b9ac11cd91a39af48aa17b4f63f175d3",
      50,
    },
    {
      "0x0102030405060708090a0b0c0d0e0f10111213141516171819",
      "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "0x4c9007f4026250c6bc8414f9bf50c86c2d7235da",
      50,
    },
    {
      "0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      "Test With Truncation",
      "0x4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
      20,
    },
    {
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "Test Using Larger Than Block-Size Key - Hash Key First",
      "0xaa4ae5e15272d00e95705637ce8a3b55ed402112",
      54,
    },
    {
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
      "0xe8e99d0f45237d786d6bbaa7965c7808bbff1a91",
      73,
    },
    {
      0, 0, 0, 0,
    },
  };
  struct test_s *test = tests;
  char digest[HASH_LENGTH];
  char kbuf[BUFSIZ];
  char dbuf[BUFSIZ];
  int n = 0;

  for (test = tests; test->key; test++)
    {
      X2B(test->key, kbuf);
      X2B(test->data, dbuf);
      hmac_sha1_process_data ((const uint8_t *)test->data, test->data_size,
                              (const uint8_t *)test->key, strlen(test->key), digest);
      strncpy (dbuf, "0x", BUFSIZ);
      bin_to_char (&dbuf[2], (sizeof dbuf) - 2, digest, HASH_LENGTH);

      if (strcmp (dbuf, test->expect) != 0)
        {
          n = 1;
          fputs ("\nkey=", stdout);
          fputs (test->key, stdout);
          fputs (", data=", stdout);
          fputs (test->data, stdout);
          fputs (",\nresult=", stdout);
          fputs (dbuf, stdout);
          fputs (": ", stdout);
          fputs (test->expect, stdout);
          fputs ("\n", stdout);
        }
    }
  return n;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif

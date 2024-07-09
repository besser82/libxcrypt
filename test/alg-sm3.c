/*
 * Copyright (C) 2024 Tianjia Zhang
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
 * 3. Neither the name of the author nor the names of other contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
#include "alg-sm3.h"

#include <stdio.h>

#if INCLUDE_sm3crypt

static const struct
{
  const char *input;
  const char result[32];
} tests[] =
{
  /* Test vectors from OSCCA GM/T 0004-2012: appendix A.  */
  {
    "abc",
    "\x66\xc7\xf0\xf4\x62\xee\xed\xd9\xd1\xf2\xd4\x6b\xdc\x10\xe4\xe2"
    "\x41\x67\xc4\x87\x5c\xf2\xf7\xa2\x29\x7d\xa0\x2b\x8f\x4b\xa8\xe0"
  },
  {
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "\x63\x9b\x6c\xc5\xe6\x4d\x9e\x37\xa3\x90\xb1\x92\xdf\x4f\xa1\xea"
    "\x07\x20\xab\x74\x7f\xf6\x92\xb9\xf3\x8c\x4e\x66\xad\x7b\x8c\x05"
  },
  {
    "",
    "\x1a\xb2\x1d\x83\x55\xcf\xa1\x7f\x8E\x61\x19\x48\x31\xe8\x1a\x8f"
    "\x22\xbe\xc8\xc7\x28\xfe\xfb\x74\x7e\xd0\x35\xeb\x50\x82\xaa\x2b"
  },
  {
    "a",
    "\x62\x34\x76\xac\x18\xf6\x5a\x29\x09\xe4\x3c\x7f\xec\x61\xb4\x9c"
    "\x7e\x76\x4a\x91\xa1\x8c\xcb\x82\xf1\x91\x7a\x29\xc8\x6c\x5e\x88"
  },
  {
    "message digest",
    "\xc5\x22\xa9\x42\xe8\x9b\xd8\x0d\x97\xdd\x66\x6e\x7a\x55\x31\xb3"
    "\x61\x88\xc9\x81\x71\x49\xe9\xb2\x58\xdf\xe5\x1e\xce\x98\xed\x77"
  },
  {
    "abcdefghijklmnopqrstuvwxyz",
    "\xb8\x0f\xe9\x7a\x4d\xa2\x4a\xfc\x27\x75\x64\xf6\x6a\x35\x9e\xf4"
    "\x40\x46\x2a\xd2\x8d\xcc\x6d\x63\xad\xb2\x4d\x5c\x20\xa6\x15\x95"
  },
  {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "\x29\x71\xd1\x0c\x88\x42\xb7\x0c\x97\x9e\x55\x06\x34\x80\xc5\x0b"
    "\xac\xff\xd9\x0e\x98\xe2\xe6\x0d\x25\x12\xab\x8a\xbf\xdf\xce\xc5"
  },
  {
    "123456789012345678901234567890123456789012345678901234567890"
    "12345678901234567890",
    "\xad\x81\x80\x53\x21\xf3\xe6\x9d\x25\x12\x35\xbf\x88\x6a\x56\x48"
    "\x44\x87\x3b\x56\xdd\x7d\xde\x40\x0f\x05\x5b\x7d\xde\x39\x30\x7a"
  }
};


static void
report_failure(int n, const char *tag,
               const char expected[32], uint8_t actual[32])
{
  int i;
  printf ("FAIL: test %d (%s):\n  exp:", n, tag);
  for (i = 0; i < 32; i++)
    {
      if (i % 4 == 0)
        putchar (' ');
      printf ("%02x", (unsigned int)(unsigned char)expected[i]);
    }
  printf ("\n  got:");
  for (i = 0; i < 32; i++)
    {
      if (i % 4 == 0)
        putchar (' ');
      printf ("%02x", (unsigned int)(unsigned char)actual[i]);
    }
  putchar ('\n');
  putchar ('\n');
}

int
main (void)
{
  sm3_ctx ctx;
  uint8_t sum[32];
  int result = 0;
  int cnt;
  int i;

  for (cnt = 0; cnt < (int) ARRAY_SIZE (tests); ++cnt)
    {
      sm3_buf (tests[cnt].input, strlen (tests[cnt].input), sum);
      if (memcmp (tests[cnt].result, sum, 32) != 0)
        {
          report_failure (cnt, "all at once", tests[cnt].result, sum);
          result = 1;
        }

      sm3_init (&ctx);
      for (i = 0; tests[cnt].input[i] != '\0'; ++i)
        sm3_update (&ctx, &tests[cnt].input[i], 1);
      sm3_final (sum, &ctx);
      if (memcmp (tests[cnt].result, sum, 32) != 0)
        {
          report_failure (cnt, "byte by byte", tests[cnt].result, sum);
          result = 1;
        }
    }

  /* Test vector from FIPS 180-2: appendix B.3.  */
  char buf[1000];
  memset (buf, 'a', sizeof (buf));
  sm3_init (&ctx);
  for (i = 0; i < 1000; ++i)
    sm3_update (&ctx, buf, sizeof (buf));
  sm3_final (sum, &ctx);
  static const char expected[32] =
    "\xc8\xaa\xf8\x94\x29\x55\x40\x29\xe2\x31\x94\x1a\x2a\xcc\x0a\xd6"
    "\x1f\xf2\xa5\xac\xd8\xfa\xdd\x25\x84\x7a\x3a\x73\x2b\x3b\x02\xc3";

  if (memcmp (expected, sum, 32) != 0)
    {
      report_failure (cnt, "block by block", expected, sum);
      result = 1;
    }

  return result;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif

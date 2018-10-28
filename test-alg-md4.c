#include "crypt-port.h"
#include "alg-md4.h"

#include <stdio.h>

#if INCLUDE_nt

static const struct
{
  const char *input;
  const char result[16];
} tests[] =
{
  /* Test vectors as defined in RFC 1320, appendix A, section 5.
     https://tools.ietf.org/html/rfc1320#appendix-A.5  */
  {
    "",
    "\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0"
  },
  {
    "a",
    "\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb\x24"
  },
  {
    "abc",
    "\xa4\x48\x01\x7a\xaf\x21\xd8\x52\x5f\xc1\x0a\xe8\x7a\xa6\x72\x9d"
  },
  {
    "message digest",
    "\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01\x4b"
  },
  {
    "abcdefghijklmnopqrstuvwxyz",
    "\xd7\x9e\x1c\x30\x8a\xa5\xbb\xcd\xee\xa8\xed\x63\xdf\x41\x2d\xa9"
  },
  {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "\x04\x3f\x85\x82\xf2\x41\xdb\x35\x1c\xe6\x27\xe1\x53\xe7\xf0\xe4"
  },
  {
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    "\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19\x9c\x3e\x7b\x16\x4f\xcc\x05\x36"
  }
};

static void
report_failure(int n, const char *tag,
               const char expected[16], uint8_t actual[16])
{
  int i;
  printf ("FAIL: test %d (%s):\n  exp:", n, tag);
  for (i = 0; i < 16; i++)
    {
      if (i % 4 == 0)
        putchar (' ');
      printf ("%02x", (unsigned int)(unsigned char)expected[i]);
    }
  printf ("\n  got:");
  for (i = 0; i < 16; i++)
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
  MD4_CTX ctx;
  uint8_t sum[16];
  int result = 0;
  int cnt;
  int i;

  for (cnt = 0; cnt < (int) ARRAY_SIZE (tests); ++cnt)
    {
      MD4_Init (&ctx);
      MD4_Update (&ctx, tests[cnt].input, strlen (tests[cnt].input));
      MD4_Final (sum, &ctx);
      if (memcmp (tests[cnt].result, sum, 16))
        {
          report_failure (cnt, "all at once", tests[cnt].result, sum);
          result = 1;
        }

      MD4_Init (&ctx);
      for (i = 0; tests[cnt].input[i] != '\0'; ++i)
        MD4_Update (&ctx, &tests[cnt].input[i], 1);
      MD4_Final (sum, &ctx);
      if (memcmp (tests[cnt].result, sum, 16))
        {
          report_failure (cnt, "byte by byte", tests[cnt].result, sum);
          result = 1;
        }
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

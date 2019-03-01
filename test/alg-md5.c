#include "crypt-port.h"
#include "alg-md5.h"

#include <stdio.h>

#if INCLUDE_md5crypt || INCLUDE_sunmd5

static const struct
{
  const char *input;
  const char result[16];
} tests[] =
{
  /* "Informal" test vectors from
     https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data
     (these were once in FIPS 180-2, but MD5 has been withdrawn).  */
  {
    "abc",
    "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72"
  },
  {
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "\x82\x15\xef\x07\x96\xa2\x0b\xca\xaa\xe1\x16\xd3\x87\x6c\x66\x4a"
  },
  /* Test vectors from the NESSIE project.  */
  {
    "",
    "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e"
  },
  {
    "a",
    "\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61"
  },
  {
    "message digest",
    "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61\xd0"
  },
  {
    "abcdefghijklmnopqrstuvwxyz",
    "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1\x3b"
  },
  {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d\x9f"
  },
  {
    "123456789012345678901234567890123456789012345678901234567890"
    "12345678901234567890",
    "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6\x7a"
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
  MD5_CTX ctx;
  uint8_t sum[16];
  int result = 0;
  int cnt;
  int i;

  for (cnt = 0; cnt < (int) ARRAY_SIZE (tests); ++cnt)
    {
      MD5_Init (&ctx);
      MD5_Update (&ctx, tests[cnt].input, strlen (tests[cnt].input));
      MD5_Final (sum, &ctx);
      if (memcmp (tests[cnt].result, sum, 16))
        {
          report_failure (cnt, "all at once", tests[cnt].result, sum);
          result = 1;
        }

      MD5_Init (&ctx);
      for (i = 0; tests[cnt].input[i] != '\0'; ++i)
        MD5_Update (&ctx, &tests[cnt].input[i], 1);
      MD5_Final (sum, &ctx);
      if (memcmp (tests[cnt].result, sum, 16))
        {
          report_failure (cnt, "byte by byte", tests[cnt].result, sum);
          result = 1;
        }
    }

  /* The third "informal" test vector from
     <https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data>. */
  char buf[1000];
  memset (buf, 'a', sizeof (buf));
  MD5_Init (&ctx);
  for (i = 0; i < 1000; ++i)
    MD5_Update (&ctx, buf, sizeof (buf));
  MD5_Final (sum, &ctx);
  static const char expected[64] =
    "\x77\x07\xd6\xae\x4e\x02\x7c\x70\xee\xa2\xa9\x35\xc2\x29\x6f\x21";
  if (memcmp (expected, sum, 16) != 0)
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

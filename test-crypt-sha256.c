#include "crypt-port.h"

#include <stdio.h>

#if INCLUDE_sha256crypt

static const struct
{
  const char *salt;
  const char *input;
  const char *expected;
} tests[] =
{
  {
    "$5$saltstring", "Hello world!",
    "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"
  },
  /* explicit specification of rounds=5000 should be allowed and preserved */
  {
    "$5$rounds=5000$saltstring", "Hello world!",
    "$5$rounds=5000$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"
  },
  {
    "$5$rounds=10000$saltstringsaltstring", "Hello world!",
    "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2."
    "opqey6IcA"
  },
  {
    "$5$rounds=1400$anotherlongsaltstring",
    "a very much longer text to encrypt.  This one even stretches over more"
    "than one line.",
    "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12"
    "oP84Bnq1"
  },
  {
    "$5$rounds=77777$short",
    "we have a short salt string but not a short password",
    "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"
  },
  {
    "$5$rounds=123456$asaltof16chars..", "a short string",
    "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/"
    "cZKmF/wJvD"
  },
};

#define ntests ARRAY_SIZE (tests)



int
main (void)
{
  struct crypt_data output;
  int result = 0;
  unsigned int i;

  for (i = 0; i < ntests; ++i)
    {
      char *cp = crypt_r (tests[i].input, tests[i].salt, &output);

      if (strcmp (cp, tests[i].expected) != 0)
        {
          printf ("test %u: expected \"%s\", got \"%s\"\n",
                  i, tests[i].expected, cp);
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

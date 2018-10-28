#include "crypt-port.h"

#include <stdio.h>

#if INCLUDE_nt

static const struct
{
  const char *input;
  const char *expected;
} tests[] =
{
  /* Generated using this perl script:
     #!/usr/bin/perl -n

     use Encode;
     use Digest::MD4 qw(md4_hex);

     chomp;
     printf("%s:\$3\$%s\n", $_, md4_hex(encode("UTF-16LE", $_)));

     echo "$password" | script.pl

     As shown on:
     http://openwall.info/wiki/john/Generating-test-hashes#NT-hash  */
  {
    "",
    "$3$$31d6cfe0d16ae931b73c59d7e0c089c0"
  },
  {
    " ",
    "$3$$71c5391067de41fad6f3063162e5eeff"
  },
  {
    "multiple words seperated by spaces",
    "$3$$51439a927ed19fe271002bb43f355758"
  },
  {
    "multiple word$ $eperated by $pace$ and $pecial character$",
    "$3$$48370cb663dfc4a0a54555764653c7f3"
  },
  {
    ".....",
    "$3$$c68e5da4d65da3c0af82c12b570a70db"
  },
  {
    "a",
    "$3$$186cb09181e2c2ecaac768c47c729904"
  },
  {
    "abc",
    "$3$$e0fba38268d0ec66ef1cb452d5885e53"
  },
  {
    "abcdefghijklmnopqrstuvwxyz",
    "$3$$0bd63185f3484bb000286c85917dc12e"
  },
  {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "$3$$2e74cc46c96ee4caee5df20d0898fef8"
  },
  {
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    "$3$$cf17b1ae2606afa964193690df7543b1"
  },
  {
    "|_337T`/p3",
    "$3$$ca8ad8058c3226764a3af34a8edcbb2e"
  },
  {
    "photojournalism",
    "$3$$83200a50482a6daf45b2902ed52042f2"
  },
  {
    "ecclesiastically",
    "$3$$0b83b68ba7a5ce58ed50bb0f9a5fa06a"
  },
  {
    "congregationalism",
    "$3$$ebd2b24e1ee857784f6ac40fd500077e"
  },
  {
    "dihydrosphingosine",
    "$3$$40fabb09b52fb8a7843f7e1ee723cf03"
  },
  {
    "semianthropological",
    "$3$$1eba95138c99f9a0621d24876eea2868"
  },
  {
    "palaeogeographically",
    "$3$$5d6536aea6febd7b98e373cfd3f28a85"
  },
  {
    "electromyographically",
    "$3$$a27af10e890b5e0856360a4d993eeb77"
  },
  {
    "noninterchangeableness",
    "$3$$3f820d837c34f4019203f9ae5df458e7"
  },
  {
    "electroencephalographically",
    "$3$$ed5d6deb9f1510c55d8c825c05985a42"
  },
  {
    "antidisestablishmentarianism",
    "$3$$bf4dd2e2566dfb4fafae5f7b0ef32470"
  },
  {
    "cyclotrimethylenetrinitramine",
    "$3$$260a9c487c4815769245a28c242ed260"
  },
  {
    "dichlorodiphenyltrichloroethane",
    "$3$$6674a3a9bb08c4e58b2cda57c66ea608"
  },
  {
    "supercalifragilisticexpialidocious",
    "$3$$f5295d5b0a47abecb70ed08bdb6d4e6e"
  }
};

#define ntests ARRAY_SIZE (tests)

int
main (void)
{
  struct crypt_data output;
  int result = 0;
  unsigned int i;
  char prevhash[4 + 32 + 1];

  for (i = 0; i < ntests; ++i)
    {
      char *cp = crypt_r (tests[i].input, "$3$", &output);
      if (strcmp (cp, tests[i].expected) != 0)
        {
          printf ("test %u.0: expected \"%s\", got \"%s\"\n",
                  i, tests[i].expected, cp);
          result = 1;
        }

      strcpy (prevhash, cp);
      cp = crypt_r (tests[i].input, prevhash, &output);
      if (strcmp (cp, prevhash) != 0)
        {
          printf ("test %u.1: expected \"%s\", got \"%s\"\n",
                  i, prevhash, cp);
          result = 1;
        }

      cp = crypt_r (tests[i].input, "$3$__not_used__1234567890abcd", &output);
      if (strcmp (cp, tests[i].expected) != 0)
        {
          printf ("test %u.2: expected \"%s\", got \"%s\"\n",
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

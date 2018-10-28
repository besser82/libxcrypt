#include "crypt-port.h"

#include <stdio.h>

#if INCLUDE_sha512crypt

static const struct
{
  const char *salt;
  const char *input;
  const char *expected;
} tests[] =
{
  {
    "$6$saltstring", "Hello world!",
    "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
    "esI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
  },
  /* explicit specification of rounds=5000 should be allowed and preserved */
  {
    "$6$rounds=5000$saltstring", "Hello world!",
    "$6$rounds=5000$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3"
    "uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
  },
  {
    "$6$rounds=10000$saltstringsaltstring", "Hello world!",
    "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb"
    "HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
  },
  {
    "$6$rounds=1400$anotherlongsaltstring",
    "a very much longer text to encrypt.  This one even stretches over more"
    "than one line.",
    "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wP"
    "vMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"
  },
  {
    "$6$rounds=77777$short",
    "we have a short salt string but not a short password",
    "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0g"
    "ge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"
  },
  {
    "$6$rounds=123456$asaltof16chars..", "a short string",
    "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
    "elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"
  },
};
#define ntests ARRAY_SIZE (tests)


int
main (void)
{
  struct crypt_data output;
  int result = 0;
  size_t i;

  for (i = 0; i < ntests; ++i)
    {
      char *cp = crypt_r (tests[i].input, tests[i].salt, &output);

      if (strcmp (cp, tests[i].expected) != 0)
        {
          printf ("test %u: expected \"%s\", got \"%s\"\n",
                  (unsigned int) i, tests[i].expected, cp);
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

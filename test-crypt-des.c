#include "crypt-port.h"

#include <stdio.h>

#if INCLUDE_descrypt || INCLUDE_bsdicrypt || INCLUDE_bigcrypt

static const struct
{
  const char *salt;
  const char *expected;
  const char *input;
} tests[] =
{
#if INCLUDE_descrypt || INCLUDE_bigcrypt
  /* traditional-DES test vectors from John the Ripper */
  { "CC", "CCNf8Sbh3HDfQ", "U*U*U*U*" },
  { "CC", "CCX.K.MFy4Ois", "U*U***U" },
  { "CC", "CC4rMpbg9AMZ.", "U*U***U*" },
  { "CC", "CC4rMpbg9AMZ.", "\xd5\xaa\xd5\xaa\xaa\xaa\xd5\xaa" },
  { "XX", "XXxzOu6maQKqQ", "*U*U*U*U" },
  { "SD", "SDbsugeBiC58A", "" },
#if INCLUDE_descrypt
  { "CC", "CCNf8Sbh3HDfQ", "U*U*U*U*ignored" },
  { "CC", "CC4rMpbg9AMZ.", "U*U***U*ignored" },
#endif
#endif

#if INCLUDE_bsdicrypt
  /* BSDI-extended-DES, ditto */
  { "_J9..CCCC", "_J9..CCCCXBrJUJV154M", "U*U*U*U*" },
  { "_J9..CCCC", "_J9..CCCCXUhOBTXzaiE", "U*U***U" },
  { "_J9..CCCC", "_J9..CCCC4gQ.mB/PffM", "U*U***U*" },
  { "_J9..XXXX", "_J9..XXXXvlzQGqpPPdk", "*U*U*U*U" },
  { "_J9..XXXX", "_J9..XXXXsqM/YSSP..Y", "*U*U*U*U*" },
  { "_J9..XXXX", "_J9..XXXXVL7qJCnku0I", "*U*U*U*U*U*U*U*U" },
  { "_J9..XXXX", "_J9..XXXXAj8cFbP5scI", "*U*U*U*U*U*U*U*U*" },
  {
    "_J9..XXXX", "_J9..XXXXAj8cFbP5scI", "\xaa\xd5\xaa\xd5\xaa\xd5\xaa\xd5\xaa"
    "\xd5\xaa\xd5\xaa\xd5\xaa\xd5\xaa"
  },
  { "_J9..SDiz", "_J9..SDizh.vll5VED9g", "ab1234567" },
  { "_J9..SDiz", "_J9..SDizRjWQ/zePPHc", "cr1234567" },
  { "_J9..SDiz", "_J9..SDizxmRI1GjnQuE", "zxyDPWgydbQjgq" },
  { "_K9..Salt", "_K9..SaltNrQgIYUAeoY", "726 even" },
  { "_J9..SDSD", "_J9..SDSD5YGyRCr4W4c", "" },
#endif

#if INCLUDE_bigcrypt
  /* 10 bigcrypt test vectors from pw-fake-unix.gz from the openwall
     wiki.  All have two blocks.  The salt is padded with dots because
     crypt_r will only use bigcrypt if the setting string begins with
     a traditional DES salt but is too long to be a traditional DES
     hashed password.  */
  { "Cx..............", "CxcR5MY6TS58EVRba0DA/cW.", "alexander" },
  { "eA..............", "eAefYgT7O7cWwShgVcvPCWpU", "basketball" },
  { "6M..............", "6MvZdspyAL4QEId8ugLUEeDs", "stephanie" },
  { "yK..............", "yKeFi29DfxXCMFzjVJOeaENI", "sunflower" },
  { "vP..............", "vPg8Hd0cexDL.9m/J3pgIR5g", "chocolate" },
  { "MO..............", "MOZvn6LQiwA0UuKZQ.TsDlQo", "katherine" },
  { "MM..............", "MMSKdTXbtmJOEQI5wMYARXvA", "porsche911" },
  { "gC..............", "gCp41sS/OAC8kMNyK5vvZZEk", "thunderbird" },
  { "7S..............", "7SH0R.zErBC/AZBmehOoEQvw", "beautiful" },
  { "Xh..............", "XhWbBsxo8cYpYvYwQItwv0qc", "challenge" },

  /* bigcrypt still discards the 8th bit of every character.  */
  {
    "Cx..............", "CxcR5MY6TS58EVRba0DA/cW.",
    "\xe1\xec\xe5\xf8\xe1\xee\xe4\xe5\xf2" /* alexander */
  },
  {
    "6M..............", "6MvZdspyAL4QEId8ugLUEeDs",
    "\xf3\xf4\xe5\xf0\xe8\xe1\xee\xe9\xe5" /* stephanie */
  },
#endif
};

#define ntests ARRAY_SIZE (tests)

int
main (void)
{
  struct crypt_data output;
  int result = 0;
  unsigned int i;
  char prevhash[25];

  for (i = 0; i < ntests; ++i)
    {
      char *cp = crypt_r (tests[i].input, tests[i].salt, &output);

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

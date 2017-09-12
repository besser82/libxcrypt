#include <string.h>
#include <stdio.h>

#include "crypt.h"

static const char *const entropy[] = {
  "\x58\x35\xcd\x26\x03\xab\x2c\x14\x92\x13\x1e\x59\xb0\xbc\xfe\xd5",
  "\x9b\x35\xa2\x45\xeb\x68\x9e\x8f\xd9\xa9\x09\x71\xcc\x4d\x21\x44",
  "\x25\x13\xc5\x94\xc3\x93\x1d\xf4\xfd\xd4\x4f\xbd\x10\xe5\x28\x08",
  "\xa0\x2d\x35\x70\xa8\x0b\xc3\xad\xdf\x61\x69\xb3\x19\xda\x7e\x8d",
  0
};

struct testcase
{
  const char *prefix;
  unsigned int expected_len;
};

const struct testcase testcases[] = {
  { "", 2 }, // DES
  { "_", 9 }, // BSDi extended DES
  { "$1$", 11 }, // MD5
  { "$5$", 11 }, // SHA-2-256
  { "$6$", 11 }, // SHA-2-512
  { "$2a$", 29 }, // bcrypt mode A
  { "$2b$", 29 }, // bcrypt mode B
  { "$2x$", 29 }, // bcrypt mode X
  { "$2y$", 29 }, // bcrypt mode Y
  { 0, 0 }
};

int
main (void)
{
  int status = 0;
  unsigned int ent;
  const struct testcase *tcase;
  char output[CRYPT_GENSALT_OUTPUT_SIZE];
  char prev_output[CRYPT_GENSALT_OUTPUT_SIZE];

  for (tcase = testcases; tcase->prefix; tcase++)
    {
      memset (prev_output, 0, CRYPT_GENSALT_OUTPUT_SIZE);
      for (ent = 0; entropy[ent]; ent++)
        {
          memset (output, 0, CRYPT_GENSALT_OUTPUT_SIZE);
          char *salt = crypt_gensalt_r (tcase->prefix, 0,
                                        entropy[ent], 16,
                                        output, CRYPT_GENSALT_OUTPUT_SIZE);
          unsigned int slen = strlen (salt);
          if (slen != tcase->expected_len)
            {
              fprintf (stderr, "ERROR: %s/%u -> %s (expected len=%u got %u)\n",
                       tcase->prefix, ent, salt,
                       tcase->expected_len, slen);
              status = 1;
            }
          else if (strncmp (salt, tcase->prefix, strlen (tcase->prefix)))
            {
              fprintf (stderr, "ERROR: %s/%u -> %s (prefix wrong)\n",
                       tcase->prefix, ent, salt);
              status = 1;
            }
          else if (!strcmp (salt, prev_output))
            {
              fprintf (stderr, "ERROR: %s/%u -> %s (same as prev)\n",
                       tcase->prefix, ent, salt);
              status = 1;
            }
          else
            fprintf (stderr, "   ok: %s/%u -> %s\n",
                     tcase->prefix, ent, salt);

          /* Note: strncpy's somewhat odd fill-to-size-with-NULs behavior
             is specifically wanted in this case.  */
          strncpy (prev_output, salt, CRYPT_GENSALT_OUTPUT_SIZE);
        }
    }

  return status;
}

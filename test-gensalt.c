#include "crypt-port.h"
#include "crypt-base.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static const char *const entropy[] =
{
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

static const struct testcase testcases[] =
{
#if ENABLE_WEAK_HASHES
  { "",       2 }, // DES
  { "_",      9 }, // BSDi extended DES
  { "$1$",   11 }, // MD5
  { "$3$",   29 }, // NTHASH
  { "$md5",  27 }, // SUNMD5
  { "$sha1", 34 }, // PBKDF with SHA1
#endif
  { "$5$",   19 }, // SHA-2-256
  { "$6$",   19 }, // SHA-2-512
  { "$2a$",  29 }, // bcrypt mode A
  { "$2b$",  29 }, // bcrypt mode B
  { "$2x$",  29 }, // bcrypt mode X
  { "$2y$",  29 }, // bcrypt mode Y
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
      XCRYPT_SECURE_MEMSET (prev_output, CRYPT_GENSALT_OUTPUT_SIZE);
      for (ent = 0; ent < (sizeof entropy / sizeof entropy[0]); ent++)
        {
          XCRYPT_SECURE_MEMSET (output, CRYPT_GENSALT_OUTPUT_SIZE);
          char *salt = crypt_gensalt_rn (tcase->prefix, 0,
                                         entropy[ent], 16,
                                         output, CRYPT_GENSALT_OUTPUT_SIZE);
          if (salt == 0)
            {
              if (entropy[ent] == 0 && errno == ENOSYS)
                {
                  fprintf (stderr, "UNSUPPORTED: %s/auto-entropy -> ENOSYS\n",
                           tcase->prefix);
                }
              else
                {
                  fprintf (stderr, "ERROR: %s/%u -> 0\n", tcase->prefix, ent);
                  status = 1;
                }
              continue;
            }
          size_t slen = strlen (salt);
          if (slen != tcase->expected_len)
            {
              fprintf (stderr,
                       "ERROR: %s/%u -> %s (expected len=%u got %zu)\n",
                       tcase->prefix, ent, salt, tcase->expected_len, slen);
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

  /* Currently, passing a null pointer as the prefix argument to
     crypt_gensalt is supposed to produce a bcrypt-mode-2b setting
     string.  */
  {
    char *setting1, *setting2;
    setting1 = crypt_gensalt_ra ("$2b$", 0, entropy[0], 16);
    setting2 = crypt_gensalt_ra (0, 0, entropy[0], 16);
    if (strcmp (setting1, setting2))
      {
        printf ("FAILED: crypt_gensalt defaulting to $2b$\n"
                "  $2b$ -> %s\n"
                "  null -> %s\n",
                setting1, setting2);
        status = 1;
      }
    free (setting1);
    free (setting2);
  }

  /* FIXME: This test is a little too specific.  It used to be in
     test-bcrypt.c and I'm not sure what it's meant to be testing.  */
  {
    char *setting1, *setting2;
    const char *which = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    setting1 = crypt_gensalt (which, 12, "CCCCCCCCCCCCCCCCCCCCC", 21);
    if (!setting1 || strncmp (setting1, "$2a$12$", 7))
      {
        printf ("FAILED (crypt_gensalt: wrong prefix) s1=%s\n", setting1);
        status = 1;
      }

    setting2 = crypt_gensalt_ra (setting1, 12, "CCCCCCCCCCCCCCCCCCCCC", 21);
    if (strcmp (setting1, setting2))
      {
        printf ("FAILED (crypt_gensalt_ra/1: s1=%s s2=%s)\n", setting1, setting2);
        status = 1;
      }

    setting1 = crypt_gensalt_ra (setting2, 12, "DCCCCCCCCCCCCCCCCCCCC", 21);
    if (!strcmp (setting1, setting2))
      {
        printf ("FAILED (crypt_gensalt_ra/2: s1=%s s2=%s)\n", setting1, setting2);
        status = 1;
      }

    free (setting1);
    free (setting2);
  }

  return status;
}

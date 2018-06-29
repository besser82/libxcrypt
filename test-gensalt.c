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

#if ENABLE_WEAK_HASHES
static const char *const des_expected_output[] = { "Mp", "Pp", "ZH", "Uh"};
static const char *const md5_expected_output[] = {
  "$1$MJHnaAke",
  "$1$PKXc3hCO",
  "$1$ZAFlICwY",
  "$1$UqGBkVu0"
};
#if ENABLE_WEAK_NON_GLIBC_HASHES
static const char *const bsdi_expected_output[] = {
  "_J9..MJHn",
  "_J9..PKXc",
  "_J9..ZAFl",
  "_J9..UqGB"
};
static const char *const nthash_expected_output[] = {
  "$3$__not_used__c809a450df09a3",
  "$3$__not_used__30d0d6f834c0c3",
  "$3$__not_used__0eeeebb83d6fe4",
  "$3$__not_used__1c690d6a9ef88c"
};
#define sunmd5_expected_output 0 /* output is not deterministic */
#define pbkdf_expected_output 0  /* output is not deterministic */
#endif
#endif
static const char *const sha256_expected_output[] = {
  "$5$MJHnaAkegEVYHsFK",
  "$5$PKXc3hCOSyMqdaEQ",
  "$5$ZAFlICwYRETzIzIj",
  "$5$UqGBkVu01rurVZqg"
};
static const char *const sha512_expected_output[] = {
  "$6$MJHnaAkegEVYHsFK",
  "$6$PKXc3hCOSyMqdaEQ",
  "$6$ZAFlICwYRETzIzIj",
  "$6$UqGBkVu01rurVZqg"
};
static const char *const bcrypt_a_expected_output[] = {
  "$2a$05$UBVLHeMpJ/QQCv3XqJx8zO",
  "$2a$05$kxUgPcrmlm9XoOjvxCyfP.",
  "$2a$05$HPNDjKMRFdR7zC87CMSmA.",
  "$2a$05$mAyzaIeJu41dWUkxEbn8hO"
};
static const char *const bcrypt_b_expected_output[] = {
  "$2b$05$UBVLHeMpJ/QQCv3XqJx8zO",
  "$2b$05$kxUgPcrmlm9XoOjvxCyfP.",
  "$2b$05$HPNDjKMRFdR7zC87CMSmA.",
  "$2b$05$mAyzaIeJu41dWUkxEbn8hO"
};
static const char *const bcrypt_x_expected_output[] = {
  "$2x$05$UBVLHeMpJ/QQCv3XqJx8zO",
  "$2x$05$kxUgPcrmlm9XoOjvxCyfP.",
  "$2x$05$HPNDjKMRFdR7zC87CMSmA.",
  "$2x$05$mAyzaIeJu41dWUkxEbn8hO"
};
static const char *const bcrypt_y_expected_output[] = {
  "$2y$05$UBVLHeMpJ/QQCv3XqJx8zO",
  "$2y$05$kxUgPcrmlm9XoOjvxCyfP.",
  "$2y$05$HPNDjKMRFdR7zC87CMSmA.",
  "$2y$05$mAyzaIeJu41dWUkxEbn8hO"
};

struct testcase
{
  const char *prefix;
  const char *const *expected_output;
  unsigned int expected_len;
  unsigned int expected_auto_len;
};

static const struct testcase testcases[] =
{
#if ENABLE_WEAK_HASHES
  { "",      des_expected_output,       2,  0 }, // DES
  { "$1$",   md5_expected_output,      11,  0 }, // MD5
#if ENABLE_WEAK_NON_GLIBC_HASHES
  { "_",     bsdi_expected_output,      9,  0 }, // BSDi extended DES
  { "$3$",   nthash_expected_output,   29,  0 }, // NTHASH
  { "$md5",  sunmd5_expected_output,   27,  0 }, // SUNMD5
  { "$sha1", pbkdf_expected_output,    34, 74 }, // PBKDF with SHA1
#endif
#endif
  { "$5$",   sha256_expected_output,   19,  0 }, // SHA-2-256
  { "$6$",   sha512_expected_output,   19,  0 }, // SHA-2-512
  { "$2a$",  bcrypt_a_expected_output, 29,  0 }, // bcrypt mode A
  { "$2b$",  bcrypt_b_expected_output, 29,  0 }, // bcrypt mode B
  { "$2x$",  bcrypt_x_expected_output, 29,  0 }, // bcrypt mode X
  { "$2y$",  bcrypt_y_expected_output, 29,  0 }, // bcrypt mode Y
  { 0, 0, 0, 0 }
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
      for (ent = 0; ent < ARRAY_SIZE (entropy); ent++)
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
          unsigned int expected_len =
                  (!entropy[ent] && tcase->expected_auto_len) ?
                  tcase->expected_auto_len : tcase->expected_len;
          if (slen != expected_len)
            {
              fprintf (stderr,
                       "ERROR: %s/%u -> %s (expected len=%u got %zu)\n",
                       tcase->prefix, ent, salt, expected_len, slen);
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
          else if (entropy[ent] && tcase->expected_output &&
                   strcmp (salt, tcase->expected_output[ent]))
            {
              fprintf (stderr, "ERROR: %s/%u -> %s (expected %s)\n",
                       tcase->prefix, ent, salt, tcase->expected_output[ent]);
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

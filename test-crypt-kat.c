/* Test crypt() API with "known answer" hashes.

   Written by Zack Weinberg <zackw at panix.com> in 2019.
   To the extent possible under law, Zack Weinberg has waived all
   copyright and related or neighboring rights to this work.

   See https://creativecommons.org/publicdomain/zero/1.0/ for further
   details.  */

#include "crypt-port.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/* This test verifies three things at once:
    - crypt, crypt_r, crypt_rn, and crypt_ra all produce the
      same outputs for the same inputs.
    - given hash <- crypt(phrase, setting),
       then hash == crypt(phrase, hash) also.
    - crypt(phrase, setting) == crypt'(phrase, setting)
      where crypt' is an independent implementation of the same
      hashing method.  (This is the "known answer" part of the test.)

   The independent implementations come from the Python 'passlib'
   library: <https://passlib.readthedocs.io/en/stable/>.
   See test-crypt-kat-gen.py for more detail.  */

struct testcase
{
  const char *salt;
  const char *expected;
  const char *input;
};

static const struct testcase tests[] =
{
#include "test-crypt-kat.inc"
};
#define ntests ARRAY_SIZE (tests)

/* The test logic is structured the way it is in order to make the
   expensive part (computing a whole bunch of hashes) parallelizable
   later.  */

struct testresult
{
  char h_crypt[CRYPT_OUTPUT_SIZE];
  char h_crypt_r[CRYPT_OUTPUT_SIZE];
  char h_crypt_rn[CRYPT_OUTPUT_SIZE];
  char h_crypt_ra[CRYPT_OUTPUT_SIZE];
  char h_recrypt[CRYPT_OUTPUT_SIZE];
};

/* Summarize the result of a single hashing operation in a format that
   will be easy for main to process.  Specifically: if the output is
   as expected, the string written to 'dest' will be the hash string.
   If the output is _not_ as expected, the string written to 'dest'
   will contain at least one '!', and will record enough information
   to diagnose the failure.  main will report a test failure for any
   string containing an '!', and will also report a failure if any of
   the fields of a 'struct testresult' is not the same as the others.  */

static void
record_result (char *dest, const char *hash, int errnm,
               const struct testcase *tcase,
               bool expect_failure_tokens)
{
  if (hash && hash[0] != '*')
    {
      if (!tcase->expected || !strcmp(hash, tcase->expected))
        snprintf (dest, CRYPT_OUTPUT_SIZE, "%s", hash);
      else
        snprintf (dest, CRYPT_OUTPUT_SIZE, "!not as expected: %s !=\t %s",
                  hash, tcase->expected);
    }
  else
    {
      /* Ill-formed setting string arguments to 'crypt' are tested in a
         different program, so we never _expect_ a failure.  However, if
         we do get a failure, we want to log it in detail.  */

      /* errno should have been set.  */
      const char *errmsg;
      if (errnm)
        errmsg = strerror (errnm);
      else
        errmsg = "errno not set";

      /* Should the API used have generated a NULL or a failure token?  */
      const char *ftstatus = "";
      if (hash == 0 && expect_failure_tokens)
        ftstatus = ", failure token not generated";
      if (hash != 0 && !expect_failure_tokens)
        ftstatus = ", failure token wrongly generated";

      /* A failure token must never compare equal to the setting string
         that was used in the computation.  N.B. recrypt uses crypt_rn,
         which never produces failure tokens, so in this branch we can
         safely assume that the setting string used was tcase->salt
         (if it generates one anyway that's an automatic failure).  */
      const char *ftmatch = "";
      if (hash != 0 && !strcmp (tcase->salt, hash))
        ftmatch = ", failure token == salt";

      if (hash == 0)
        hash = "(null)";

      snprintf (dest, CRYPT_OUTPUT_SIZE, "!got %s: %s%s%s",
                hash, errmsg, ftstatus, ftmatch);
    }
}

static void *
calc_hashes_crypt (void *results_)
{
  struct testresult *results = results_;
  char *hash;
  size_t i;

  for (i = 0; i < ntests; i++)
    {
      errno = 0;
      hash = crypt (tests[i].input, tests[i].salt);
      record_result (results[i].h_crypt, hash, errno, &tests[i],
                     ENABLE_FAILURE_TOKENS);
    }

  return 0;
}

static void *
calc_hashes_crypt_r (void *results_)
{
  struct testresult *results = results_;
  char *hash;
  size_t i;
  struct crypt_data data;

  memset (&data, 0, sizeof data);
  for (i = 0; i < ntests; i++)
    {
      errno = 0;
      hash = crypt_r (tests[i].input, tests[i].salt, &data);
      record_result (results[i].h_crypt_r, hash, errno, &tests[i],
                     ENABLE_FAILURE_TOKENS);
    }

  return 0;
}

static void *
calc_hashes_crypt_rn (void *results_)
{
  struct testresult *results = results_;
  char *hash;
  size_t i;
  struct crypt_data data;

  memset (&data, 0, sizeof data);
  for (i = 0; i < ntests; i++)
    {
      errno = 0;
      hash = crypt_rn (tests[i].input, tests[i].salt, &data, (int)sizeof data);
      record_result (results[i].h_crypt_rn, hash, errno, &tests[i], false);
    }

  return 0;
}

static void *
calc_hashes_crypt_ra (void *results_)
{
  struct testresult *results = results_;
  char *hash;
  size_t i;
  void *datap = 0;
  int datasz = 0;

  for (i = 0; i < ntests; i++)
    {
      errno = 0;
      hash = crypt_ra (tests[i].input, tests[i].salt, &datap, &datasz);
      record_result (results[i].h_crypt_ra, hash, errno, &tests[i], false);
    }

  free (datap);
  return 0;
}

static void *
calc_hashes_recrypt (void *results_)
{
  struct testresult *results = results_;
  char *hash;
  size_t i;
  struct crypt_data data;

  memset (&data, 0, sizeof data);
  for (i = 0; i < ntests; i++)
    if (results[i].h_crypt_rn[0] != '*')
      {
        errno = 0;
        hash = crypt_rn (tests[i].input, results[i].h_crypt_rn, &data,
                         (int)sizeof data);
        record_result (results[i].h_recrypt, hash, errno, &tests[i], false);
      }

  return 0;
}

static void
print_escaped (const char *s)
{
  const unsigned char *p = (const unsigned char *)s;
  for (; *p; p++)
    if (0x20 <= *p && *p <= 0x7E && *p != '\\' && *p != '\"')
      putchar (*p);
    else
      printf ("\\x%02x", (unsigned int)*p);
}

static void
report_error (const char *badhash, const struct testcase *tc,
              const char *mismatched, const char *tag)
{
  printf ("FAIL: %s/", tc->salt);
  print_escaped (tc->input);
  printf (": crypt%s: got %s", tag, badhash);
  if (mismatched)
    printf (" (mismatch: %s)", mismatched);
  putchar ('\n');
}

static void
report_success (const char *hash,
                const struct testcase *tc)
{
  printf ("ok: %s/", tc->salt);
  print_escaped (tc->input);
  printf (" -> %s\n", hash);
}

int
main (void)
{
  if (ntests == 0)
    return 77; /* UNSUPPORTED if there are no tests to run */

  int rv = 0;
  struct testresult *results = calloc (ntests, sizeof (struct testresult));
  if (!results)
    {
      fprintf (stderr, "failed to allocate %zu bytes: %s\n",
               ntests * sizeof (struct testresult), strerror (errno));
      return 1;
    }

  calc_hashes_crypt (results);
  calc_hashes_crypt_r (results);
  calc_hashes_crypt_rn (results);
  calc_hashes_crypt_ra (results);
  calc_hashes_recrypt (results);

  for (size_t i = 0; i < ntests; i++)
    {
      int failed = 0;
      if (strchr (results[i].h_crypt, '!'))
        {
          report_error (results[i].h_crypt, &tests[i], 0, "");
          failed = 1;
        }
      if (strchr (results[i].h_crypt_r, '!'))
        {
          report_error (results[i].h_crypt_r, &tests[i], 0, "_r");
          failed = 1;
        }
      if (strchr (results[i].h_crypt_rn, '!'))
        {
          report_error (results[i].h_crypt_rn, &tests[i], 0, "_rn");
          failed = 1;
        }
      if (strchr (results[i].h_crypt_ra, '!'))
        {
          report_error (results[i].h_crypt_ra, &tests[i], 0, "_ra");
          failed = 1;
        }
      if (strchr (results[i].h_recrypt, '!'))
        {
          report_error (results[i].h_recrypt, &tests[i], 0, "_rn (recrypt)");
          failed = 1;
        }

      if (!failed)
        {
          if (strcmp (results[i].h_crypt_r, results[i].h_crypt))
            {
              report_error (results[i].h_crypt_r, &tests[i],
                            results[i].h_crypt, "_r");
              failed = 1;
            }
          if (strcmp (results[i].h_crypt_rn, results[i].h_crypt))
            {
              report_error (results[i].h_crypt_rn, &tests[i],
                            results[i].h_crypt, "_rn");
              failed = 1;
            }
          if (strcmp (results[i].h_crypt_ra, results[i].h_crypt))
            {
              report_error (results[i].h_crypt_ra, &tests[i],
                            results[i].h_crypt, "_ra");
              failed = 1;
            }
          if (strcmp (results[i].h_recrypt, results[i].h_crypt))
            {
              report_error (results[i].h_recrypt, &tests[i],
                            results[i].h_crypt, "_rn (recrypt)");
              failed = 1;
            }
        }

      if (!failed)
        report_success (results[i].h_crypt, &tests[i]);

      rv |= failed;
    }

  /* Scrupulously free all allocations so valgrind is happy.  */
  free (results);

  return rv;
}

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

/* The precalculated hashes in ka-table.inc, and some of the
   relationships among groups of test cases (see ka-table-gen.py)
   are invalidated if the execution character set is not ASCII.  */
static_assert(' ' == 0x20 && 'C' == 0x43 && '~' == 0x7E,
              "Execution character set does not appear to be ASCII");

/* This test verifies three things at once:
    - crypt, crypt_r, crypt_rn, and crypt_ra
      all produce the same outputs for the same inputs.
    - given hash <- crypt(phrase, setting),
       then hash == crypt(phrase, hash) also.
    - crypt(phrase, setting) == crypt'(phrase, setting)
      where crypt' is an independent implementation of the same
      hashing method.  (This is the "known answer" part of the test.)

   The independent implementations come from the Python 'passlib'
   library: <https://passlib.readthedocs.io/en/stable/>.
   See ka-table-gen.py for more detail.

   This file is compiled once for each hash, with macros defined that
   make ka-table.inc expose only the subset of the tests that are
   relevant to that hash.  This allows the test driver to run the
   known-answer tests for each enabled hash in parallel.  */

struct testcase
{
  const char *salt;
  const char *expected;
  const char *input;
};

static const struct testcase tests[] =
{
#include "ka-table.inc"

  /* Sentinel.  */
  { 0, 0, 0 },
};

/* Print out a string, using \xXX escapes for any characters that are
   not printable ASCII.  Backslash, single quote, and double quote are
   also escaped, by preceding them with another backslash.  If machine-
   parsing the output, note that we use the Python semantics of \x, not
   the C semantics: each \x consumes _exactly two_ subsequent hex digits.
   (For instance, \x123 means 0x12 0x33.)  */
static void
print_escaped (const char *s)
{
  const unsigned char *p = (const unsigned char *)s;
  for (; *p; p++)
    {
      unsigned char c = *p;
      if (c == '\\' || c == '\"' || c == '\'')
        {
          putchar ('\\');
          putchar (c);
        }
      else if (0x20 <= c && c <= 0x7E)
        putchar (c);
      else
        printf ("\\x%02x", (unsigned int)c);
    }
}

/* Subroutine of report_result.  */
static void
begin_error_report (const struct testcase *tc, const char *tag)
{
  printf ("FAIL: %s/", tc->salt);
  print_escaped (tc->input);
  printf (": %s ", tag);
}

/* Summarize the result of a single hashing operation.
   If everything is as expected, prints nothing and returns 0.
   Otherwise, prints a diagnostic message to stdout (not stderr!)
   and returns 1.  */
static int
report_result (const char *tag, const char *hash, int errnm,
               const struct testcase *tc, bool expect_failure_tokens)
{
  if (hash && hash[0] != '*')
    {
      /* We don't look at errno in this branch, because errno is
         allowed to be set by successful operations.  */
      if (!strcmp (hash, tc->expected))
        return 0;

      begin_error_report (tc, tag);
      printf ("mismatch: expected %s got %s\n", tc->expected, hash);
      return 1;
    }
  else
    {
      /* Ill-formed setting string arguments to 'crypt' are tested in a
         different program, so we never _expect_ a failure.  However, if
         we do get a failure, we want to log it in detail.  */
      begin_error_report (tc, tag);

      if (hash == 0)
        printf ("failure: got (null)");
      else
        printf ("failure: got %s", hash);

      /* errno should have been set.  */
      if (errnm)
        printf (", errno = %s", strerror (errnm));
      else
        printf (", errno not set");

      /* Should the API used have generated a NULL or a failure token?  */
      if (hash == 0 && expect_failure_tokens)
        printf (", failure token not generated");
      if (hash != 0 && !expect_failure_tokens)
        printf (", failure token wrongly generated");

      /* A failure token must never compare equal to the setting string
         that was used in the computation.  N.B. recrypt uses crypt_rn,
         which never produces failure tokens, so in this branch we can
         safely assume that the setting string used was tc->salt
         (if it generates one anyway that's an automatic failure).  */
      if (hash != 0 && !strcmp (tc->salt, hash))
        printf (", failure token == salt");

      putchar ('\n');
      return 1;
    }
}

static int
calc_hashes_crypt (void)
{
  char *hash;
  const struct testcase *t;
  int status = 0;

  for (t = tests; t->input != 0; t++)
    {
      errno = 0;
      hash = crypt (t->input, t->salt);
      status |= report_result ("crypt", hash, errno, t,
                               ENABLE_FAILURE_TOKENS);
    }

  return status;
}

static int
calc_hashes_crypt_r_rn (void)
{
  char *hash;
  union
  {
    char pass[CRYPT_MAX_PASSPHRASE_SIZE + 1];
    int aligned;
  } u;
  const struct testcase *t;
  struct crypt_data data;
  int status = 0;

  memset (&data, 0, sizeof data);
  memset (u.pass, 0, CRYPT_MAX_PASSPHRASE_SIZE + 1);
  for (t = tests; t->input != 0; t++)
    {
      strncpy(u.pass + 1, t->input, CRYPT_MAX_PASSPHRASE_SIZE);
      printf("[%zu]: %s %s\n", strlen(t->input),
             t->input, t->salt);
      errno = 0;
      hash = crypt_r (u.pass + 1, t->salt, &data);
      status |= report_result ("crypt_r", hash, errno, t,
                               ENABLE_FAILURE_TOKENS);

      errno = 0;
      hash = crypt_rn (u.pass + 1, t->salt, &data, (int)sizeof data);
      status |= report_result ("crypt_rn", hash, errno, t, false);
    }

  return status;
}

static int
calc_hashes_crypt_ra_recrypt (void)
{
  char *hash;
  const struct testcase *t;
  void *datap = 0;
  int datasz = 0;
  int status = 0;

  for (t = tests; t->input != 0; t++)
    {
      errno = 0;
      hash = crypt_ra (t->input, t->salt, &datap, &datasz);
      if (report_result ("crypt_ra", hash, errno, t, false))
        status = 1;
      else
        {
          /* if we get here, we know hash == t->expected */
          errno = 0;
          hash = crypt_ra (t->input, t->expected,
                           &datap, &datasz);
          status |= report_result ("recrypt", hash, errno, t, false);
        }
    }

  free (datap);
  return status;
}

int
main (void)
{
  int status = 0;

  /* Mark this test SKIPPED if the very first entry in the table is the
     sentinel; this happens only when the hash we would test is disabled.  */
  if (tests[0].input == 0)
    return 77;

  status |= calc_hashes_crypt ();
  status |= calc_hashes_crypt_r_rn ();
  status |= calc_hashes_crypt_ra_recrypt ();

  return status;
}

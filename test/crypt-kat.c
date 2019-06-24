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

#ifdef HAVE_PTHREAD
#include <pthread.h>
#else
#define flockfile(fp)   do { } while (0)
#define funlockfile(fp) do { } while (0)
#endif

#if ENABLE_OBSOLETE_API && !ENABLE_OBSOLETE_API_ENOSYS
symver_ref("fcrypt", fcrypt, SYMVER_FLOOR);
#endif

/* The precalculated hashes in test-crypt-kat.inc, and some of the
   relationships among groups of test cases (see test-crypt-kat-gen.py)
   are invalidated if the execution character set is not ASCII.  */
static_assert(' ' == 0x20 && 'C' == 0x43 && '~' == 0x7E,
              "Execution character set does not appear to be ASCII");

/* This test verifies three things at once:
    - crypt, crypt_r, crypt_rn, crypt_ra, and fcrypt (if enabled)
      all produce the same outputs for the same inputs.
    - given hash <- crypt(phrase, setting),
       then hash == crypt(phrase, hash) also.
    - crypt(phrase, setting) == crypt'(phrase, setting)
      where crypt' is an independent implementation of the same
      hashing method.  (This is the "known answer" part of the test.)

   The independent implementations come from the Python 'passlib'
   library: <https://passlib.readthedocs.io/en/stable/>.
   See test-crypt-kat-gen.py for more detail.

   The test program has been structured to make the most expensive
   part (computing a whole bunch of hashes) somewhat parallelizable.
   crypt and fcrypt have to be called serially for all inputs; we do
   this on the main thread.  When pthreads are available, a second
   thread calls crypt_r and crypt_rn for all inputs, and a third
   thread calls crypt_ra for each input and then repeats that call
   with the hash output by the first call as the setting string.  Each
   thread compares its own two results to the expected hash.  If there
   are any errors, it reports them to stdout.  Each thread returns a
   boolean failure flag (cast to void*, because pthreads) and main
   will exit unsuccessfully if any flag is set.

   More threads would not reduce the overall time required for the
   test, because of crypt and fcrypt having to be called serially
   for each hash.  We can't reduce the runtime of the parallel
   section below the time that takes; the above division of labor
   gives the second and third threads the same amount of work to
   do as the main thread.  In principle we could split things up
   more finely when fcrypt is configured out, but it isn't worth
   the additional ifdeffage.  */

struct testcase
{
  const char *salt;
  const char *expected;
  const char *input;
};

static const struct testcase tests[] =
{
#include "crypt-kat.inc"
};
#define ntests ARRAY_SIZE (tests)

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

      flockfile (stdout);
      begin_error_report (tc, tag);
      printf ("mismatch: expected %s got %s\n", tc->expected, hash);
      funlockfile (stdout);
      return 1;
    }
  else
    {
      /* Ill-formed setting string arguments to 'crypt' are tested in a
         different program, so we never _expect_ a failure.  However, if
         we do get a failure, we want to log it in detail.  */
      flockfile (stdout);
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
      funlockfile (stdout);
      return 1;
    }
}

static void *
calc_hashes_crypt_fcrypt (ARG_UNUSED (void *unused))
{
  char *hash;
  size_t i;
  int status = 0;

  for (i = 0; i < ntests; i++)
    {
      errno = 0;
      hash = crypt (tests[i].input, tests[i].salt);
      status |= report_result ("crypt", hash, errno, &tests[i],
                               ENABLE_FAILURE_TOKENS);

#if ENABLE_OBSOLETE_API && !ENABLE_OBSOLETE_API_ENOSYS
      errno = 0;
      hash = fcrypt (tests[i].input, tests[i].salt);
      status |= report_result ("fcrypt", hash, errno, &tests[i],
                               ENABLE_FAILURE_TOKENS);
#endif
    }

  return (void *)(uintptr_t)status;
}

static void *
calc_hashes_crypt_r_rn (ARG_UNUSED (void *unused))
{
  char *hash;
  union
  {
    char pass[CRYPT_MAX_PASSPHRASE_SIZE + 1];
    int aligned;
  } u;
  size_t i;
  struct crypt_data data;
  int status = 0;

  memset (&data, 0, sizeof data);
  memset (u.pass, 0, CRYPT_MAX_PASSPHRASE_SIZE + 1);
  for (i = 0; i < ntests; i++)
    {
      strncpy(u.pass + 1, tests[i].input, CRYPT_MAX_PASSPHRASE_SIZE);
      printf("[%zu]: %s %s\n", strlen(tests[i].input), tests[i].input, tests[i].salt);
      errno = 0;
      hash = crypt_r (u.pass + 1, tests[i].salt, &data);
      status |= report_result ("crypt_r", hash, errno, &tests[i],
                               ENABLE_FAILURE_TOKENS);

      errno = 0;
      hash = crypt_rn (u.pass + 1, tests[i].salt, &data, (int)sizeof data);
      status |= report_result ("crypt_rn", hash, errno, &tests[i], false);
    }

  return (void *)(uintptr_t)status;
}

static void *
calc_hashes_crypt_ra_recrypt (ARG_UNUSED (void *unused))
{
  char *hash;
  size_t i;
  void *datap = 0;
  int datasz = 0;
  int status = 0;

  for (i = 0; i < ntests; i++)
    {
      errno = 0;
      hash = crypt_ra (tests[i].input, tests[i].salt, &datap, &datasz);
      if (report_result ("crypt_ra", hash, errno, &tests[i], false))
        status = 1;
      else
        {
          /* if we get here, we know hash == tests[i].expected */
          errno = 0;
          hash = crypt_ra (tests[i].input, tests[i].expected,
                           &datap, &datasz);
          status |= report_result ("recrypt", hash, errno, &tests[i], false);
        }
    }

  free (datap);
  return (void *)(uintptr_t)status;
}

int
main (void)
{
  int status = 0;

  if (ntests == 0)
    return 77; /* UNSUPPORTED if there are no tests to run */

#ifdef HAVE_PTHREAD
  {
    pthread_t t1, t2;
    int err;
    void *xstatus;
    err = pthread_create (&t1, 0, calc_hashes_crypt_r_rn, 0);
    if (err)
      {
        fprintf (stderr, "pthread_create (crypt_r): %s\n", strerror (err));
        return 1;
      }
    err = pthread_create (&t2, 0, calc_hashes_crypt_ra_recrypt, 0);
    if (err)
      {
        fprintf (stderr, "pthread_create (crypt_ra): %s\n", strerror (err));
        return 1;
      }

    status |= !!calc_hashes_crypt_fcrypt (0);

    err = pthread_join (t1, &xstatus);
    if (err)
      {
        fprintf (stderr, "pthread_join (crypt_r): %s\n", strerror (err));
        status = 1;
      }
    else
      {
        status |= !!xstatus;
      }
    err = pthread_join (t2, &xstatus);
    if (err)
      {
        fprintf (stderr, "pthread_join (crypt_rn): %s\n", strerror (err));
        status = 1;
      }
    else
      {
        status |= !!xstatus;
      }
  }
#else
  status |= !!calc_hashes_crypt_fcrypt (results);
  status |= !!calc_hashes_crypt_r_rn (results);
  status |= !!calc_hashes_crypt_ra_recrypt (results);
#endif

  return status;
}

/* Test crypt() API with "known answer" hashes.

   Written by Zack Weinberg <zackw at panix.com> in 2019.
   To the extent possible under law, Zack Weinberg has waived all
   copyright and related or neighboring rights to this work.

   See https://creativecommons.org/publicdomain/zero/1.0/ for further
   details.  */

#include "crypt-port.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

/* The precalculated hashes in test-crypt-kat.inc, and some of the
   relationships among groups of test cases (see test-crypt-kat-gen.py)
   are invalidated if the execution character set is not ASCII.  */
static_assert(' ' == 0x20 && 'C' == 0x43 && '~' == 0x7E,
              "Execution character set does not appear to be ASCII");

/* This test verifies four things at once:
    - crypt, crypt_r, crypt_rn, and crypt_ra all produce the
      same outputs for the same inputs.
    - given hash <- crypt(phrase, setting),
       then hash == crypt(phrase, hash) also.
    - crypt(phrase, setting) == crypt'(phrase, setting)
      where crypt' is an independent implementation of the same
      hashing method.  (This is the "known answer" part of the test.)
    - Except for certain known cases, whenever p1 != p2,
      crypt(p1, s) != crypt(p2, s).

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

/* The test logic is structured the way it is in order to make the most
   expensive part (computing a whole bunch of hashes) parallelizable.  */

struct testresult
{
  const struct testcase *tc;
  char *h_crypt;
  char *h_crypt_r;
  char *h_crypt_rn;
  char *h_crypt_ra;
  char *h_recrypt;
};

/* Summarize the result of a single hashing operation in a format that
   will be easy for main to process.  Specifically: if the output is
   as expected, the string written to 'dest' will be the hash string.
   If the output is _not_ as expected, the string written to 'dest'
   will contain at least one '!', and will record enough information
   to diagnose the failure.  main will report a test failure for any
   string containing an '!', and will also report a failure if any of
   the fields of a 'struct testresult' is not the same as the others.  */

#ifndef HAVE_VASPRINTF
#define INITIAL_LEN 128
static int
vasprintf (char **strp, const char *fmt, va_list ap)
{
  va_list aq;
  va_copy (aq, ap);

  char *buf = malloc (INITIAL_LEN);
  if (!buf) return -1;
  int len = snprintf (buf, INITIAL_LEN, fmt, aq);
  va_end (aq);

  buf = realloc (buf, len + 1);
  if (!buf) return -1;
  if (len >= INITIAL_LEN)
    /* There wasn't enough space initially; now there is.  */
    if (len != snprintf (buf, len + 1, fmt, ap))
      abort ();

  *strp = buf;
  return len;
}
#endif

static char *
xasprintf (const char *fmt, ...)
{
  char *rv;
  va_list ap;
  va_start (ap, fmt);
  if (vasprintf (&rv, fmt, ap) < 0)
    {
      perror ("asprintf");
      exit (1);
    }
  va_end (ap);
  return rv;
}

static void
record_result (char **dest, const char *hash, int errnm,
               const struct testcase *tcase,
               bool expect_failure_tokens)
{
  if (hash && hash[0] != '*')
    {
      if (!strcmp (hash, tcase->expected))
        *dest = xasprintf ("%s", hash);
      else
        *dest = xasprintf ("!not as expected: %s !=\t %s",
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

      *dest = xasprintf ("!got %s: %s%s%s",
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
      results[i].tc = &tests[i];
      errno = 0;
      hash = crypt (tests[i].input, tests[i].salt);
      record_result (&results[i].h_crypt, hash, errno, &tests[i],
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
      record_result (&results[i].h_crypt_r, hash, errno, &tests[i],
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
      record_result (&results[i].h_crypt_rn, hash, errno, &tests[i], false);

      if (results[i].h_crypt_rn[0] != '!')
        {
          errno = 0;
          hash = crypt_rn (tests[i].input, results[i].h_crypt_rn, &data,
                           (int)sizeof data);
          record_result (&results[i].h_recrypt, hash, errno, &tests[i], false);
        }
      else
        results[i].h_recrypt = "!skipped";
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
      record_result (&results[i].h_crypt_ra, hash, errno, &tests[i], false);
    }

  free (datap);
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
report_ka_error (const char *badhash, const struct testcase *tc,
              const char *mismatched, const char *tag)
{
  printf ("FAIL: %s/", tc->salt);
  print_escaped (tc->input);
  printf (": crypt%s: got %s", tag, badhash);
  if (mismatched)
    printf (" (mismatch: %s)", mismatched);
  putchar ('\n');
}

static int
do_ka_tests (struct testresult *results)
{
#ifdef HAVE_PTHREAD
  {
    pthread_t t_r, t_rn, t_ra;
    int err;
    err = pthread_create (&t_r, 0, calc_hashes_crypt_r, results);
    if (err) {
      fprintf (stderr, "pthread_create (crypt_r): %s\n", strerror (err));
      return 1;
    }
    err = pthread_create (&t_rn, 0, calc_hashes_crypt_rn, results);
    if (err) {
      fprintf (stderr, "pthread_create (crypt_rn): %s\n", strerror (err));
      return 1;
    }
    err = pthread_create (&t_ra, 0, calc_hashes_crypt_ra, results);
    if (err) {
      fprintf (stderr, "pthread_create (crypt_ra): %s\n", strerror (err));
      return 1;
    }

    calc_hashes_crypt (results);

    err = pthread_join (t_r, 0);
    if (err) {
      fprintf (stderr, "pthread_join (crypt_r): %s\n", strerror (err));
      return 1;
    }
    err = pthread_join (t_rn, 0);
    if (err) {
      fprintf (stderr, "pthread_join (crypt_rn): %s\n", strerror (err));
      return 1;
    }
    err = pthread_join (t_ra, 0);
    if (err) {
      fprintf (stderr, "pthread_join (crypt_ra): %s\n", strerror (err));
      return 1;
    }
  }
#else
  calc_hashes_crypt (results);
  calc_hashes_crypt_r (results);
  calc_hashes_crypt_rn (results);
  calc_hashes_crypt_ra (results);
#endif

  int rv = 0;
  for (size_t i = 0; i < ntests; i++)
    {
      int failed = 0;
      if (strchr (results[i].h_crypt, '!'))
        {
          report_ka_error (results[i].h_crypt, &tests[i], 0, "");
          failed = 1;
        }
      if (strchr (results[i].h_crypt_r, '!'))
        {
          report_ka_error (results[i].h_crypt_r, &tests[i], 0, "_r");
          failed = 1;
        }
      if (strchr (results[i].h_crypt_rn, '!'))
        {
          report_ka_error (results[i].h_crypt_rn, &tests[i], 0, "_rn");
          failed = 1;
        }
      if (strchr (results[i].h_crypt_ra, '!'))
        {
          report_ka_error (results[i].h_crypt_ra, &tests[i], 0, "_ra");
          failed = 1;
        }
      if (strchr (results[i].h_recrypt, '!'))
        {
          report_ka_error (results[i].h_recrypt, &tests[i], 0, "_rn (recrypt)");
          failed = 1;
        }

      if (!failed)
        {
          if (strcmp (results[i].h_crypt_r, results[i].h_crypt))
            {
              report_ka_error (results[i].h_crypt_r, &tests[i],
                               results[i].h_crypt, "_r");
              failed = 1;
            }
          if (strcmp (results[i].h_crypt_rn, results[i].h_crypt))
            {
              report_ka_error (results[i].h_crypt_rn, &tests[i],
                               results[i].h_crypt, "_rn");
              failed = 1;
            }
          if (strcmp (results[i].h_crypt_ra, results[i].h_crypt))
            {
              report_ka_error (results[i].h_crypt_ra, &tests[i],
                               results[i].h_crypt, "_ra");
              failed = 1;
            }
          if (strcmp (results[i].h_recrypt, results[i].h_crypt))
            {
              report_ka_error (results[i].h_recrypt, &tests[i],
                               results[i].h_crypt, "_rn (recrypt)");
              failed = 1;
            }

          /* Tell the collision tests to skip this one if it's inconsistent.  */
          if (failed)
            results[i].h_crypt[0] = '!';
        }

      rv |= failed;
    }

  return rv;
}

/* Collision test */

#if INCLUDE_descrypt || INCLUDE_bsdicrypt || INCLUDE_bigcrypt
static bool
strneq_7bit (const char *p1, const char *p2, size_t limit)
{
  for (size_t i = 0; i < limit; i++)
    {
      if ((p1[i] & 0x7F) != (p2[i] & 0x7F))
        return true;
      if (p1[i] == '\0')
        break;
    }
  return false;
}
#endif

#if INCLUDE_bcrypt_x
/* Must match the definition of BF_key in crypt-bcrypt.c.  */
typedef uint32_t BF_key[18];


/* The bug in bcrypt mode "x" (preserved from the original
   implementation of bcrypt) is, at its root, that the code below
   sign- rather than zero-extends *p before or-ing it into 'tmp'.
   When *p has its 8th bit set, it is therefore or-ed in as
   0xFF_FF_FF_xx rather than 0x00_00_00_xx, and clobbers the other
   three bytes in 'tmp'.  Depending on its position within the input,
   this can erase up to three other characters of the passphrase.
   The exact set of strings involved in any one group of collisions is
   difficult to describe in words and may depend on the endianness of
   the CPU.  The test cases in this file have only been verified on
   a little-endian CPU.  */
static void
buggy_expand_BF_key (BF_key *expanded, const char *phrase)
{
  const char *p = phrase;
  for (int i = 0; i < (int)ARRAY_SIZE (*expanded); i++)
    {
      uint32_t tmp = 0;
      int32_t stmp;
      for (int j = 0; j < 4; j++)
        {
          tmp <<= 8;
          stmp = (int32_t) (signed char)*p;
          tmp |= (uint32_t) stmp;
          if (!*p)
            p = phrase;
          else
            p++;
        }
      (*expanded)[i] = tmp;
    }
}

static bool
sign_extension_collision_p (const char *p1, const char *p2)
{
  BF_key expanded_1, expanded_2;
  buggy_expand_BF_key (&expanded_1, p1);
  buggy_expand_BF_key (&expanded_2, p2);
  return !memcmp (expanded_1, expanded_2, sizeof (BF_key));
}
#endif

#if INCLUDE_sunmd5
static bool
equivalent_sunmd5_settings_p (const char *s1, const char *s2)
{
  if (strncmp (s1, "$md5", 4))
    return false;
  if (strncmp (s2, "$md5", 4))
    return false;

  size_t l1 = strlen (s1);
  size_t l2 = strlen (s2);
  size_t ll;
  const char *sl, *sh;
  if (l1 < l2)
    {
      ll = l1;
      sl = s1;
      sh = s2;
    }
  else
    {
      ll = l2;
      sl = s2;
      sh = s1;
    }
  if (strncmp (sl, sh, ll))
    return false;
  /* The two cases where sunmd5 settings are equivalent:
     $md5...$ and $md5...$$
     $md5...  and $md5...$x
   */
  if (sl[ll-1] == '$')
    {
      if (sh[ll] != '$' || sh[ll+1] != '\0')
        return false;
    }
  else
    {
      if (sh[ll] != '$' || sh[ll+1] != 'x' || sh[ll+2] != '\0')
        return false;
    }

  return true;
}
#endif

static bool
collision_expected (const struct testresult *a, const struct testresult *b)
{
  const char *p1 = a->tc->input;
  const char *p2 = b->tc->input;
  const char *s1 = a->tc->salt;
  const char *s2 = b->tc->salt;

  /* Under no circumstances should two hashes with different settings
     collide, except... */
  if (strcmp (s1, s2))
    {
#if INCLUDE_bigcrypt && INCLUDE_descrypt
      /* a DES hash can collide with a bigcrypt hash when the phrase
         input to bigcrypt was fewer than 8 characters long;  */
      if (s1[0] != '$' && s1[0] != '_' &&
          s2[0] != '$' && s2[0] != '_' &&
          s1[0] == s2[0] && s1[1] == s2[1] &&
          ((s1[2] != '\0' && s2[2] == '\0' && strlen (p1) <= 8) ||
           (s1[2] == '\0' && s2[2] != '\0' && strlen (p2) <= 8)))
            return !strneq_7bit (p1, p2, 8);
#endif

#if INCLUDE_nt
      /* all settings for NTHASH are equivalent;  */
      if (!strncmp (s1, "$3$", 3) && !strncmp(s2, "$3$", 3))
        return !strncmp (p1, p2, 128);
#endif

#if INCLUDE_sunmd5
      /* $md5... and $md5...$x are equivalent.  */
      if (equivalent_sunmd5_settings_p (s1, s2))
        return !strcmp (p1, p2);
#endif

      return false;
    }

#if INCLUDE_bcrypt || INCLUDE_bcrypt_a || INCLUDE_bcrypt_x || INCLUDE_bcrypt_y
  if (!strncmp (s1, "$2", 2)) /* bcrypt */
    {
      /* bcrypt truncates passphrases to 72 characters.  */
      if (!strncmp (p1, p2, 72))
        return true;

#if INCLUDE_bcrypt_x
      if (!strncmp (s1, "$2x", 3) /* bcrypt with preserved bug */
          && sign_extension_collision_p (p1, p2))
        return true;
#endif

      return false;
    }
#endif

#if INCLUDE_descrypt
  if (s1[0] != '$' && s1[0] != '_' && s1[2] == '\0')
    /* descrypt truncates passphrases to 8 characters and strips the
       8th bit.  */
    return !strneq_7bit (p1, p2, 8);
#endif

#if INCLUDE_bigcrypt
  if (s1[0] != '$' && s1[0] != '_' && s1[2] != '\0')
    /* bigcrypt truncates passphrases to 128 characters and strips the
       8th bit.  */
    return !strneq_7bit (p1, p2, 128);
#endif

#if INCLUDE_bsdicrypt
  if (s1[0] == '_')
    /* bsdicrypt does not truncate the passphrase, but it does still
       strip the 8th bit.  */
    return !strneq_7bit (p1, p2, (size_t)-1);
#endif

#if INCLUDE_nt
  if (!strcmp (s1, "$3$"))
    /* nthash truncates the passphrase to 128 characters */
    return !strncmp (p1, p2, 128);
#endif

  return false;
}

static void
report_collision (const struct testresult *a, const struct testresult *b)
{
  fputs ("FAIL: collision:\n  A:    '", stdout);
  print_escaped (a->tc->input);
  fputs ("' with '", stdout);
  print_escaped (a->tc->salt);
  fputs ("'\n  B:    '", stdout);
  print_escaped (b->tc->input);
  fputs ("' with '", stdout);
  print_escaped (b->tc->salt);
  fputs ("'\n  H:    '", stdout);
  print_escaped (a->h_crypt);
  fputs ("'\n", stdout);
}

static void
report_no_collision (const struct testresult *a, const struct testresult *b)
{
  fputs ("FAIL: no collision:\n  A:    '", stdout);
  print_escaped (a->tc->input);
  fputs ("' with '", stdout);
  print_escaped (a->tc->salt);
  fputs ("'\n  B:    '", stdout);
  print_escaped (b->tc->input);
  fputs ("' with '", stdout);
  print_escaped (b->tc->salt);
  fputs ("'\n AH:    '", stdout);
  print_escaped (a->h_crypt);
  fputs ("'\n BH:    '", stdout);
  print_escaped (b->h_crypt);
  fputs ("'\n", stdout);
}

static int
cmp_testresult_by_hash (const void *ax, const void *bx)
{
  const struct testresult *a = ax;
  const struct testresult *b = bx;
  return strcmp (a->h_crypt, b->h_crypt);
}

static int
do_collision_tests (struct testresult *results)
{
  qsort (results, ntests, sizeof (struct testresult), cmp_testresult_by_hash);

  /* Sorting the test result records by hash means that if there are
     any collisions, the records involved will be adjacent.  */
  int rv = 0;
  for (size_t i = 1; i < ntests; i++)
    {
      const struct testresult *a = &results[i-1];
      const struct testresult *b = &results[i];
      if (a->h_crypt[0] == '!' || b->h_crypt[0] == '!')
        continue;

      bool collision = !strcmp (a->h_crypt, b->h_crypt);
      bool x_collision = collision_expected (a, b);

      if (collision && !x_collision)
        {
          rv = 1;
          report_collision (a, b);
        }
      else if (!collision && x_collision)
        {
          rv = 1;
          report_no_collision (a, b);
        }
    }
  return rv;
}

int
main (void)
{
  if (ntests == 0)
    return 77; /* UNSUPPORTED if there are no tests to run */

  struct testresult *results = calloc (ntests, sizeof (struct testresult));
  if (!results)
    {
      fprintf (stderr, "failed to allocate %zu bytes: %s\n",
               ntests * sizeof (struct testresult), strerror (errno));
      return 1;
    }

  int rv = 0;
  rv |= do_ka_tests (results);
  rv |= do_collision_tests (results);

  /* Scrupulously free all allocations so valgrind is happy.  */
  for (size_t i = 0; i < ntests; i++)
    {
      free (results[i].h_crypt);
      free (results[i].h_crypt_r);
      free (results[i].h_crypt_rn);
      free (results[i].h_crypt_ra);
      free (results[i].h_recrypt);
    }
  free (results);

  return rv;
}

/* Test passing invalid arguments to crypt*().

   Written by Zack Weinberg <zackw at panix.com> in 2018.
   To the extent possible under law, Zack Weinberg has waived all
   copyright and related or neighboring rights to this work.

   See https://creativecommons.org/publicdomain/zero/1.0/ for further
   details.  */

#include "crypt-port.h"

#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>

/* The behavior tested below should be consistent for all hashing
   methods.  */
static const char *settings[] =
{
#if INCLUDE_descrypt || INCLUDE_bigcrypt
  "Mp",
#endif
#if INCLUDE_bsdicrypt
  "_J9..MJHn",
#endif
#if INCLUDE_md5crypt
  "$1$MJHnaAke",
#endif
#if INCLUDE_nt
  "$3$",
#endif
#if INCLUDE_sunmd5
  /* exercise all paths of the bug-compatibility logic */
  "$md5,rounds=55349$BPm.fm03$",
  "$md5,rounds=55349$BPm.fm03$x",
  "$md5,rounds=55349$BPm.fm03$$",
  "$md5,rounds=55349$BPm.fm03$$x",
  "$md5$BPm.fm03$",
  "$md5$BPm.fm03$x",
  "$md5$BPm.fm03$$",
  "$md5$BPm.fm03$$x",
#endif
#if INCLUDE_sm3crypt
  "$sm3$MJHnaAkegEVYHsFK",
  "$sm3$rounds=10191$MJHnaAkegEVYHsFK",
#endif
#if INCLUDE_sha1crypt
  "$sha1$248488$ggu.H673kaZ5$",
#endif
#if INCLUDE_sha256crypt
  "$5$MJHnaAkegEVYHsFK",
  "$5$rounds=10191$MJHnaAkegEVYHsFK",
#endif
#if INCLUDE_sha512crypt
  "$6$MJHnaAkegEVYHsFK",
  "$6$rounds=10191$MJHnaAkegEVYHsFK",
#endif
#if INCLUDE_bcrypt_a
  "$2a$05$UBVLHeMpJ/QQCv3XqJx8zO",
#endif
#if INCLUDE_bcrypt
  "$2b$05$UBVLHeMpJ/QQCv3XqJx8zO",
#endif
#if INCLUDE_bcrypt_x
  "$2x$05$UBVLHeMpJ/QQCv3XqJx8zO",
#endif
#if INCLUDE_bcrypt_y
  "$2y$05$UBVLHeMpJ/QQCv3XqJx8zO",
#endif
#if INCLUDE_yescrypt
  "$y$j9T$MJHnaAkegEVYHsFKkmfzJ1",
#endif
#if INCLUDE_scrypt
  "$7$CU..../....MJHnaAkegEVYHsFKkmfzJ1",
#endif
#if INCLUDE_gost_yescrypt
  "$gy$j9T$MJHnaAkegEVYHsFKkmfzJ1",
#endif
};

/* In some of the tests below, a segmentation fault is the expected result.  */
static sigjmp_buf env;
static void
segv_handler (int sig)
{
  siglongjmp (env, sig);
}

static bool error_occurred;

#ifndef XCRYPT_USE_ASAN /* see comments in do_tests */
static void
expect_no_fault (const char *tag,
                 const char *phrase, const char *setting, const char *expect,
                 void (*testfn) (const char *, const char *,
                                 const char *, const char *))
{
  int rv = sigsetjmp (env, 1);
  if (!rv)
    testfn (tag, phrase, setting, expect);
  else
    {
      printf ("FAIL: %s: Unexpected %s\n", tag, strsignal (rv));
      error_occurred = 1;
    }
}
#endif

static void
expect_a_fault (const char *tag,
                const char *phrase, const char *setting, const char *expect,
                void (*testfn) (const char *, const char *,
                                const char *, const char *))
{
  int rv = sigsetjmp (env, 1);
  if (!rv)
    {
      testfn (tag, phrase, setting, expect);
      printf ("ERROR: %s: No signal occurred\n", tag);
      error_occurred = true;
    }
}

static void
check (const char *tag, const char *expect, const char *got)
{
  int err = errno;
  if ((got == 0 && expect != 0)
      || (got != 0 && expect == 0)
      || (got != 0 && expect != 0 && strcmp(got, expect) != 0))
    {
      printf ("FAIL: %s: exp '%s' got '%s'\n",
              tag, expect ? expect : "(nil)",
              got ? got : "(nil)");
      error_occurred = true;
    }
  if ((expect == 0 || expect[0] == '*') && err != EINVAL)
    {
      printf ("FAIL: %s: exp '%s' got '%s'\n",
              tag, strerror (EINVAL), strerror (err));
      error_occurred = true;
    }
}

static void
test_crypt (const char *tag,
            const char *phrase, const char *setting, const char *expect)
{
  char *got = crypt (phrase, setting);
  check (tag, expect, got);
}

static void
test_crypt_r (const char *tag,
              const char *phrase, const char *setting, const char *expect)
{
  struct crypt_data data;
  memset (&data, 0, sizeof data);
  char *got = crypt_r (phrase, setting, &data);
  check (tag, expect, got);
}

static void
test_crypt_rn (const char *tag,
               const char *phrase, const char *setting, const char *expect)
{
  struct crypt_data data;
  memset (&data, 0, sizeof data);

  char *got = crypt_rn (phrase, setting, &data, (int) sizeof data);
  check (tag, expect, got);
}

static void
test_crypt_ra (const char *tag,
               const char *phrase, const char *setting, const char *expect)
{
  /* cheat - crypt_ra doesn't actually care whether its scratch area
     is on the heap as long as it's big enough */
  struct crypt_data data;
  memset (&data, 0, sizeof data);
  void *datap = &data;
  int datas = (int) sizeof data;

  char *got = crypt_ra (phrase, setting, &datap, &datas);
  check (tag, expect, got);
}

#if ENABLE_FAILURE_TOKENS
# define FT0 "*0"
# define FT1 "*1"
#else
# define FT0 0
# define FT1 0
#endif

/* PAGE should point to PAGESIZE bytes of read-write memory followed
   by another PAGESIZE bytes of inaccessible memory.  */

static void
do_tests(char *page, size_t pagesize)
{
  static const char phrase[] =
    "the ritual question of how much is two plus two";

  /* This copy operation intentionally omits the NUL; 'p1' points to a
     sequence of nonzero bytes followed immediately by inaccessible
     memory.  */
  memcpy (page + pagesize - (sizeof phrase - 1), phrase, sizeof phrase - 1);
  const char *p1 = page + pagesize - (sizeof phrase - 1);
  const char *p2 = page + pagesize;
  size_t i;

  /* Our crypt*() functions return NULL / a failure token, with errno set
     to EINVAL, when either the setting or the phrase argument is NULL.
     ASan's interceptors for crypt*() instead crash the program when either
     argument is NULL -- this is arguably a better choice, but for
     compatibility's sake we can't change what our functions do.  There is
     no way to disable interception of specific functions as far as I can
     tell.  Therefore, these tests are skipped when compiled with ASan.  */
#ifndef XCRYPT_USE_ASAN
  /* When SETTING is null, it shouldn't matter what PHRASE is.  */
  expect_no_fault ("0.0.crypt",    0,  0, FT0, test_crypt);
  expect_no_fault ("0.0.crypt_r",  0,  0, FT0, test_crypt_r);
  expect_no_fault ("0.0.crypt_rn", 0,  0, 0,    test_crypt_rn);
  expect_no_fault ("0.0.crypt_ra", 0,  0, 0,    test_crypt_ra);

  expect_no_fault ("''.0.crypt",    "", 0, FT0, test_crypt);
  expect_no_fault ("''.0.crypt_r",  "", 0, FT0, test_crypt_r);
  expect_no_fault ("''.0.crypt_rn", "", 0, 0,    test_crypt_rn);
  expect_no_fault ("''.0.crypt_ra", "", 0, 0,    test_crypt_ra);

  expect_no_fault ("ph.0.crypt",    phrase, 0, FT0, test_crypt);
  expect_no_fault ("ph.0.crypt_r",  phrase, 0, FT0, test_crypt_r);
  expect_no_fault ("ph.0.crypt_rn", phrase, 0, 0,    test_crypt_rn);
  expect_no_fault ("ph.0.crypt_ra", phrase, 0, 0,    test_crypt_ra);

  expect_no_fault ("p1.0.crypt",    p1, 0, FT0, test_crypt);
  expect_no_fault ("p1.0.crypt_r",  p1, 0, FT0, test_crypt_r);
  expect_no_fault ("p1.0.crypt_rn", p1, 0, 0,    test_crypt_rn);
  expect_no_fault ("p1.0.crypt_ra", p1, 0, 0,    test_crypt_ra);

  expect_no_fault ("p2.0.crypt",    p2, 0, FT0, test_crypt);
  expect_no_fault ("p2.0.crypt_r",  p2, 0, FT0, test_crypt_r);
  expect_no_fault ("p2.0.crypt_rn", p2, 0, 0,    test_crypt_rn);
  expect_no_fault ("p2.0.crypt_ra", p2, 0, 0,    test_crypt_ra);

  /* Conversely, when PHRASE is null,
     it shouldn't matter what SETTING is...  */
  expect_no_fault ("0.''.crypt",    0, "", FT0,  test_crypt);
  expect_no_fault ("0.''.crypt_r",  0, "", FT0,  test_crypt_r);
  expect_no_fault ("0.''.crypt_rn", 0, "", 0,    test_crypt_rn);
  expect_no_fault ("0.''.crypt_ra", 0, "", 0,    test_crypt_ra);

  expect_no_fault ("0.'*'.crypt",    0, "*", FT0,  test_crypt);
  expect_no_fault ("0.'*'.crypt_r",  0, "*", FT0,  test_crypt_r);
  expect_no_fault ("0.'*'.crypt_rn", 0, "*", 0,    test_crypt_rn);
  expect_no_fault ("0.'*'.crypt_ra", 0, "*", 0,    test_crypt_ra);

  expect_no_fault ("0.'*0'.crypt",    0, "*0", FT1,  test_crypt);
  expect_no_fault ("0.'*0'.crypt_r",  0, "*0", FT1,  test_crypt_r);
  expect_no_fault ("0.'*0'.crypt_rn", 0, "*0", 0,    test_crypt_rn);
  expect_no_fault ("0.'*0'.crypt_ra", 0, "*0", 0,    test_crypt_ra);

  expect_no_fault ("0.'*1'.crypt",    0, "*1", FT0,  test_crypt);
  expect_no_fault ("0.'*1'.crypt_r",  0, "*1", FT0,  test_crypt_r);
  expect_no_fault ("0.'*1'.crypt_rn", 0, "*1", 0,    test_crypt_rn);
  expect_no_fault ("0.'*1'.crypt_ra", 0, "*1", 0,    test_crypt_ra);

  expect_no_fault ("0.p1.crypt",    0, p1, FT0,  test_crypt);
  expect_no_fault ("0.p1.crypt_r",  0, p1, FT0,  test_crypt_r);
  expect_no_fault ("0.p1.crypt_rn", 0, p1, 0,    test_crypt_rn);
  expect_no_fault ("0.p1.crypt_ra", 0, p1, 0,    test_crypt_ra);

  /* ... except for the case where SETTING is nonnull but there are
     fewer than 2 readable characters at SETTING, in which case we'll
     crash before we get to the null check in do_crypt.  This is a
     bug, but it's impractical to fix without breaking the property
     that 'crypt' _never_ creates a failure token that is equal to the
     setting string, which is more important than this corner case.  */
  expect_a_fault ("0.p2.crypt",    0, p2, FT0,  test_crypt);
  expect_a_fault ("0.p2.crypt_r",  0, p2, FT0,  test_crypt_r);
  expect_a_fault ("0.p2.crypt_rn", 0, p2, 0,    test_crypt_rn);
  expect_a_fault ("0.p2.crypt_ra", 0, p2, 0,    test_crypt_ra);
#endif /* no ASan */

  /* When SETTING is valid, passing an invalid string as PHRASE should
     crash reliably.  */
  for (i = 0; i < ARRAY_SIZE (settings); i++)
    {
      snprintf (page, pagesize, "p1.'%s'.crypt", settings[i]);
      expect_a_fault (page, p1, settings[i], FT0,  test_crypt);

      snprintf (page, pagesize, "p1.'%s'.crypt_r", settings[i]);
      expect_a_fault (page, p1, settings[i], FT0,  test_crypt_r);

      snprintf (page, pagesize, "p1.'%s'.crypt_rn", settings[i]);
      expect_a_fault (page, p1, settings[i], 0,    test_crypt_rn);

      snprintf (page, pagesize, "p1.'%s'.crypt_ra", settings[i]);
      expect_a_fault (page, p1, settings[i], 0,    test_crypt_ra);

      snprintf (page, pagesize, "p2.'%s'.crypt", settings[i]);
      expect_a_fault (page, p2, settings[i], FT0,  test_crypt);

      snprintf (page, pagesize, "p2.'%s'.crypt_r", settings[i]);
      expect_a_fault (page, p2, settings[i], FT0,  test_crypt_r);

      snprintf (page, pagesize, "p2.'%s'.crypt_rn", settings[i]);
      expect_a_fault (page, p2, settings[i], 0,    test_crypt_rn);

      snprintf (page, pagesize, "p2.'%s'.crypt_ra", settings[i]);
      expect_a_fault (page, p2, settings[i], 0,    test_crypt_ra);
    }

  /* Conversely, when PHRASE is valid, passing an invalid string as SETTING
     should crash reliably.  */
  expect_a_fault ("ph.p2.crypt",    phrase, p2, FT0,  test_crypt);
  expect_a_fault ("ph.p2.crypt_r",  phrase, p2, FT0,  test_crypt_r);
  expect_a_fault ("ph.p2.crypt_rn", phrase, p2, 0,    test_crypt_rn);
  expect_a_fault ("ph.p2.crypt_ra", phrase, p2, 0,    test_crypt_ra);

  for (i = 0; i < ARRAY_SIZE (settings); i++)
    {
      p1 = memcpy (page + pagesize - strlen (settings[i]),
                   settings[i], strlen (settings[i]));

      snprintf (page, pagesize, "ph.'%s'.crypt", settings[i]);
      expect_a_fault (page, phrase, p1, FT0, test_crypt);

      snprintf (page, pagesize, "ph.'%s'.crypt_r", settings[i]);
      expect_a_fault (page, phrase, p1, FT0, test_crypt_r);

      snprintf (page, pagesize, "ph.'%s'.crypt_rn", settings[i]);
      expect_a_fault (page, phrase, p1, 0,    test_crypt_rn);

      snprintf (page, pagesize, "ph.'%s'.crypt_ra", settings[i]);
      expect_a_fault (page, phrase, p1, 0,    test_crypt_ra);
    }
}

int
main (void)
{
  /* Set up a two-page region whose first page is read-write and
     whose second page is inaccessible.  */
  long pagesize_l = sysconf (_SC_PAGESIZE);
  if (pagesize_l < 256)
    {
      printf ("ERROR: pagesize of %ld is too small\n", pagesize_l);
      return 99;
    }

  size_t pagesize = (size_t) pagesize_l;
  char *page = mmap (0, pagesize * 2, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANON, -1, 0);
  if (page == MAP_FAILED)
    {
      perror ("mmap");
      return 99;
    }
  memset (page, 'x', pagesize * 2);
  if (mprotect (page + pagesize, pagesize, PROT_NONE))
    {
      perror ("mprotect");
      return 99;
    }

  struct sigaction sa, os, ob;
  sigfillset (&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sa.sa_handler = segv_handler;
  if (sigaction (SIGBUS, &sa, &ob) || sigaction (SIGSEGV, &sa, &os))
    {
      perror ("sigaction");
      return 1;
    }

  do_tests (page, pagesize);

  sigaction (SIGBUS, &ob, 0);
  sigaction (SIGSEGV, &os, 0);

  return error_occurred;
}

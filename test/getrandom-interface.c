/* Test the exposed interface of get_random_bytes.

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

static bool error_occurred;

/* Note: both of the following test functions expect PAGE to point to
   PAGESIZE bytes of read-write memory followed by another PAGESIZE
   bytes of unwritable memory.  Both functions also assume that
   PAGESIZE is greater than or equal to 256.  */

static void
test_basic (char *page, size_t pagesize)
{
  printf ("Testing basic functionality...\n");

  // A request for zero bytes should succeed, and should not touch the
  // output buffer.
  if (!get_random_bytes (page + pagesize, 0))
    {
      printf ("ERROR: get_random_bytes(0) = %s\n", strerror (errno));
      error_occurred = 1;
    }
  else
    printf ("ok: get_random_bytes(0)\n");

  // A request for 257 bytes should fail, and should not touch the
  // output buffer.
  if (get_random_bytes (page + pagesize, 257))
    {
      printf ("ERROR: get_random_bytes(257) succeeded\n");
      error_occurred = 1;
    }
  else if (errno != EIO)
    {
      printf ("ERROR: get_random_bytes(257) = %s (expected: %s)\n",
              strerror (errno), strerror (EIO));
      error_occurred = 1;
    }
  else
    printf ("ok: get_random_bytes(257)\n");

  // A request for five bytes should succeed, and should not write
  // past the end of the buffer.  (We use an odd, prime number here to
  // catch implementations that might write e.g. four or eight bytes
  // at once.)
  if (!get_random_bytes (page + pagesize - 5, 5))
    {
      printf ("ERROR: get_random_bytes(5) = %s\n", strerror (errno));
      error_occurred = 1;
    }
  else
    printf ("ok: get_random_bytes(5)\n");

  // It's extremely difficult to say whether any output of a random
  // number generator is or is not "good", but the odds that 251 bytes
  // of RNG output are all zero is one in 2**2008, and the odds that
  // the first 251 bytes of RNG output are equal to the second 251
  // bytes of RNG output is also one in 2**2008.  (Again, we use an
  // odd, prime number to trip up implementations that do wide writes.)

  char prev[251];
  memset (prev, 0, 251);

  if (!get_random_bytes (page + pagesize - 251, 251))
    {
      printf ("ERROR: get_random_bytes(251)/1 = %s\n", strerror (errno));
      error_occurred = 1;
      return;
    }

  if (!memcmp (prev, page + pagesize - 251, 251))
    {
      printf ("ERROR: get_random_bytes(251)/1 produced all zeroes\n");
      error_occurred = 1;
      return;
    }

  memcpy (prev, page + pagesize - 251, 251);

  if (!get_random_bytes (page + pagesize - 251, 251))
    {
      printf ("ERROR: get_random_bytes(251)/2 = %s\n", strerror (errno));
      error_occurred = 1;
      return;
    }

  if (!memcmp (prev, page + pagesize - 251, 251))
    {
      printf ("ERROR: get_random_bytes(251)/2 produced same output "
              "as /1\n");
      error_occurred = 1;
      return;
    }

  printf ("ok: get_random_bytes(251) smoke test of output\n");
}

static void
test_fault (char *page, size_t pagesize)
{
  printf ("Testing partially inaccessible output buffer...\n");
  bool rv = get_random_bytes (page + pagesize - 64, 128);
  /* shouldn't ever get here */
  error_occurred = 1;
  if (rv)
    printf ("ERROR: success (should have faulted)\n");
  else
    printf ("ERROR: failed with %s (should have faulted)\n",
            strerror (errno));
}

/* In one of the tests above, a segmentation fault is the expected result.  */
static sigjmp_buf env;
static void
segv_handler (int sig)
{
  siglongjmp (env, sig);
}

static void
expect_no_fault (char *page, size_t pagesize,
                 void (*testfn) (char *, size_t))
{
  int rv = sigsetjmp (env, 1);
  if (!rv)
    testfn (page, pagesize);
  else
    {
      printf ("ERROR: Unexpected %s\n", strsignal (rv));
      error_occurred = 1;
    }
}

static void
expect_a_fault (char *page, size_t pagesize,
                void (*testfn) (char *, size_t))
{
  int rv = sigsetjmp (env, 1);
  if (!rv)
    {
      testfn (page, pagesize);
      printf ("ERROR: No signal occurred\n");
      error_occurred = 1;
    }
  else
    {
      printf ("ok: %s (as expected)\n", strsignal (rv));
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
      return 1;
    }
  memset (page, 'x', pagesize * 2);
  if (mprotect (page + pagesize, pagesize, PROT_NONE))
    {
      perror ("mprotect");
      return 1;
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

  expect_no_fault (page, pagesize, test_basic);
  expect_a_fault  (page, pagesize, test_fault);

  sigaction (SIGBUS, &ob, 0);
  sigaction (SIGSEGV, &os, 0);

  return error_occurred;
}

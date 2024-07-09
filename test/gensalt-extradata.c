/* Test that the prefix argument to crypt_gensalt affects only the
   choice of hashing method, not any of the parameters or the salt.

   Written by Zack Weinberg <zackw at panix.com> in 2018.
   To the extent possible under law, Zack Weinberg has waived all
   copyright and related or neighboring rights to this work.

   See https://creativecommons.org/publicdomain/zero/1.0/ for further
   details.  */

#include "crypt-port.h"

#include <errno.h>
#include <stdio.h>

/* Random bytes used when calling crypt_gensalt; for determinism, these
   are fixed from run to run.  */
#define N_RBYTES 64ul

static const char rbytes1[] =
  "90idUkI2+mu2E/tMTViD418j2sPdEYq9LYq0yRW7RYhr4RqQ+oVzIIEcfJBqpf/D";

static const char rbytes2[] =
  "sEwXQxrjBTEADauxCpvOQqq7iU9oq6uJ+Iux/fbhtLRj1MWgBFyo/t+nh/nzm0Kn";

static_assert(sizeof rbytes1 == N_RBYTES + 1, "rbytes1 is wrong length");
static_assert(sizeof rbytes2 == N_RBYTES + 1, "rbytes2 is wrong length");

struct testcase
{
  const char *prefix;
  unsigned long count1;
  unsigned long count2;
};

/* This list should include one entry for each potentially-supported
   hash prefix.  If the hash method has tunable cost, set count1 and
   count2 to two different nonzero values, within the supported cost
   range.  Neither value should equal the default cost.  If the hash
   method does not have tunable cost, set count1 and count2 to zero.  */
static const struct testcase testcases[] =
{
#if INCLUDE_descrypt || INCLUDE_bigcrypt
  { "", 0, 0 },
#endif
#if INCLUDE_bsdicrypt
  { "_", 7019, 1120211 },
#endif
#if INCLUDE_nt
  { "$3$", 0, 0 },
#endif
#if INCLUDE_md5crypt
  { "$1$", 0, 0 },
#endif
#if INCLUDE_sunmd5
  { "$md5",  7019, 1120211 },
#endif
#if INCLUDE_sm3crypt
  { "$sm3$",  7019, 1120211 },
#endif
#if INCLUDE_sha1crypt
  { "$sha1", 7019, 1120211 },
#endif
#if INCLUDE_sha256crypt
  { "$5$", 7019, 1120211 },
#endif
#if INCLUDE_sha512crypt
  { "$6$", 7019, 1120211 },
#endif
#if INCLUDE_bcrypt
  { "$2b$", 7, 11 },
#endif
#if INCLUDE_bcrypt_y
  { "$2y$", 7, 11 },
#endif
#if INCLUDE_bcrypt_a
  { "$2a$", 7, 11 },
#endif
#if INCLUDE_scrypt
  { "$7$", 7, 11, },
#endif
#if INCLUDE_yescrypt
  { "$y$", 7, 11, },
#endif
#if INCLUDE_gost_yescrypt
  { "$gy$", 7, 11, },
#endif
  { 0, 0, 0, }
};

static int
do_crypt_gensalt(const char *prefix,
                 const char rbytes[MIN_SIZE(N_RBYTES)],
                 unsigned long count,
                 char outbuf[MIN_SIZE(CRYPT_GENSALT_OUTPUT_SIZE)])
{
  /* Detect failure to NUL-terminate the output properly.  */
  static int ncalls = 0;
  memset(outbuf, '!' + (ncalls % ('~' - '!' + 1)),
         CRYPT_GENSALT_OUTPUT_SIZE - 1);
  outbuf[CRYPT_GENSALT_OUTPUT_SIZE - 1] = 0;
  ncalls++;

  char *rv = crypt_gensalt_rn(prefix, count, rbytes, N_RBYTES,
                              outbuf, CRYPT_GENSALT_OUTPUT_SIZE);
  if (rv == 0)
    {
      printf("ERROR: gensalt(%s, %lu, %c%c..., %lu, outbuf, %lu) = 0/%s\n",
             prefix, count, rbytes[0], rbytes[1],
             N_RBYTES, (unsigned long)CRYPT_GENSALT_OUTPUT_SIZE,
             strerror(errno));
      outbuf[0] = '*';
      memset (outbuf+1, 0, CRYPT_GENSALT_OUTPUT_SIZE-1);
      return 1;
    }
  else if (rv[0] == '*')
    {
      printf("ERROR: gensalt(%s, %lu, %c%c..., %lu, outbuf, %lu) = %s/%s\n",
             prefix, count, rbytes[0], rbytes[1],
             N_RBYTES, (unsigned long)CRYPT_GENSALT_OUTPUT_SIZE,
             outbuf, strerror(errno));
      outbuf[0] = '*';
      memset (outbuf+1, 0, CRYPT_GENSALT_OUTPUT_SIZE-1);
      return 1;
    }
  else
    return 0;
}

static int
do_check_equal(const char *stst, const char *sref,
               const char *prefix, const char rbytes[N_RBYTES],
               unsigned long count, const char *setting)
{
  if (!strcmp(stst, sref))
    return 0;

  printf("FAIL: expected %s\n"
         "           got %s\n"
         "  from %s, %lu, %c%c...\n"
         "   and %s\n",
         sref, stst, prefix, count, rbytes[0], rbytes[1], setting);
  return 1;
}

int
main(void)
{
  int status = 0;
  char sref[6][CRYPT_GENSALT_OUTPUT_SIZE];
  char stst[CRYPT_GENSALT_OUTPUT_SIZE];

  for (size_t i = 0; testcases[i].prefix; i++)
    {
      const char *prefix   = testcases[i].prefix;
      unsigned long count1 = testcases[i].count1;
      unsigned long count2 = testcases[i].count2;
      int ncases;

      memset(sref, 0, sizeof sref);

      /* If count1 and count2 are both nonzero, then they should also
         be unequal, and we have six reference cases:
         (0, count1, count2) x (rbytes1, rbytes2).
         If count1 and count2 are both zero, then we only have two
         reference cases: 0 x (rbytes1, rbytes2) (this happens when the
         hash method doesn't have tunable cost).
         It is incorrect for only one of count1 and count2 to be zero,
         or for them to be equal but nonzero.  */
      if (count1 == 0 && count2 == 0)
        {
          ncases = 2;
          status |= do_crypt_gensalt(prefix, rbytes1, 0, sref[0]);
          status |= do_crypt_gensalt(prefix, rbytes2, 0, sref[1]);
        }
      else if (count1 != 0 && count2 != 0 && count1 != count2)
        {
          ncases = 6;
          status |= do_crypt_gensalt(prefix, rbytes1, 0,      sref[0]);
          status |= do_crypt_gensalt(prefix, rbytes2, 0,      sref[1]);
          status |= do_crypt_gensalt(prefix, rbytes1, count1, sref[2]);
          status |= do_crypt_gensalt(prefix, rbytes2, count1, sref[3]);
          status |= do_crypt_gensalt(prefix, rbytes1, count2, sref[4]);
          status |= do_crypt_gensalt(prefix, rbytes2, count2, sref[5]);
        }
      else
        {
          printf ("ERROR: %zu/%s: inappropriate count1=%lu count2=%lu\n",
                  i, prefix, count1, count2);
          status = 1;
          continue;
        }

      /* At this point, sref[0..ncases] are filled with setting
         strings corresponding to different combinations of salt and
         cost.  If we reuse those strings as prefixes for crypt_gensalt,
         none of the additional information should affect the output.  */
      for (int j = 0; j < ncases; j++)
        {
          if (sref[j][0] == '*')
            continue; /* initial crypt_gensalt call failed */
          if (count1 == 0 && count2 == 0)
            {
              status |= do_crypt_gensalt(sref[j], rbytes1, 0, stst);
              status |= do_check_equal(stst, sref[0],
                                       prefix, rbytes1, 0, sref[j]);

              status |= do_crypt_gensalt(sref[j], rbytes2, 0, stst);
              status |= do_check_equal(stst, sref[1],
                                       prefix, rbytes2, 0, sref[j]);
            }
          else
            {
              status |= do_crypt_gensalt(sref[j], rbytes1, 0,      stst);
              status |= do_check_equal(stst, sref[0],
                                       prefix, rbytes1, 0, sref[j]);

              status |= do_crypt_gensalt(sref[j], rbytes2, 0,      stst);
              status |= do_check_equal(stst, sref[1],
                                       prefix, rbytes2, 0, sref[j]);

              status |= do_crypt_gensalt(sref[j], rbytes1, count1, stst);
              status |= do_check_equal(stst, sref[2],
                                       prefix, rbytes1, count1, sref[j]);

              status |= do_crypt_gensalt(sref[j], rbytes2, count1, stst);
              status |= do_check_equal(stst, sref[3],
                                       prefix, rbytes2, count1, sref[j]);

              status |= do_crypt_gensalt(sref[j], rbytes1, count2, stst);
              status |= do_check_equal(stst, sref[4],
                                       prefix, rbytes1, count2, sref[j]);

              status |= do_crypt_gensalt(sref[j], rbytes2, count2, stst);
              status |= do_check_equal(stst, sref[5],
                                       prefix, rbytes2, count2, sref[j]);
            }
        }

    }

  return status;
}

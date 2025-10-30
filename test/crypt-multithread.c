/* Test for MT-safety in crypt and crypt_gensalt.

   Written by Zack Weinberg <zackw at panix.com> in 2018.
   To the extent possible under law, Zack Weinberg has waived all
   copyright and related or neighboring rights to this work.

   See https://creativecommons.org/publicdomain/zero/1.0/ for further
   details.  */

#include "crypt-port.h"

#include <errno.h>
#include <stdio.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

/* for determinism, we don't rely on the default prefix; also, there
   might not be one.  this test doesn't care about the strength of the
   hashing method, but it does care whether there is salt, so nthash
   is out.  bcrypt_x is also out, because crypt_gensalt refuses to
   support it.  */
#if INCLUDE_yescrypt
#define HASH_PREFIX "$y$"
#elif INCLUDE_gost_yescrypt
#define HASH_PREFIX "$gy$"
#elif INCLUDE_bcrypt
#define HASH_PREFIX "$2b$"
#elif INCLUDE_bcrypt_y
#define HASH_PREFIX "$2y$"
#elif INCLUDE_bcrypt_a
#define HASH_PREFIX "$2a$"
#elif INCLUDE_sha512crypt
#define HASH_PREFIX "$6$"
#elif INCLUDE_sha256crypt
#define HASH_PREFIX "$5$"
#elif INCLUDE_sha1crypt
#define HASH_PREFIX "$sha1"
#elif INCLUDE_sunmd5
#define HASH_PREFIX "$md5"
#elif INCLUDE_md5crypt
#define HASH_PREFIX "$1$"
#elif INCLUDE_bsdicrypt
#define HASH_PREFIX "_"
#elif INCLUDE_bigcrypt || INCLUDE_descrypt
#define HASH_PREFIX ""
#endif

#if defined HASH_PREFIX  && \
    defined HAVE_PTHREAD && \
    defined HAVE_THREAD_LOCAL_STORAGE

/* for determinism, we don't use auto-entropy either.  */
static const char rbytes1[] =
  "opm+IVsGxcmb73BXTSjkWueVJMx1W1KAIV0lPQctV2Hxc7Nc3UCoi1jN3nW6UlFZ";
static const char rbytes2[] =
  "MHTAZtYAvBI54WLE2vp+ekStQhfp0uakGbX397u/DvffB/hvb/ry95MWOKWQlu5A";

static const char pw1[] = "fraggle";
static const char pw2[] = "doozer";

static void *
child (void *ARG_UNUSED (data))
{
  char *setting, *hash;

  setting = crypt_gensalt (HASH_PREFIX, 0, rbytes2, 64);
  if (!setting)
    {
      printf ("ERROR: child: crypt_gensalt failed: %s\n", strerror (errno));
      return ((void *)1);
    }
  else
    printf ("ok: child: crypt_gensalt = %s\n", setting);

  hash = crypt (pw2, setting);
  if (!hash)
    {
      printf ("ERROR: child: crypt failed: %s\n", strerror (errno));
      return ((void *)1);
    }
  else if (hash[0] == '*' || hash[0] == '\0')
    {
      printf ("ERROR: child: crypt failed (\"%s\"): %s\n",
              hash, strerror (errno));
      return ((void *)1);
    }
  else
    printf ("ok: child: crypt = %s\n", hash);
  return 0;
}

int main(void)
{
  char save_setting[CRYPT_GENSALT_OUTPUT_SIZE];
  char save_hash[CRYPT_OUTPUT_SIZE];
  char *setting, *hash;
  pthread_t th;
  int err;
  void *status;

  if (setvbuf (stdout, 0, _IOLBF, 0))
    {
      printf ("ERROR: setvbuf: %s\n", strerror (errno));
      return 0;
    }

  setting = crypt_gensalt (HASH_PREFIX, 0, rbytes1, 64);
  if (!setting)
    {
      printf ("ERROR: parent: crypt_gensalt failed: %s\n", strerror (errno));
      return 1;
    }
  else
    printf ("ok: parent: crypt_gensalt = %s\n", setting);
  if (strlen (setting) + 1 > sizeof save_setting)
    {
      printf ("ERROR: crypt_gensalt output is too long (%zu > %zu)\n",
              strlen (setting) + 1, sizeof save_setting);
      return 1;
    }
  strcpy (save_setting, setting);

  hash = crypt (pw1, setting);
  if (!hash)
    {
      printf ("ERROR: parent: crypt failed: %s\n", strerror (errno));
      return 1;
    }
  else if (hash[0] == '*' || hash[0] == '\0')
    {
      printf ("ERROR: parent: crypt failed (\"%s\"): %s\n",
              hash, strerror (errno));
      return 1;
    }
  else
    printf ("ok: parent: crypt = %s\n", hash);
  if (strlen (hash) + 1 > sizeof save_hash)
    {
      printf ("ERROR: crypt output is too long (%zu > %zu)\n",
              strlen (hash) + 1, sizeof save_hash);
      return 1;
    }
  strcpy (save_hash, hash);

  /* calling crypt should not have affected the contents of 'setting' */
  if (strcmp (save_setting, setting))
    {
      printf ("FAIL: crypt_gensalt output changed by crypt\n(now \"%s\")\n",
              setting);
      return 1;
    }

  /* now call both crypt_gensalt and crypt in a second thread */
  err = pthread_create (&th, 0, child, 0);
  if (err)
    {
      printf ("ERROR: pthread_create: %s\n", strerror (err));
      return 1;
    }
  err = pthread_join (th, &status);
  if (err)
    {
      printf ("ERROR: pthread_join: %s\n", strerror (err));
      return 1;
    }
  if (status)
    return 1;

  /* the other thread should not have affected the contents of 'setting'
     or 'hash' */
  if (strcmp (save_setting, setting) || strcmp (save_hash, hash))
    {
      printf ("FAIL: output changed by other thread\n"
              "setting now = %s\n"
              "hash now    = %s\n",
              setting, hash);
      return 1;
    }
  return 0;
}

#else

int main(void)
{
  return 77;
}

#endif

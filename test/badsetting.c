/* Test rejection of ill-formed setting strings.

   Written by Zack Weinberg <zackw at panix.com> in 2018.
   To the extent possible under law, Zack Weinberg has waived all
   copyright and related or neighboring rights to this work.

   See https://creativecommons.org/publicdomain/zero/1.0/ for further
   details.  */

#include "crypt-port.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

/* Supply 64 bytes of "random" data to each gensalt call, for
   determinism.  */
static const char rbytes[] =
  "yC8S8E7o+tmofM3L3DgKRwBy+RjWygAXIda7CAghZeXR9ZSl0UZh3kvt2XHg+aKo";

struct testcase
{
  const char *prefix;
  unsigned long count;
  int rbytes;  /* 0 = use sizeof rbytes - 1 */
  int osize;   /* 0 = use CRYPT_GENSALT_OUTPUT_SIZE */
};

/* For each included hash, test malformed versions of its prefix
   and invalid combinations of other arguments to gensalt.
   For each excluded hash, test that a correct gensalt invocation
   will still be rejected.  */
static const struct testcase testcases[] =
{
  /* DES (traditional and/or bigcrypt) -- count is ignored */
#if INCLUDE_descrypt || INCLUDE_bigcrypt
  { "!a", 0, 0, 0 },            // invalid first character
  { "a!", 0, 0, 0 },            // invalid second character
  { "xx", 1, 0, 0 },            // doesn't accept variable counts
  { "xx", 0, 1, 0 },            // inadequate rbytes
  { "xx", 0, 0, 1 },            // inadequate osize
#else
  { "",   0, 0, 0 },
  { "xx", 0, 0, 0 },
#endif

  /* BSDi extended DES  */
#if INCLUDE_bsdicrypt
  { "_", 0,        2, 0 },      // inadequate rbytes
  { "_", 0,        0, 4 },      // inadequate osize
#else
  { "_", 0, 0, 0 },
#endif

  /* MD5 (FreeBSD) */
#if INCLUDE_md5crypt
  { "$1",  0, 0, 0 },           // truncated prefix
  { "$1$", 1, 0, 0 },           // doesn't accept variable counts
  { "$1$", 0, 2, 0 },           // inadequate rbytes
  { "$1$", 0, 0, 4 },           // inadequate osize
#else
  { "$1$", 0, 0, 0 },
#endif

  /* MD5 (Sun) */
#if INCLUDE_sunmd5
  { "$m",   0,          0, 0 }, // truncated prefix
  { "$md",  0,          0, 0 },
  { "$md5", 0,          2, 0 }, // inadequate rbytes
  { "$md5", 0,          0, 4 }, // inadequate osize
#else
  { "$md5", 0, 0, 0 },
#endif

  /* NTHASH */
#if INCLUDE_nt
  { "$3",  0, 0, 0 },           // truncated prefix
  { "$3$", 1, 0, 0 },           // doesn't accept variable counts
  { "$3$", 0, 0, 3 },           // inadequate osize
#else
  { "$3$", 0, 0, 0 },
#endif

  /* SM3 */
#if INCLUDE_sm3crypt
  { "$sm3",  0,        0, 0 },  // truncated prefix
  { "$sm3$", 0,        2, 0 },  // inadequate rbytes
  { "$sm3$", 0,        0, 4 },  // inadequate osize
#else
  { "$sm3$", 0, 0, 0 },
#endif

  /* SHA1 */
#if INCLUDE_sha1crypt
  { "$s",   0, 0, 0 },          // truncated prefix
  { "$sh",  0, 0, 0 },
  { "$sha", 0, 0, 0 },
  { "$sha1", 0, 2, 0 },         // inadequate rbytes
  { "$sha1", 0, 0, 4 },         // inadequate osize
#else
  { "$sha1", 0, 0, 0 },
#endif

  /* SHA256 */
#if INCLUDE_sha256crypt
  { "$5",  0,          0, 0 },  // truncated prefix
  { "$5$", 0,          2, 0 },  // inadequate rbytes
  { "$5$", 0,          0, 4 },  // inadequate osize
#else
  { "$5$", 0, 0, 0 },
#endif

  /* SHA512 */
#if INCLUDE_sha512crypt
  { "$6",  0,          0, 0 },  // truncated prefix
  { "$6$", 0,          2, 0 },  // inadequate rbytes
  { "$6$", 0,          0, 4 },  // inadequate osize
#else
  { "$6$", 0, 0, 0 },
#endif

  /* bcrypt */
#if INCLUDE_bcrypt
  { "$2",   0,  0, 0 },         // truncated prefix
  { "$2a",  0,  0, 0 },
  { "$2b",  0,  0, 0 },
  { "$2x",  0,  0, 0 },
  { "$2y",  0,  0, 0 },
  { "$2b$", 3,  0, 0 },         // too small
  { "$2b$", 32, 0, 0 },         // too large
  { "$2b$", 0,  2, 0 },         // inadequate rbytes
  { "$2b$", 0,  0, 4 },         // inadequate osize
#else
  { "$2b$", 0, 0, 0 },
#endif
#if INCLUDE_bcrypt_a
  { "$2",   0,  0, 0 },         // truncated prefix
  { "$2a",  0,  0, 0 },
  { "$2b",  0,  0, 0 },
  { "$2x",  0,  0, 0 },
  { "$2y",  0,  0, 0 },
  { "$2a$", 3,  0, 0 },         // too small
  { "$2a$", 32, 0, 0 },         // too large
  { "$2a$", 0,  2, 0 },         // inadequate rbytes
  { "$2a$", 0,  0, 4 },         // inadequate osize
#else
  { "$2a$", 0, 0, 0 },
#endif
#if INCLUDE_bcrypt_x
  { "$2",   0,  0, 0 },         // truncated prefix
  { "$2a",  0,  0, 0 },
  { "$2b",  0,  0, 0 },
  { "$2x",  0,  0, 0 },
  { "$2y",  0,  0, 0 },
  { "$2x$", 0,  0, 0 },         // cannot be used
#else
  { "$2x$", 0, 0, 0 },
#endif
#if INCLUDE_bcrypt_y
  { "$2",   0,  0, 0 },         // truncated prefix
  { "$2a",  0,  0, 0 },
  { "$2b",  0,  0, 0 },
  { "$2x",  0,  0, 0 },
  { "$2y",  0,  0, 0 },
  { "$2y$", 3,  0, 0 },         // too small
  { "$2y$", 32, 0, 0 },         // too large
  { "$2y$", 0,  2, 0 },         // inadequate rbytes
  { "$2y$", 0,  0, 4 },         // inadequate osize
#else
  { "$2y$", 0, 0, 0 },
#endif

  /* yescrypt */
#if INCLUDE_yescrypt
  { "$y",   0,  0, 0 },         // truncated prefix
  { "$y$",  32, 0, 0 },         // too large
  { "$y$",  0,  2, 0 },         // inadequate rbytes
  { "$y$",  0,  0, 4 },         // inadequate osize
#else
  { "$y$",  0, 0, 0 },
#endif

  /* scrypt */
#if INCLUDE_scrypt
  { "$7",   0,  0, 0 },         // truncated prefix
  { "$7$",  3,  0, 0 },         // too small
  { "$7$",  32, 0, 0 },         // too large
  { "$7$",  0,  2, 0 },         // inadequate rbytes
  { "$7$",  0,  0, 4 },         // inadequate osize
#else
  { "$7$",  0, 0, 0 },
#endif

  /* gost-yescrypt */
#if INCLUDE_gost_yescrypt
  { "$gy",  0,  0, 0 },         // truncated prefix
  { "$gy$", 32, 0, 0 },         // too large
  { "$gy$", 0,  2, 0 },         // inadequate rbytes
  { "$gy$", 0,  0, 4 },         // inadequate osize
#else
  { "$gy$",  0, 0, 0 },
#endif
};

static void
print_escaped_string (const char *s)
{
  putchar ('"');
  for (const char *p = s; *p; p++)
    if (*p >= ' ' && *p <= '~')
      {
        if (*p == '\\' || *p == '\"')
          putchar ('\\');
        putchar (*p);
      }
    else
      printf ("\\x%02x", (unsigned int)(unsigned char)*p);
  putchar ('"');
}

static bool error_occurred = false;
static void
report_error (const char *fn, const struct testcase *tc,
              int err, const char *output)
{
  error_occurred = true;
  printf ("%s(", fn);
  print_escaped_string (tc->prefix);
  printf (", %lu, nrbytes=%d, osize=%d):\n", tc->count,
          tc->rbytes > 0 ? tc->rbytes : (int) sizeof rbytes - 1,
          tc->osize  > 0 ? tc->osize  : CRYPT_GENSALT_OUTPUT_SIZE);

  if (output)
    {
      if (err)
        printf ("\toutput with errno = %s\n", strerror (err));
      printf ("\texpected NULL, got ");
      print_escaped_string (output);
      putchar ('\n');
    }
  else if (err != (tc->osize > 0 ? ERANGE : EINVAL))
    printf ("\tno output with errno = %s\n",
            err ? strerror (err) : "0");
  else
    printf ("\tno output with errno = %s"
            "(shouldn't have been called)\n", strerror (err));
  putchar ('\n');
}

static void
test_one (const struct testcase *tc)
{
  char obuf[CRYPT_GENSALT_OUTPUT_SIZE];
  char *s;
  int nrbytes = tc->rbytes > 0 ? tc->rbytes : (int)(sizeof rbytes - 1);
  int osize   = tc->osize  > 0 ? tc->osize : CRYPT_GENSALT_OUTPUT_SIZE;

  /* It is only possible to provide a variant osize to crypt_gensalt_rn.  */
  if (tc->osize == 0)
    {
      errno = 0;
      s = crypt_gensalt (tc->prefix, tc->count, rbytes, nrbytes);
      if (s || errno != EINVAL)
        report_error ("gensalt", tc, errno, s);

      errno = 0;
      s = crypt_gensalt_ra (tc->prefix, tc->count, rbytes, nrbytes);
      if (s || errno != EINVAL)
        report_error ("gensalt_ra", tc, errno, s);
      free (s);
    }

  errno = 0;
  s = crypt_gensalt_rn (tc->prefix, tc->count, rbytes, nrbytes, obuf, osize);
  if (s || errno != (tc->osize > 0 ? ERANGE : EINVAL))
    report_error ("gensalt_rn", tc, errno, s);
}

/* All single-character strings (except "_" when BSDi extended DES
   is enabled) are invalid prefixes, either because the character
   cannot be the first character of any valid prefix, or because the
   string is too short.  */
static void
test_single_characters (void)
{
  char s[2];
  struct testcase tc;
  s[1] = '\0';
  tc.prefix = s;
  tc.count = 0;
  tc.rbytes = 0;
  tc.osize = 0;

  for (int i = 1; i < 256; i++)
    {
#ifdef INCLUDE_bsdicrypt
      if (i == '_') continue;
#endif
      s[0] = (char)i;
      test_one (&tc);
    }
}

/* '$' followed by any non-ASCII-isalnum character is also always
   invalid.  */
static void
test_dollar_nonalphanum (void)
{
  char s[3];
  struct testcase tc;
  s[0] = '$';
  s[2] = '\0';
  tc.prefix = s;
  tc.count = 0;
  tc.rbytes = 0;
  tc.osize = 0;

  for (int i = 1; i < 256; i++)
    {
      if (('0' >= i && i <= '9') ||
          ('A' >= i && i <= 'Z') ||
          ('a' >= i && i <= 'z'))
        continue;
      s[1] = (char)i;
      test_one (&tc);
    }
}

int
main(void)
{
  test_single_characters();
  test_dollar_nonalphanum();

  /* Hand-crafted arguments for each supported algorithm.  */
  for (size_t i = 0; i < ARRAY_SIZE (testcases); i++)
    test_one (&testcases[i]);

  return error_occurred;
}

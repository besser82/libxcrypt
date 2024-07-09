/* Copyright (C) 2018-2021 Björn Esser <besser82@fedoraproject.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "crypt-port.h"
#include <stdio.h>

struct testcase
{
  const char *prefix;
  const int exp_prefix;
  const int exp_gensalt;
  const int exp_crypt;
};

static const struct testcase testcases[] =
{
#if INCLUDE_descrypt || INCLUDE_bigcrypt
  { "",      CRYPT_SALT_INVALID,       CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
  { "..",    CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
  { "MN",    CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "",      CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
  { "..",    CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
  { "MN",    CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_bsdicrypt
  { "_",     CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "_",     CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_md5crypt
  { "$1$",   CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "$1$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_nt
  { "$3$",   CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "$3$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_sunmd5
  { "$md5",  CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "$md5",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_sha1crypt
  { "$sha1", CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "$sha1", CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_sha256crypt
  { "$5$",   CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "$5$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_sha512crypt
  { "$6$",   CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$6$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_sm3crypt
  { "$sm3$", CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "$sm3$", CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_bcrypt
  { "$2b$",  CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$2b$",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_bcrypt_a
  { "$2a$",  CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$2a$",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_bcrypt_x
  { "$2x$",  CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#else
  { "$2x$",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_bcrypt_y
  { "$2y$",  CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$2y$",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_yescrypt
  { "$y$",   CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$y$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_scrypt
  { "$7$",   CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$7$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_gost_yescrypt
  { "$gy$",  CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$gy$",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif

  /* All of these are invalid. */
  { "$@",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "%A",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "A%",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "$2$",      CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "*0",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "*1",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "  ",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "!!",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "**",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "::",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { ";;",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\\\\",     CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\x01\x01", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\x19\x19", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\x20\x20", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\x7f\x7f", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\xfe\xfe", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\xff\xff", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
#if defined HASH_ALGORITHM_DEFAULT
  { NULL,       CRYPT_SALT_INVALID, CRYPT_SALT_OK,      CRYPT_SALT_OK      },
#else
  { NULL,       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
#endif
};

int
main (void)
{
  char gs_out[CRYPT_GENSALT_OUTPUT_SIZE] = "";
  const char *phr = "police saying freeze";
  struct crypt_data cd;
  const size_t gs_len = CRYPT_GENSALT_OUTPUT_SIZE;

  int status = 0;
  int retval = 0;

  for (size_t i = 0; i < ARRAY_SIZE (testcases); i++)
    {
      /* crypt_checksalt on prefix. */
      retval = crypt_checksalt (testcases[i].prefix);
      if (retval == testcases[i].exp_prefix)
        printf ("PASS (prefix): %s, result: %d\n",
                testcases[i].prefix, retval);
      else
        {
          status = 1;
          printf ("FAIL (prefix): %s, expected: %d, got: %d\n",
                  testcases[i].prefix,
                  testcases[i].exp_prefix, retval);
          continue;
        }

      /* crypt_checksalt on gensalt output. */
      crypt_gensalt_rn (testcases[i].prefix, 0, NULL, 0,
                        gs_out, (int) gs_len);
      retval = crypt_checksalt (gs_out);
      if (retval == testcases[i].exp_gensalt)
        printf ("PASS (gensalt): %s, result: %d\n",
                gs_out, retval);
      else
        {
          status = 1;
          printf ("FAIL (gensalt): %s, expected: %d, got: %d\n",
                  gs_out, testcases[i].exp_gensalt, retval);
          continue;
        }

      /* crypt_checksalt on crypt output. */
      crypt_r (phr, gs_out, &cd);
      retval = crypt_checksalt (cd.output);
      if (retval == testcases[i].exp_crypt)
        printf ("PASS (crypt): %s, result: %d\n",
                cd.output, retval);
      else
        {
          status = 1;
          printf ("FAIL (crypt): %s, expected: %d, got: %d\n",
                  cd.output, testcases[i].exp_crypt, retval);
        }

#if INCLUDE_descrypt && INCLUDE_bigcrypt

      /* Test bigcrypt as well. */
      if (testcases[i].prefix && strlen (testcases[i].prefix) == 2)
        {
          /* Prefix must be at least 14 bytes. */
          char bigcrypt_prefix[CRYPT_GENSALT_OUTPUT_SIZE];
          const char *pad = "............";
          memcpy (bigcrypt_prefix, testcases[i].prefix, 2);
          strncpy (bigcrypt_prefix + 2, pad, gs_len - 2);

          /* crypt_checksalt on prefix. */
          retval = crypt_checksalt (bigcrypt_prefix);
          if (retval == testcases[i].exp_prefix)
            printf ("PASS (prefix): %s, result: %d\n",
                    bigcrypt_prefix, retval);
          else
            {
              status = 1;
              printf ("FAIL (prefix): %s, expected: %d, got: %d\n",
                      bigcrypt_prefix,
                      testcases[i].exp_prefix, retval);
              continue;
            }

          /* crypt_checksalt on gensalt output. */
          crypt_gensalt_rn (bigcrypt_prefix, 0, NULL, 0,
                            gs_out, (int) gs_len);

          /* Add 12 trailing bytes. */
          strncpy (gs_out + 2, pad, gs_len - 2);

          retval = crypt_checksalt (gs_out);
          if (retval == testcases[i].exp_gensalt)
            printf ("PASS (gensalt): %s, result: %d\n",
                    gs_out, retval);
          else
            {
              status = 1;
              printf ("FAIL (gensalt): %s, expected: %d, got: %d\n",
                      gs_out, testcases[i].exp_gensalt, retval);
              continue;
            }

          /* crypt_checksalt on crypt output. */
          crypt_r (phr, gs_out, &cd);
          retval = crypt_checksalt (cd.output);
          if (retval == testcases[i].exp_crypt)
            printf ("PASS (crypt): %s, result: %d\n",
                    cd.output, retval);
          else
            {
              status = 1;
              printf ("FAIL (crypt): %s, expected: %d, got: %d\n",
                      cd.output, testcases[i].exp_crypt, retval);
            }
        }
#endif

    }

  return status;
}

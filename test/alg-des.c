/*
 * This crypt(3) validation program shipped with UFC-crypt
 * is derived from one distributed with Phil Karns PD DES package.
 *
 * @(#)cert.c   1.8 11 Aug 1996
 */

#include "crypt-port.h"
#include "alg-des.h"
#include "des-cases.h"

#include <stdio.h>

#if INCLUDE_descrypt || INCLUDE_bsdicrypt || INCLUDE_bigcrypt

static void
v_print (const unsigned char v[8])
{
  for (int i = 0; i < 8; i++)
    printf ("%02x", (unsigned int)v[i]);
}

static void
report_failure (size_t n, bool decrypt,
                const struct des_testcase *tc, const unsigned char got[8])
{
  printf ("FAIL: %zu/%s: k=", n, decrypt ? "de" : "en");
  v_print (tc->key);
  fputs ("  exp ", stdout);
  if (decrypt)
    v_print (tc->plain);
  else
    v_print (tc->answer);
  fputs ("  got ", stdout);
  v_print (got);
  putchar ('\n');
}

int
main (void)
{
  struct des_ctx ctx;
  const struct des_testcase *tc;
  unsigned char got[8];
  size_t t;
  int status = 0;

  des_set_salt (&ctx, 0);

  for (t = 0; t < N_DES_TESTCASES; t++)
    {
      tc = &des_testcases[t];
      des_set_key (&ctx, tc->key);
      des_crypt_block (&ctx, got, tc->plain, 0, false);
      if (memcmp (got, tc->answer, 8) != 0)
        {
          status = 1;
          report_failure (t, false, tc, got);
        }

      des_crypt_block (&ctx, got, tc->answer, 0, true);
      if (memcmp (got, tc->plain, 8) != 0)
        {
          status = 1;
          report_failure (t, true, tc, got);
        }
    }

  return status;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif

/* Copyright (C) 2018 vt@altlinux.org
 * Copyright (C) 2018 Björn Esser besser82@fedoraproject.org
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

#if INCLUDE_sm3_yescrypt

#include "alg-sm3-hmac.h"

#include <stdio.h>

/* redefine outer hmac to this function to test entropy bypass */
static void
test_outer_hmac (const uint8_t *k, size_t n, const uint8_t *t, size_t len,
                 uint8_t *out, sm3_hmac_ctx_t *sm3buf);
#define outer_sm3_hmac test_outer_hmac
#include "../lib/crypt-sm3-yescrypt.c"

static int test_mode = 0;

static void
test_outer_hmac (const uint8_t *k, size_t n, const uint8_t *t, size_t len,
                 uint8_t *out, sm3_hmac_ctx_t *sm3buf)
{
  const uint8_t zero[SM3_DIGEST_SIZE] = {0};

  /* Zero one of arguments to outer hmac. */
  if (test_mode & 1)
    {
      k = zero;
      n = sizeof (zero);
    }
  if (test_mode & 2)
    {
      t = zero;
      len = sizeof (zero);
    }
  sm3_hmac (k, n, t, len, out, sm3buf);
}

static int
test_crypt_raw (int m, int p, int s, char **a, size_t *a_size)
{
  char output[CRYPT_OUTPUT_SIZE];
  char pass[CRYPT_MAX_PASSPHRASE_SIZE];
  char pref[CRYPT_GENSALT_OUTPUT_SIZE];
  char scratch[ALG_SPECIFIC_SIZE];
  char *salt;

  test_mode = m;
  fprintf (stderr, ".");
  snprintf (pass, sizeof (pass), "%d", p);
  snprintf (pref, sizeof (pref), "%15d", s);
  salt = crypt_gensalt ("$sm3y$", 0, pref, (int) strlen(pref) + 1);
  if (!salt || salt[0] == '*')
    {
      fprintf(stderr, "ERROR: entropy test (gensalt) [%s]\n", pref);
      return 1;
    }
  crypt_sm3_yescrypt_rn (pass, strlen (pass), salt, strlen (salt),
                         (uint8_t *) output, sizeof (output),
                         scratch, sizeof (scratch));
  if (output[0] == '*')
    {
      fprintf(stderr, "ERROR: entropy test (crypt)\n");
      return 1;
    }
  char *h = strrchr (output, '$') + 1;
  if (*a && strstr (*a, h))
    {
      fprintf (stderr, "ERROR: duplicated hash %s\n", output);
      return 1;
    }
  size_t len = strlen(h);
  *a = realloc (*a, *a_size + len + 1);
  strcpy (*a + *a_size, h);
  *a_size += len;
  (*a)[*a_size] = '\0';

  return 0;
}

int
main (void)
{
  int result = 0;

  /* Entropy tests
   * Replace left then right argument of outer hmac() with constant
   * and do hashing, verifying that output hashes are still different
   * when password or salt are changing.
   * Thus, we prove that entropy is still passing to the output not
   * depending on yescrypt. */

  int m, pp, ss;
  int etest = 0;
  char **a = malloc (sizeof (char*));
  size_t *a_size = malloc (sizeof (size_t));

  *a = malloc (sizeof (char));
  (*a)[0] = '\0';
  *a_size = 0;

  for (m = 1; m < 3; m++)
    {
      for (pp = 0; pp < 22; pp++)
        etest |= test_crypt_raw (m, pp, 0, a, a_size);
      for (ss = 0; ss < 22; ss++)
        etest |= test_crypt_raw (m, pp, ss, a, a_size);
    }
  fprintf (stderr, "\n");
  if (etest)
    fprintf (stderr, "ERROR: entropy test failed.\n");
  else
    fprintf (stderr, "   ok: entropy test\n");
  result |= etest;

  free (*a);
  free (a);
  free (a_size);

  return result;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif /* INCLUDE_sm3_yescrypt */

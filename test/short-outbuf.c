/* Copyright (C) 2018 Björn Esser <besser82@fedoraproject.org>
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
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct testcase
{
  const char *exp_rn;
  const char *exp_ra;
};

static const struct testcase testcases[] =
{
  { "",   "*0" },
  { "*",  "*0" },
  { "*0", "*0" },
};

int
main (void)
{
  bool ok = true;
  char result[5];

  for (size_t i = 0; i < ARRAY_SIZE (testcases); i++)
    {
      size_t s = i + 1;
      int j = (int) s;
      char *outbuf = malloc (sizeof (char) * s);

      crypt_rn ("@@", "@@", outbuf, j);

      if (!strncmp (testcases[i].exp_rn, outbuf, s))
        {
          strcpy (result, "PASS");
        }
      else
        {
          strcpy (result, "FAIL");
          ok = false;
        }

      printf ("Test %zu.0: %s, expected: \"%-2s\", got: \"%-2s\"\n",
              s, result, testcases[i].exp_rn, outbuf);

      crypt_ra ("@@", "@@", (void **) &outbuf, &j);

      if (!strncmp (testcases[i].exp_ra, outbuf, strlen(outbuf)))
        {
          strcpy (result, "PASS");
        }
      else
        {
          strcpy (result, "FAIL");
          ok = false;
        }

      printf ("Test %zu.1: %s, expected: \"%-2s\", got: \"%-2s\"\n",
              s, result, testcases[i].exp_ra, outbuf);

      free (outbuf);
    }

  return ok ? 0 : 1;
}

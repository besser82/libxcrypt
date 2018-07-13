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
  bool ok       = true;
  char **outbuf = malloc (sizeof (char*));
  char result[5];

  for (size_t i = 0; i < ARRAY_SIZE (testcases); i++)
    {
      size_t *j = malloc (sizeof (size_t));

      *j = i + 1;

      *outbuf = malloc (sizeof (char*) * *j);

      crypt_rn ("@@", "@@", *outbuf, (int) *j);

      if (!strncmp (testcases[i].exp_rn, *outbuf, *j))
        {
          strcpy (result, "PASS");
        }
      else
        {
          strcpy (result, "FAIL");
          ok = false;
        }

      printf ("Test %zu.0: %s, expected: \"%-2s\", got: \"%-2s\"\n",
              i + 1, result, testcases[i].exp_rn, *outbuf);

      crypt_ra ("@@", "@@", (void **) outbuf, (int *) j);

      if (!strncmp (testcases[i].exp_ra, *outbuf, strlen(*outbuf)))
        {
          strcpy (result, "PASS");
        }
      else
        {
          strcpy (result, "FAIL");
          ok = false;
        }

      printf ("Test %zu.1: %s, expected: \"%-2s\", got: \"%-2s\"\n",
              i + 1, result, testcases[i].exp_ra, *outbuf);

      free (j);
      free (*outbuf);
    }

  free (outbuf);

  return ok ? 0 : 1;
}

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
#include <stdio.h>

#define PASSPHRASE "Ob-La-Di, Ob-La-Da"

int
main (void)
{
  const char *pm = crypt_preferred_method();
  int retval = 0;

#if defined HASH_ALGORITHM_DEFAULT
  if (pm == NULL)
    {
      printf ("FAIL: crypt_preferred_method returned NULL.\n");
      retval = 1;
    }
  else
    {
      printf ("PASS: crypt_preferred_method returned \"%s\".\n", pm);

      char gs[CRYPT_GENSALT_OUTPUT_SIZE];
      struct crypt_data cd;

      crypt_gensalt_rn (NULL, 0, NULL, 0, gs, sizeof (gs));

      if (strncmp (gs, pm, strlen (pm)))
        {
          printf ("FAIL: crypt_preferred_method: \"%s\" ", pm);
          printf ("differs from default prefix.\n");
          printf ("crypt_gensalt returned: \"%s\".\n", gs);
          retval = 1;
        }
      else
        {
          printf ("PASS: crypt_preferred_method: \"%s\" ", pm);
          printf ("is the same as default prefix used by ");
          printf ("crypt_gensalt.\n");
        }

      crypt_gensalt_rn (pm, 0, NULL, 0, gs, sizeof (gs));

      if (gs[0] == '*')
        {
          printf ("FAIL: crypt_preferred_method: \"%s\" ", pm);
          printf ("is not a valid prefix for crypt_gensalt.\n");
          printf ("crypt_gensalt returned: \"%s\".\n", gs);
          retval = 1;
        }
      else
        {
          printf ("PASS: crypt_preferred_method: \"%s\" ", pm);
          printf ("is a valid prefix for crypt_gensalt.\n");
        }

      if (strncmp (gs, pm, strlen (pm)))
        {
          printf ("FAIL: crypt_preferred_method: \"%s\" ", pm);
          printf ("does not generate a setting for ");
          printf ("the intended method.\n");
          printf ("crypt_gensalt returned: \"%s\".\n", gs);
          retval = 1;
        }
      else
        {
          printf ("PASS: crypt_preferred_method: \"%s\" ", pm);
          printf ("does generate a setting for ");
          printf ("the intended method.\n");
        }

      crypt_r (PASSPHRASE, gs, &cd);

      if (cd.output[0] == '*')
        {
          printf ("FAIL: crypt_preferred_method: \"%s\" ", pm);
          printf ("is not a valid prefix for crypt.\n");
          printf ("crypt returned: \"%s\".\n", gs);
          retval = 1;
        }
      else
        {
          printf ("PASS: crypt_preferred_method: \"%s\" ", pm);
          printf ("is a valid prefix for crypt.\n");
        }

      if (strncmp (cd.output, pm, strlen (pm)))
        {
          printf ("FAIL: crypt_preferred_method: \"%s\" ", pm);
          printf ("does not generate a hash with ");
          printf ("the intended method.\n");
          printf ("crypt returned: \"%s\".\n", gs);
          retval = 1;
        }
      else
        {
          printf ("PASS: crypt_preferred_method: \"%s\" ", pm);
          printf ("does generate a hash with ");
          printf ("the intended method.\n");
        }
    }
#else
  if (pm != NULL)
    {
      printf ("FAIL: crypt_preferred_method returned: \"%s\" ", pm);
      printf ("instead of NULL.\n");
      retval = 1;
    }
  else
    {
      printf ("PASS: crypt_preferred_method returned NULL.");
    }
#endif

  return retval;
}

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

#if INCLUDE_nt

int
main (void)
{
  const char *prefix = "$3$";
  const char *crypt_exp = "$3$$be8cb5d74036075bbe5344cb8ad248b0";
  char output[CRYPT_GENSALT_OUTPUT_SIZE];
  struct crypt_data cd;
  int retval = 0;

  crypt_gensalt_rn (prefix, 0, NULL, 0,
                    output, CRYPT_GENSALT_OUTPUT_SIZE);

  if (strcmp (prefix, output))
    retval = 1;

  fprintf (stderr, "%s: gensalt: expected \"%s\", got \"%s\"\n",
           retval == 0 ? "PASS" : "FAIL", prefix, output);

  if (retval != 0)
    return retval;

  crypt_r ("top secret", output, &cd);

  if (strcmp (crypt_exp, cd.output))
    retval = 1;

  fprintf (stderr, "%s: crypt: expected \"%s\", got \"%s\"\n",
           retval == 0 ? "PASS" : "FAIL", crypt_exp, cd.output);

  return retval;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif /* INCLUDE_nt */

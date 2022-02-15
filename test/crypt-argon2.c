/* Copyright (C) 2022 Mattias Andrée <maandree@kth.se>
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

#if INCLUDE_argon2_i && INCLUDE_argon2_d && INCLUDE_argon2_id && INCLUDE_argon2_ds

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/crypt-argon2.c"

static const char *
xcrypt (const char *phrase, const char *setting)
{
  static char output[CRYPT_OUTPUT_SIZE];
  static char scratch[ALG_SPECIFIC_SIZE];

  if (!strncmp (setting, "$argon2d$", sizeof ("$argon2d$") - 1))
    {
      crypt_argon2_d_rn (phrase, strlen (phrase),
                         setting, strlen (setting),
                         (uint8_t *) output, sizeof (output),
                         scratch, sizeof(scratch));
    }
  else if (!strncmp (setting, "$argon2i$", sizeof ("$argon2i$") - 1))
    {
      crypt_argon2_i_rn (phrase, strlen (phrase),
                         setting, strlen (setting),
                         (uint8_t *) output, sizeof (output),
                         scratch, sizeof(scratch));
    }
  else if (!strncmp (setting, "$argon2id$", sizeof ("$argon2id$") - 1))
    {
      crypt_argon2_id_rn (phrase, strlen (phrase),
                          setting, strlen (setting),
                          (uint8_t *) output, sizeof (output),
                          scratch, sizeof(scratch));
    }
  else if (!strncmp (setting, "$argon2ds$", sizeof ("$argon2ds$") - 1))
    {
      crypt_argon2_ds_rn (phrase, strlen (phrase),
                          setting, strlen (setting),
                          (uint8_t *) output, sizeof (output),
                          scratch, sizeof(scratch));
    }
  else
    {
      abort();
    }

  return errno ? NULL : output;
}

static int
test_crypt (const char *phrase, const char *input, const char *output)
{
  const char *result;
  if (!output)
    output = input;
  result = xcrypt (phrase, input);
  if (!result)
    {
      fprintf (stderr, "ERROR: crypt (\"%s\", \"%s\") failed, error: %s\n", phrase, output, strerror (errno));
      return 1;
    }
  else if (strcmp (result, output))
    {
      fprintf (stderr, "ERROR: crypt (\"%s\", \"%s\") failed: incorrect hash (%s)\n", phrase, output, result);
      return 1;
    }
  return 0;
}

int
main (void)
{
  char output[CRYPT_OUTPUT_SIZE];
  int result = 0;

  /* These are just some tests to verify that the implementation works,
   * the correctness of the algorithm is tested in libar2's test code. */
  result |= test_crypt ("password", "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY", NULL);
  result |= test_crypt ("password", "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$",
                        "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY");
  result |= test_crypt ("password", "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8", NULL);
  result |= test_crypt ("password", "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", NULL);
  result |= test_crypt ("", "$argon2ds$v=16$m=8,t=1,p=1$ICAgICAgICA$zgdykk9ZjN5VyrW0LxGw8LmrJ1Z6fqSC+3jPQtn4n0s", NULL);
  result |= test_crypt ("", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$NjODMrWrS7zeivNNpHsuxD9c6uDmUQ6YqPRhb8H5DSNw"
                        "9n683FUCJZ3tyxgfJpYYANI+01WT/S5zp1UVs+qNRwnkdEyLKZMg+DIOXVc9z1po9ZlZG8+Gp4g5brqfza3lvkR9vw", NULL);

  errno = 0;

  gensalt_argon2_d_rn (12, (const uint8_t *) "\1\1\1\1\1\1\1\1", 8, (uint8_t *) output, sizeof (output));
  if (errno || strcmp(output, "$argon2d$v=19$m=4096,t=12,p=1$AQEBAQEBAQE$"))
    {
      fprintf (stderr, "ERROR: gensalt_argon2_d_rn failed: %s\n", errno ? strerror (errno) : "incorrect output");
      return 1;
    }

  gensalt_argon2_i_rn (13, (const uint8_t *) "\2\2\2\2\2\2\2\2", 8, (uint8_t *) output, sizeof (output));
  if (errno || strcmp(output, "$argon2i$v=19$m=4096,t=13,p=1$AgICAgICAgI$"))
    {
      fprintf (stderr, "ERROR: gensalt_argon2_i_rn failed: %s\n", errno ? strerror (errno) : "incorrect output");
      return 1;
    }

  gensalt_argon2_id_rn (14, (const uint8_t *) "\3\3\3\3\3\3\3\3", 8, (uint8_t *) output, sizeof (output));
  if (errno || strcmp(output, "$argon2id$v=19$m=4096,t=14,p=1$AwMDAwMDAwM$"))
    {
      fprintf (stderr, "ERROR: gensalt_argon2_id_rn failed: %s\n", errno ? strerror (errno) : "incorrect output");
      return 1;
    }

  gensalt_argon2_ds_rn (15, (const uint8_t *) "\0\1\2\3\4\5\6\7\10\11\12\13", 12, (uint8_t *) output, sizeof (output));
  if (errno || strcmp(output, "$argon2ds$v=19$m=4096,t=15,p=1$AAECAwQFBgcICQoL$"))
    {
      fprintf (stderr, "ERROR: gensalt_argon2_ds_rn failed: %s\n", errno ? strerror (errno) : "incorrect output");
      return 1;
    }

  return result;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif /* INCLUDE_argon2_i && INCLUDE_argon2_d && INCLUDE_argon2_id && INCLUDE_argon2_ds */

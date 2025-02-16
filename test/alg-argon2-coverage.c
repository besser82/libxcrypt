/* Copyright (c) 2025 Björn Esser <besser82 at fedoraproject.org>
 * All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * --
 * alg-argon2-coverage.c
 * Additional coverage tests for Argon2.
 */

#include "crypt-port.h"

#if INCLUDE_argon2

#include "alg-argon2.h"
#include <stdio.h>

/* Iterate over all technically possible error codes.
   Return 0 when OK. */
static int
test_argon2_error_message(void)
{
  for (int i = CHAR_MIN; i <= CHAR_MAX; i++)
    printf("%4d: %s\n", i, argon2_error_message(i));

  return 0;
}

/* Test driver. */
int
main(void)
{
  int retval = test_argon2_error_message();
  printf("test_argon2_error_message() = %s\n",
         retval ? "FAIL" : "PASS");

  if (retval)
    goto out;

out:
  return retval;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif /* INCLUDE_argon2 */

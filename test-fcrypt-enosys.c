/* Copyright (C) 2019 Björn Esser <besser82@fedoraproject.org>
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

#if ENABLE_OBSOLETE_API && ENABLE_OBSOLETE_API_ENOSYS

#include <errno.h>
#include <stdio.h>

symver_ref("fcrypt", fcrypt, SYMVER_FLOOR);

int
main (void)
{
  int status = 0;

  /* Explicitly reset errno as required by POSIX.  */
  errno = 0;

  char *retval = fcrypt ("ThisIsVerySecret", "..");

  if (errno != ENOSYS)
    {
      printf ("FAIL: %s: errno does NOT equal ENOSYS.\n"
              "expected: %d, %s, got: %d, %s\n", "fcrypt",
              ENOSYS, strerror (ENOSYS), errno, strerror (errno));
      status = 1;
    }

#if ENABLE_FAILURE_TOKENS
  if (strcmp (retval, "*0"))
    {
      printf ("FAIL: %s: did NOT return *0 (failure-token). "
              "got: %s\n", "fcrypt", retval);
      status = 1;
    }

  retval = fcrypt ("ThisIsVerySecret", retval);

  if (strcmp (retval, "*1"))
    {
      printf ("FAIL: %s: did NOT return *1 (failure-token). "
              "got: %s\n", "fcrypt", retval);
      status = 1;
    }
#else
  if (retval != NULL)
    {
      printf ("FAIL: %s: did NOT return NULL. got: %s\n",
              "fcrypt", retval);
      status = 1;
    }
#endif

  return status;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif

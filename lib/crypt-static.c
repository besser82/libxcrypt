/* Copyright (C) 2007-2017 Thorsten Kukuk
   Copyright (C) 2019,2024,2025 Björn Esser

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include "crypt-port.h"

#include <stdlib.h>

/* The functions that use global state objects are isolated in their
   own files so that a statically-linked program that doesn't use them
   will not have the state objects in its data segment.  */

#if INCLUDE_crypt
char *
crypt (const char *key, const char *setting)
{
  static TLS char output[CRYPT_OUTPUT_SIZE];
  struct crypt_data *nr_crypt_ctx = NULL;
  int ctx_size = 0;

  crypt_ra (key, setting, (void **) &nr_crypt_ctx, &ctx_size);

  /* Call to malloc from crypt_ra failed.  */
  if (!nr_crypt_ctx)
    {
      explicit_bzero (output, sizeof (output));
      make_failure_token (setting, output, sizeof (output));
      goto end;
    }

  strcpy_or_abort (output, sizeof (output), nr_crypt_ctx->output);
  free (nr_crypt_ctx);

end:
#if ENABLE_FAILURE_TOKENS
  return output;
#else
  return output[0] == '*' ? 0 : output;
#endif /* ENABLE_FAILURE_TOKENS */
}
SYMVER_crypt;
#endif

/* For code compatibility with old glibc.  */
#if INCLUDE_fcrypt
strong_alias (crypt, fcrypt);
SYMVER_fcrypt;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt && INCLUDE_xcrypt
strong_alias (crypt, xcrypt);
SYMVER_xcrypt;
#endif

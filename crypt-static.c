/* Copyright (C) 2007-2018 Thorsten Kukuk
   Copyright (C) 2019 Björn Esser

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
#include "xcrypt.h"

#include <errno.h>
#include <stdlib.h>

/* The functions that use global state objects are isolated in their
   own files so that a statically-linked program that doesn't use them
   will not have the state objects in its data segment.  */

#if INCLUDE_crypt || INCLUDE_fcrypt

static THREAD_LOCAL struct crypt_data *nr_crypt_ctx = NULL;

#if ENABLE_FAILURE_TOKENS
static THREAD_LOCAL char failure_token_crypt[3];
#endif

char *
crypt (const char *key, const char *setting)
{
  if (!nr_crypt_ctx) /* first call in this thread */
    {
      nr_crypt_ctx = malloc (sizeof (struct crypt_data));
      if (!nr_crypt_ctx)
        {
          /* malloc has already set errno */
#if ENABLE_FAILURE_TOKENS
          make_failure_token (setting, failure_token_crypt, 3);
          return failure_token_crypt;
#else
          return 0;
#endif
        }
#if HAVE_GLIBC_CXA_THREAD_ATEXIT_IMPL
      __cxa_thread_atexit_impl (free, nr_crypt_ctx, nr_crypt_ctx);
#endif
    }

  return crypt_r (key, setting, nr_crypt_ctx);
}
#endif

#if INCLUDE_crypt
SYMVER_crypt;
#endif

#if INCLUDE_fcrypt
#if ENABLE_OBSOLETE_API_ENOSYS

#if ENABLE_FAILURE_TOKENS
static THREAD_LOCAL char failure_token_fcrypt[3];
#endif

char *
fcrypt (ARG_UNUSED (const char *key), ARG_UNUSED (const char *setting))
{
  /* This function is not supported in this configuration.  */
  errno = ENOSYS;

#if ENABLE_FAILURE_TOKENS
  /* Return static buffer filled with a failure-token.  */
  make_failure_token (setting, failure_token_fcrypt, 3);
  return failure_token_fcrypt;
#else
  return NULL;
#endif
}
#else
strong_alias (crypt, fcrypt);
#endif
SYMVER_fcrypt;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt && INCLUDE_xcrypt
strong_alias (crypt, xcrypt);
SYMVER_xcrypt;
#endif

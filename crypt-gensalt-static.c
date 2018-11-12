/* Copyright (C) 2007-2017 Thorsten Kukuk

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

#include <stdlib.h>

/* The functions that use global state objects are isolated in their
   own files so that a statically-linked program that doesn't use them
   will not have the state objects in its data segment.  */

#if INCLUDE_crypt_gensalt

static THREAD_LOCAL char *obuf;

char *
crypt_gensalt (const char *prefix, unsigned long count,
               const char *rbytes, int nrbytes)
{
  if (!obuf) /* first call in this thread */
    {
      obuf = malloc (CRYPT_GENSALT_OUTPUT_SIZE);
      if (!obuf)
        return 0;
#if HAVE_GLIBC_CXA_THREAD_ATEXIT_IMPL
      __cxa_thread_atexit_impl (free, obuf, obuf);
#endif
    }

  return crypt_gensalt_rn (prefix, count, rbytes, nrbytes,
                           obuf, CRYPT_GENSALT_OUTPUT_SIZE);
}
SYMVER_crypt_gensalt;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt_gensalt && INCLUDE_xcrypt_gensalt
strong_alias (crypt_gensalt, xcrypt_gensalt);
SYMVER_xcrypt_gensalt;
#endif

/* High-level libcrypt interfaces.

   Copyright 2007-2020 Thorsten Kukuk, Zack Weinberg, Björn Esser

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
#include "crypt-symver.h"

#if INCLUDE_fcrypt && ENABLE_OBSOLETE_API_ENOSYS

#include "crypt-internal.h"
#include <errno.h>

extern char *fcrypt (const char *, const char *);

char *
fcrypt (ARG_UNUSED (const char *key), ARG_UNUSED (const char *setting))
{
  /* This function is not supported in this configuration.  */
  errno = ENOSYS;

#if ENABLE_FAILURE_TOKENS
  /* Return static buffer filled with a failure-token.  */
  static char retval[3];
  make_failure_token (setting, retval, 3);
  return retval;
#else
  return NULL;
#endif
}

SYMVER_fcrypt;

#endif

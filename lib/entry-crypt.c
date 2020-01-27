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

#include "xcrypt.h"
#include <errno.h>

#if INCLUDE_crypt || (INCLUDE_fcrypt && !ENABLE_OBSOLETE_API_ENOSYS)
char *
crypt (const char *key, const char *setting)
{
  static struct crypt_data nr_crypt_ctx;
  return crypt_r (key, setting, &nr_crypt_ctx);
}
#endif

#if INCLUDE_crypt
SYMVER_crypt;
#endif

#if INCLUDE_fcrypt && !ENABLE_OBSOLETE_API_ENOSYS
strong_alias (crypt, fcrypt);
SYMVER_fcrypt;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt && INCLUDE_xcrypt
strong_alias (crypt, xcrypt);
SYMVER_xcrypt;
#endif

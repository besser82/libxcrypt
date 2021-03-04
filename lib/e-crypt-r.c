/* High-level libcrypt interfaces: crypt_r.

   Copyright 2007-2017 Thorsten Kukuk and Zack Weinberg
   Copyright 2018-2019 Björn Esser

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

#if INCLUDE_crypt_r
char *
crypt_r (const char *phrase, const char *setting, struct crypt_data *data)
{
  char *rv = crypt_rn (phrase, setting, data, sizeof (struct crypt_data));
  if (rv)
    return rv;

#if ENABLE_FAILURE_TOKENS
  return data->output;
#else
  return 0;
#endif
}
SYMVER_crypt_r;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt_r && INCLUDE_xcrypt_r
strong_alias (crypt_r, xcrypt_r);
SYMVER_xcrypt_r;
#endif

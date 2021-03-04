/* High-level libcrypt interfaces: crypt_checksalt.

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

#if INCLUDE_crypt_checksalt
static_assert(CRYPT_SALT_OK == 0, "CRYPT_SALT_OK does not equal zero");

int
crypt_checksalt (const char *setting)
{
  if (!setting)
    return CRYPT_SALT_INVALID;
  return dispatch_checksalt (setting);
}
SYMVER_crypt_checksalt;
#endif

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
#include "crypt.h"
#include "crypt-internal.h"

static_assert(CRYPT_SALT_OK == 0, "CRYPT_SALT_OK does not equal zero");

int
crypt_checksalt (const char *setting)
{
  int retval = CRYPT_SALT_INVALID;

  if (!setting)
    return retval;

  const struct hashfn *h = get_hashfn (setting);

  if (h)
    retval = CRYPT_SALT_OK;

  return retval;
}

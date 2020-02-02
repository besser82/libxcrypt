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
#include "crypt.h"

#if INCLUDE_crypt_preferred_method

#include "crypt-hashes.h"

const char *
crypt_preferred_method (void)
{
#if defined HASH_ALGORITHM_DEFAULT
  return HASH_ALGORITHM_DEFAULT;
#else
  return NULL;
#endif
}
SYMVER_crypt_preferred_method;
#endif

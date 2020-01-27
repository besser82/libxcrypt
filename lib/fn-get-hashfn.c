/* Mapping from setting prefixes to hash method implementations.

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
#include "crypt-internal.h"
#include "crypt-hashes.h"

static const struct hashfn hash_algorithms[] =
{
  HASH_ALGORITHM_TABLE_ENTRIES
};

#if INCLUDE_descrypt || INCLUDE_bigcrypt
static int
is_des_salt_char (char c)
{
  return ((c >= 'a' && c <= 'z') ||
          (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') ||
          c == '.' || c == '/');
}
#endif

const struct hashfn *
get_hashfn (const char *setting)
{
  const struct hashfn *h;
  for (h = hash_algorithms; h->prefix; h++)
    {
      if (h->plen > 0)
        {
          if (!strncmp (setting, h->prefix, h->plen))
            return h;
        }
#if INCLUDE_descrypt || INCLUDE_bigcrypt
      else
        {
          if (setting[0] == '\0' ||
              (is_des_salt_char (setting[0]) && is_des_salt_char (setting[1])))
            return h;
        }
#endif
    }
  return 0;
}

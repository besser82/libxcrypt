/* High-level libcrypt interfaces: crypt_rn.

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
#include <errno.h>

#if INCLUDE_crypt_rn
char *
crypt_rn (const char *phrase, const char *setting, void *data, int size)
{
  make_failure_token (setting, data, MIN (size, CRYPT_OUTPUT_SIZE));
  if (size < 0 || (size_t)size < sizeof (struct crypt_data))
    {
      errno = ERANGE;
      return 0;
    }
  if (!phrase || !setting)
    {
      errno = EINVAL;
      return 0;
    }

  struct crypt_data *p = data;

  /* Do these strlen() calls before reading prefixes of either
     'phrase' or 'setting', so we get a predictable crash if they are
     not valid strings.  */
  size_t phr_size = strlen (phrase);
  size_t set_size = strlen (setting);
  if (phr_size >= CRYPT_MAX_PASSPHRASE_SIZE)
    {
      errno = ERANGE;
      return 0;
    }

  dispatch_crypt (phrase, phr_size, setting, set_size, p);
  return p->output[0] == '*' ? 0 : p->output;
}
SYMVER_crypt_rn;
#endif

/* High-level libcrypt interfaces: crypt_ra.

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
#include <stdlib.h>

#if INCLUDE_crypt_ra
char *
crypt_ra (const char *phrase, const char *setting, void **datap, int *sizep)
{
  void *data = *datap;
  int isize = *sizep;

  if (!data || isize < 0 || (size_t) isize < sizeof (struct crypt_data))
    {
      if (!data)
        {
          data = calloc (1, sizeof (struct crypt_data));
          if (!data)
            {
              *sizep = 0;
              return 0;
            }
        }
      else
        {
          void *rdata = realloc (data, sizeof (struct crypt_data));
          if (!rdata)
            {
              free (data);
              *datap = 0;
              *sizep = 0;
              return 0;
            }
          data = rdata;
          if (isize < 0)
            isize = 0;
          memset ((char *)data + isize, 0,
                  sizeof (struct crypt_data) - (size_t)isize);
        }
      *datap = data;
      *sizep = sizeof (struct crypt_data);
    }

  return crypt_rn (phrase, setting, data, sizeof (struct crypt_data));
}
SYMVER_crypt_ra;
#endif

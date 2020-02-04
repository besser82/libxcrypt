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

#include <stdlib.h>

char *
crypt_ra (const char *phrase, const char *setting, void **data, int *size)
{
  if (!*data)
    {
      *data = malloc (sizeof (struct crypt_data));
      if (!*data)
        return 0;
      *size = sizeof (struct crypt_data);
    }
  if (*size < 0 || (size_t)*size < sizeof (struct crypt_data))
    {
      void *rdata = realloc (*data, sizeof (struct crypt_data));
      if (!rdata)
        return 0;
      *data = rdata;
      *size = sizeof (struct crypt_data);
    }

  struct crypt_data *p = *data;
  make_failure_token (setting, p->output, sizeof p->output);
  do_crypt (phrase, setting, p);
  return p->output[0] == '*' ? 0 : p->output;
}

/* Common code for all of the crypt() variants.

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

#include <errno.h>

/* The internal storage area within struct crypt_data is used as
   follows.  We don't know what alignment the algorithm modules will
   need for their scratch data, so give it the maximum natural
   alignment.  Note that the C11 alignas() specifier can't be applied
   directly to a struct type, but it can be applied to the first field
   of a struct, which effectively forces alignment of the entire
   struct, since the first field must always have offset 0.  */
struct crypt_internal
{
  char alignas (max_align_t) alg_specific[ALG_SPECIFIC_SIZE];
};

static_assert(sizeof (struct crypt_internal) + alignof (struct crypt_internal)
              <= CRYPT_DATA_INTERNAL_SIZE,
              "crypt_data.internal is too small for crypt_internal");

/* struct crypt_data is allocated by application code and contains
   only char-typed fields, so its 'internal' field may not be
   sufficiently aligned.  */
static inline struct crypt_internal *
get_internal (struct crypt_data *data)
{
  uintptr_t internalp = (uintptr_t) data->internal;
  const uintptr_t align = alignof (struct crypt_internal);
  internalp = (internalp + align - 1) & ~(align - 1);
  return (struct crypt_internal *)internalp;
}

void
do_crypt (const char *phrase, const char *setting, struct crypt_data *data)
{
  if (!phrase || !setting)
    {
      errno = EINVAL;
      return;
    }
  /* Do these strlen() calls before reading prefixes of either
     'phrase' or 'setting', so we get a predictable crash if they are
     not valid strings.  */
  size_t phr_size = strlen (phrase);
  size_t set_size = strlen (setting);
  if (phr_size >= CRYPT_MAX_PASSPHRASE_SIZE)
    {
      errno = ERANGE;
      return;
    }
  const struct hashfn *h = get_hashfn (setting);
  if (!h)
    {
      /* Unrecognized hash algorithm */
      errno = EINVAL;
      return;
    }

  struct crypt_internal *cint = get_internal (data);
  h->crypt (phrase, phr_size, setting, set_size,
            (unsigned char *)data->output, sizeof data->output,
            cint->alg_specific, sizeof cint->alg_specific);

  secure_erase (data->internal, sizeof data->internal);
}

/* Dispatch to individual hashing methods.

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
#include <stdlib.h>

/* The internal storage area within struct crypt_data is used as
   follows.  We don't know what alignment the algorithm modules will
   need for their scratch data, so give it the maximum natural
   alignment.  Note that the C11 alignas() specifier can't be applied
   directly to a struct type, but it can be applied to the first field
   of a struct, which effectively forces alignment of the entire
   struct, since the first field must always have offset 0.  */
struct crypt_internal
{
  char alignas (alignof (max_align_t)) alg_specific[ALG_SPECIFIC_SIZE];
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

typedef void (*crypt_fn) (const char *phrase, size_t phr_size,
                          const char *setting, size_t set_size,
                          uint8_t *output, size_t out_size,
                          void *scratch, size_t scr_size);

typedef void (*gensalt_fn) (unsigned long count,
                            const uint8_t *rbytes, size_t nrbytes,
                            uint8_t *output, size_t output_size);

struct hashfn
{
  const char *prefix;
  size_t plen;
  crypt_fn crypt;
  gensalt_fn gensalt;
  /* The type of this field is unsigned char because get_random_bytes
     can produce no more than 256 bytes per call.  */
  unsigned char nrbytes;
};

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

static const struct hashfn *
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

int
dispatch_checksalt (const char *setting)
{
  const struct hashfn *h = get_hashfn (setting);
  if (h)
    return CRYPT_SALT_OK;
  else
    return CRYPT_SALT_INVALID;
}

void
dispatch_crypt (const char *phrase, size_t phr_size,
                const char *setting, size_t set_size,
                struct crypt_data *data)
{
  const struct hashfn *h = get_hashfn (setting);
  if (!h)
    {
      errno = EINVAL;
      return;
    }
  struct crypt_internal *ci = get_internal (data);
  h->crypt (phrase, phr_size,
            setting, set_size,
            (unsigned char *)data->output, sizeof data->output,
            ci->alg_specific, sizeof ci->alg_specific);
  explicit_bzero (ci->alg_specific, sizeof ci->alg_specific);
}

void
dispatch_gensalt (const char *prefix, unsigned long cost,
                  const char *rbytes, int nrbytes, char *output,
                  int output_size)
{
  const struct hashfn *h = get_hashfn (prefix);
  if (!h || nrbytes < 0)
    {
      errno = EINVAL;
      return;
    }

  if (rbytes)
    {
      h->gensalt (cost,
                  (const unsigned char *)rbytes, (size_t)nrbytes,
                  (unsigned char *)output, (size_t)output_size);
    }
  else
    {
      unsigned char internal_rbytes[UCHAR_MAX];
      if (!get_random_bytes (internal_rbytes, h->nrbytes))
        return;

      h->gensalt(cost,
                 internal_rbytes, h->nrbytes,
                 (unsigned char *)output, (size_t)output_size);
      explicit_bzero (internal_rbytes, h->nrbytes);
    }
}

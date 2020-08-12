/* High-level libcrypt interfaces.

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
#include "xcrypt.h"

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
  /* The type of this field is unsigned char to ensure that it cannot
     be set larger than the size of an internal buffer in crypt_gensalt_rn.  */
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

static void
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

  XCRYPT_SECURE_MEMSET (data->internal, sizeof data->internal);
}

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

  struct crypt_data *p = data;
  do_crypt (phrase, setting, p);
  return p->output[0] == '*' ? 0 : p->output;
}
SYMVER_crypt_rn;
#endif

#if INCLUDE_crypt_ra
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
SYMVER_crypt_ra;
#endif

#if INCLUDE_crypt_r
char *
crypt_r (const char *phrase, const char *setting, struct crypt_data *data)
{
  make_failure_token (setting, data->output, sizeof data->output);
  do_crypt (phrase, setting, data);
#if ENABLE_FAILURE_TOKENS
  return data->output;
#else
  return data->output[0] == '*' ? 0 : data->output;
#endif
}
SYMVER_crypt_r;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt_r && INCLUDE_xcrypt_r
strong_alias (crypt_r, xcrypt_r);
SYMVER_xcrypt_r;
#endif

#if INCLUDE_crypt_gensalt_rn
char *
crypt_gensalt_rn (const char *prefix, unsigned long count,
                  const char *rbytes, int nrbytes, char *output,
                  int output_size)
{
  make_failure_token ("", output, output_size);

  /* Individual gensalt functions will check for adequate space for
     their own breed of setting, but the shortest possible one is
     three bytes (DES two-character salt + NUL terminator) and we
     also want to rule out negative numbers early.  */
  if (output_size < 3)
    {
      errno = ERANGE;
      return 0;
    }

  /* If the prefix is 0, that means to use the current best default.
     Note that this is different from the behavior when the prefix is
     "", which selects DES.  HASH_ALGORITHM_DEFAULT is not defined when
     the current default algorithm was disabled at configure time.  */
  if (!prefix)
    {
#if defined HASH_ALGORITHM_DEFAULT
      prefix = HASH_ALGORITHM_DEFAULT;
#else
      errno = EINVAL;
      return 0;
#endif
    }

  const struct hashfn *h = get_hashfn (prefix);
  if (!h)
    {
      errno = EINVAL;
      return 0;
    }

  char internal_rbytes[UCHAR_MAX];
  /* typeof (internal_nrbytes) == typeof (h->nrbytes).  */
  unsigned char internal_nrbytes = 0;

  /* If rbytes is 0, read random bytes from the operating system if
     possible.  */
  if (!rbytes)
    {
      if (!get_random_bytes (internal_rbytes, h->nrbytes))
        return 0;

      rbytes = internal_rbytes;
      nrbytes = internal_nrbytes = h->nrbytes;
    }

  h->gensalt (count,
              (const unsigned char *)rbytes, (size_t)nrbytes,
              (unsigned char *)output, (size_t)output_size);

  if (internal_nrbytes)
    XCRYPT_SECURE_MEMSET (internal_rbytes, internal_nrbytes);

  return output[0] == '*' ? 0 : output;
}
SYMVER_crypt_gensalt_rn;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt_gensalt_rn && INCLUDE_crypt_gensalt_r
strong_alias (crypt_gensalt_rn, crypt_gensalt_r);
SYMVER_crypt_gensalt_r;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt_gensalt_rn && INCLUDE_xcrypt_gensalt_r
strong_alias (crypt_gensalt_rn, xcrypt_gensalt_r);
SYMVER_xcrypt_gensalt_r;
#endif

#if INCLUDE_crypt_gensalt_ra
char *
crypt_gensalt_ra (const char *prefix, unsigned long count,
                  const char *rbytes, int nrbytes)
{
  char *output = malloc (CRYPT_GENSALT_OUTPUT_SIZE);
  if (!output)
    return 0;

  char *result = crypt_gensalt_rn (prefix, count, rbytes, nrbytes, output,
                                   CRYPT_GENSALT_OUTPUT_SIZE);
  if (result == 0)
    free (output);
  return result;
}
SYMVER_crypt_gensalt_ra;
#endif

#if INCLUDE_crypt_checksalt
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
SYMVER_crypt_checksalt;
#endif

#if INCLUDE_crypt_preferred_method
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

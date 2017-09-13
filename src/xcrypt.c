/* Copyright (C) 2007, 2008, 2009 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@thkukuk.de>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xcrypt-private.h"
#include "crypt-obsolete.h"

#define CRYPT_OUTPUT_SIZE               (7 + 22 + 31 + 1)
#define CRYPT_GENSALT_OUTPUT_SIZE       (7 + 22 + 1)

/*
 * For use by the old, non-reentrant routines
 * (crypt/encrypt/setkey)
 */
struct crypt_data _ufc_foobar;

struct hashfn
{
  const char *prefix;
  char *(*crypt) (const char *key, const char *salt, char *data, size_t size);
  char *(*gensalt) (unsigned long count,
                    const char *input, int input_size,
                    char *output, int output_size);
};

/* This table should always begin with the algorithm that should be used
   for new encryptions.  */
static const struct hashfn tagged_hashes[] = {
  /* bcrypt */
  { "$2a$", _xcrypt_crypt_bcrypt_rn, _xcrypt_gensalt_bcrypt_a_rn },
  { "$2b$", _xcrypt_crypt_bcrypt_rn, _xcrypt_gensalt_bcrypt_b_rn },
  { "$2x$", _xcrypt_crypt_bcrypt_rn, _xcrypt_gensalt_bcrypt_x_rn },
  { "$2y$", _xcrypt_crypt_bcrypt_rn, _xcrypt_gensalt_bcrypt_y_rn },

  /* legacy hashes */
  { "$1$", _xcrypt_crypt_md5_rn, _xcrypt_gensalt_md5_rn },
  { "$5$", _xcrypt_crypt_sha256_rn, _xcrypt_gensalt_sha256_rn },
  { "$6$", _xcrypt_crypt_sha512_rn, _xcrypt_gensalt_sha512_rn },
  { 0, 0, 0 }
};

/* BSD-style extended DES hash */
static const struct hashfn bsdi_extended_hash = {
  "_", _xcrypt_crypt_extended_rn, _xcrypt_gensalt_extended_rn
};

/* bigcrypt-style extended DES hash */
static const struct hashfn traditional_hash = {
  "", _xcrypt_crypt_traditional_rn, _xcrypt_gensalt_traditional_rn
};

static int
is_des_salt_char (char c)
{
  return ((c >= 'a' && c <= 'z') ||
          (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') ||
          c == '.' || c == '/');
}

static const struct hashfn *
_xcrypt_get_hash (const char *salt)
{
  if (salt[0] == '$')
    {
      const struct hashfn *h;
      for (h = tagged_hashes; h->prefix; h++)
        if (!strncmp (salt, h->prefix, strlen (h->prefix)))
          return h;
      return NULL;
    }
  else if (salt[0] == '_')
    return &bsdi_extended_hash;
  else if (salt[0] == '\0' ||
           (is_des_salt_char (salt[0]) && is_des_salt_char (salt[1])))
    return &traditional_hash;
  else
    return NULL;
}

static char *
_xcrypt_retval_magic (char *retval, const char *salt, char *output)
{
  if (retval)
    return retval;

  output[0] = '*';
  output[1] = '0';
  output[2] = '\0';

  if (salt[0] == '*' && salt[1] == '0')
    output[1] = '1';

  return output;
}

static char *
_xcrypt_rn (const char *key, const char *salt, char *data, size_t size)
{
  const struct hashfn *h = _xcrypt_get_hash (salt);
  if (!h)
    {
      /* Unrecognized hash algorithm */
      errno = ERANGE;
      return NULL;
    }
  return h->crypt (key, salt, data, size);
}

char *
crypt_rn (const char *key, const char *salt, void *data, int size)
{
  return _xcrypt_retval_magic (_xcrypt_rn (key, salt, data, size),
                               salt, data);
}

char *
crypt_ra (const char *key, const char *salt, void **data, int *size)
{
  if (!*data)
    {
      *data = malloc (sizeof (struct crypt_data));
      if (!*data)
        return NULL;
      *size = sizeof (struct crypt_data);
    }
  return crypt_rn (key, salt, *data, *size);
}

char *
crypt_r (const char *key, const char *salt, struct crypt_data *data)
{
  return crypt_rn (key, salt, (char *) data, sizeof (*data));
}

char *
crypt (const char *key, const char *salt)
{
  return crypt_rn (key, salt, (char *) &_ufc_foobar, sizeof (_ufc_foobar));
}

char *
crypt_gensalt_rn (const char *prefix, unsigned long count,
                  const char *input, int size, char *output,
                  int output_size)
{
  const struct hashfn *h;

  /* This may be supported on some platforms in the future */
  if (!input)
    {
      errno = EINVAL;
      return NULL;
    }

  h = _xcrypt_get_hash (prefix);
  if (!h)
    {
      errno = EINVAL;
      return NULL;
    }
  return h->gensalt (count, input, size, output, output_size);
}

char *
crypt_gensalt_r (const char *prefix, unsigned long count,
                 const char *input, int size, char *output, int output_size)
{
  return crypt_gensalt_rn (prefix, count, input, size, output, output_size);
}

char *
crypt_gensalt_ra (const char *prefix, unsigned long count,
                  const char *input, int size)
{
  char *output = malloc (CRYPT_GENSALT_OUTPUT_SIZE);
  if (!output)
    return output;

  return crypt_gensalt_rn (prefix, count, input, size, output,
                           CRYPT_GENSALT_OUTPUT_SIZE);
}

char *
crypt_gensalt (const char *prefix, unsigned long count,
               const char *input, int size)
{
  static char output[CRYPT_GENSALT_OUTPUT_SIZE];

  return crypt_gensalt_rn (prefix, count,
                           input, size, output, sizeof (output));
}

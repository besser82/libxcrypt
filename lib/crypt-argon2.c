/**
 * ISC License
 * 
 * © 2022 Mattias Andrée <maandree@kth.se>
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "crypt-port.h"
#include "crypt-hashes.h"

#if INCLUDE_argon2_d || INCLUDE_argon2_i || INCLUDE_argon2_id || INCLUDE_argon2_ds

#include <libar2simplified.h>
#include <libar2.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define REMOVE_CONST(X)\
  (*(void **)(void *)&(X))

#define DEFAULT_TAG_SIZE 32
#define DEFAULT_VERSION LIBAR2_ARGON2_VERSION_13
#define DEFAULT_M_COST 4096
#define DEFAULT_LANES 1

static void
crypt_argon2_rn (const char *prefix,
                 const char *phrase, size_t phr_size,
                 const char *setting, size_t set_size,
                 uint8_t *output, size_t o_size,
                 void *scratch, size_t s_size)
{
  struct libar2_argon2_parameters *params = NULL;
  struct libar2_context ctx;
  char *settings_end;
  int free_scratch = 0;
  size_t required_s_size;
  size_t required_o_size;
  size_t offset;

  if (strncmp (setting, prefix, strlen (prefix)) || !set_size)
    goto einval;

  params = libar2simplified_decode (setting, NULL, &settings_end, NULL);
  if (!params)
    goto fail;
  if (*settings_end)
    goto einval;
  if (!params->hashlen)
    params->hashlen = DEFAULT_TAG_SIZE;

  required_o_size = libar2_encode_params (NULL, params) - 1;
  required_o_size += libar2_encode_base64 (NULL, NULL, params->hashlen);
  if (o_size < required_o_size)
    goto einval;

  libar2simplified_init_context (&ctx);
  ctx.autoerase_message = 0; /* allows `phrase` to be read-only */
  required_s_size = libar2_hash_buf_size (params);
  if (required_s_size > s_size)
    {
      if (free_scratch)
        free (scratch);
      scratch = malloc (required_s_size);
      if (!scratch)
        {
          errno = ENOMEM;
          goto fail;
        }
      free_scratch = 1;
    }

  if (libar2_hash (scratch, REMOVE_CONST (phrase), phr_size, params, &ctx))
    goto fail;

  offset = libar2_encode_params ((char *) output, params) - 1;
  libar2_encode_base64 ((char *) &output[offset], scratch, params->hashlen);

  free(params);
  errno = 0;
  return;

 einval:
  errno = EINVAL;
 fail:
  free (params);
  if (free_scratch)
    {
      free (scratch);
    }
  return;
}

static void
gensalt_argon2_rn (enum libar2_argon2_type type,
                   unsigned long count,
                   const uint8_t *rbytes, size_t nrbytes,
                   uint8_t *output, size_t o_size)
{
  struct libar2_argon2_parameters params;

  if (count >> 31 > 1)
    goto erange;

  memset (&params, 0, sizeof (params));
  params.type = type;
  params.version = DEFAULT_VERSION;
  params.t_cost = (uint_least32_t) count;
  params.m_cost = DEFAULT_M_COST;
  params.lanes = DEFAULT_LANES;
  params.salt = REMOVE_CONST (rbytes); /* libar2 does not use `const` because
                                        * it has an option to erase the salt */
  params.saltlen = nrbytes;
  params.hashlen = DEFAULT_TAG_SIZE;
  if (libar2_validate_params (&params, NULL) != LIBAR2_OK)
    goto erange;

  if (o_size < libar2_encode_params (NULL, &params))
    goto erange;

  if (libar2_encode_params ((char *) output, &params) > o_size)
    abort();

  return;

 erange:
  errno = ERANGE;
  return;  
}

#if INCLUDE_argon2_d
void
crypt_argon2_d_rn (const char *phrase, size_t phr_size,
                   const char *setting, size_t set_size,
                   uint8_t *output, size_t o_size,
                   void *scratch, size_t s_size)
{
  crypt_argon2_rn ("$argon2d$", phrase, phr_size, setting,
                   set_size, output, o_size, scratch, s_size);
}
#endif /* INCLUDE_argon2_d */

#if INCLUDE_argon2_i
void
crypt_argon2_i_rn (const char *phrase, size_t phr_size,
                   const char *setting, size_t set_size,
                   uint8_t *output, size_t o_size,
                   void *scratch, size_t s_size)
{
  crypt_argon2_rn ("$argon2i$", phrase, phr_size, setting,
                   set_size, output, o_size, scratch, s_size);
}
#endif /* INCLUDE_argon2_i */

#if INCLUDE_argon2_id
void
crypt_argon2_id_rn (const char *phrase, size_t phr_size,
                    const char *setting, size_t set_size,
                    uint8_t *output, size_t o_size,
                    void *scratch, size_t s_size)
{
  crypt_argon2_rn ("$argon2id$", phrase, phr_size, setting,
                   set_size, output, o_size, scratch, s_size);
}
#endif /* INCLUDE_argon2_id */

#if INCLUDE_argon2_ds
void
crypt_argon2_ds_rn (const char *phrase, size_t phr_size,
                    const char *setting, size_t set_size,
                    uint8_t *output, size_t o_size,
                    void *scratch, size_t s_size)
{
  crypt_argon2_rn ("$argon2ds$", phrase, phr_size, setting,
                   set_size, output, o_size, scratch, s_size);
}
#endif /* INCLUDE_argon2_ds */

#if INCLUDE_argon2_d
void
gensalt_argon2_d_rn (unsigned long count,
                     const uint8_t *rbytes, size_t nrbytes,
                     uint8_t *output, size_t o_size)
{
  gensalt_argon2_rn(LIBAR2_ARGON2D, count, rbytes, nrbytes, output, o_size);
}
#endif /* INCLUDE_argon2_d */

#if INCLUDE_argon2_i
void
gensalt_argon2_i_rn (unsigned long count,
                     const uint8_t *rbytes, size_t nrbytes,
                     uint8_t *output, size_t o_size)
{
  gensalt_argon2_rn(LIBAR2_ARGON2I, count, rbytes, nrbytes, output, o_size);
}
#endif /* INCLUDE_argon2_i */

#if INCLUDE_argon2_id
void
gensalt_argon2_id_rn (unsigned long count,
                      const uint8_t *rbytes, size_t nrbytes,
                      uint8_t *output, size_t o_size)
{
  gensalt_argon2_rn(LIBAR2_ARGON2ID, count, rbytes, nrbytes, output, o_size);
}
#endif /* INCLUDE_argon2_ds */

#if INCLUDE_argon2_ds
void
gensalt_argon2_ds_rn (unsigned long count,
                      const uint8_t *rbytes, size_t nrbytes,
                      uint8_t *output, size_t o_size)
{
  gensalt_argon2_rn(LIBAR2_ARGON2DS, count, rbytes, nrbytes, output, o_size);
}
#endif /* INCLUDE_argon2_ds */

#endif /* INCLUDE_argon2_d || INCLUDE_argon2_i || INCLUDE_argon2_id || INCLUDE_argon2_ds */

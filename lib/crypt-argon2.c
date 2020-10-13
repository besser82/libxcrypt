/*
 * Copyright (C) 2020 Samanta Navarro <ferivoz@riseup.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "crypt-port.h"
#include "crypt-hashes.h"

#include <errno.h>

#if INCLUDE_argon2_d || INCLUDE_argon2_i || INCLUDE_argon2_id

#include <argon2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alg-argon2-encoding.h"

static uint32_t
get_value(const char *nptr, const char *arg, char **endptr, const char end)
{
  unsigned long val;

  if (strncmp (nptr, arg, strlen (arg)))
    return 0;
  nptr += strlen (arg);
  if (!(*nptr >= '1' && *nptr <= '9'))
    return 0;
  val = strtoul (nptr, endptr, 10);
  if (val == 0 || val > UINT32_MAX || **endptr != end)
    return 0;
  return (uint32_t) val;
}

#define GET_VALUE(dst, arg, end) \
{ \
        dst = get_value (s, arg, &q, end); \
        if (dst == 0) \
          { \
            errno = EINVAL; \
            return; \
          } \
        s = q + 1; \
}

static void
crypt_argon2_rn (const argon2_type hash_type,
                 const char *phrase, size_t phr_size,
                 const char *setting, size_t set_size,
                 uint8_t *output, size_t o_size,
                 void *scratch, size_t s_size)
{
  char *buf = scratch, *q;
  const char *d, *s = setting, *type;
  uint8_t *salt;
  size_t pos, salt_len;
  uint32_t v, m, t, p;

  if (s_size == 0 || s_size < phr_size || set_size < 26)
    {
      errno = EINVAL;
      return;
    }

  switch (hash_type) {
  case Argon2_d:
    type = "$argon2d$";
    break;
  case Argon2_i:
    type = "$argon2i$";
    break;
  case Argon2_id:
    type = "$argon2id$";
    break;
  default:
    type = NULL;
    break;
  }

  if (type == NULL)
    {
      errno = EINVAL;
      return;
    }

  /* Setting for a different hash algorithm. */
  if (strncmp (s, type, strlen(type)))
    {
      errno = EINVAL;
      return;
    }
  s += strlen(type);

  GET_VALUE(v, "v=", '$');
  GET_VALUE(m, "m=", ',');
  GET_VALUE(t, "t=", ',');
  GET_VALUE(p, "p=", '$');

  strncpy (buf, s, s_size);
  buf[s_size - 1] = '\0';
  pos = strcspn (buf, "$");
  buf[pos] = '\0';
  salt = (uint8_t *) buf + pos + 1;
  salt_len = s_size - pos - 1;
  if ((d = argon2_decode64 (salt, &salt_len, buf)) == NULL ||
      (*d != '\0' && *d != '$'))
    {
      errno = EINVAL;
      return;
    }

  /* Parameters are invalid. */
  if (argon2_hash (t, m, p, phrase, phr_size, salt, salt_len,
      NULL, 32, (char *) output, o_size, hash_type, v) != ARGON2_OK)
    {
      errno = EINVAL;
      return;
    }
}

#if INCLUDE_argon2_d
void
crypt_argon2_d_rn (const char *phrase, size_t phr_size,
                   const char *setting, size_t set_size,
                   uint8_t *output, size_t o_size,
                   void *scratch, size_t s_size)
{
  crypt_argon2_rn (Argon2_d, phrase, phr_size, setting, set_size,
                   output, o_size, scratch, s_size);
}
#endif /* INCLUDE_argon2_d */

#if INCLUDE_argon2_i
void
crypt_argon2_i_rn (const char *phrase, size_t phr_size,
                   const char *setting, size_t set_size,
                   uint8_t *output, size_t o_size,
                   void *scratch, size_t s_size)
{
  crypt_argon2_rn (Argon2_i, phrase, phr_size, setting, set_size,
                   output, o_size, scratch, s_size);
}
#endif /* INCLUDE_argon2_i */

#if INCLUDE_argon2_id
void
crypt_argon2_id_rn (const char *phrase, size_t phr_size,
                    const char *setting, size_t set_size,
                    uint8_t *output, size_t o_size,
                    void *scratch, size_t s_size)
{
  crypt_argon2_rn (Argon2_id, phrase, phr_size, setting, set_size,
                   output, o_size, scratch, s_size);
}
#endif /* INCLUDE_argon2_id */

static void
gensalt_argon2_rn (const char *type, unsigned long count,
                   const uint8_t *rbytes, size_t nrbytes,
                   uint8_t *output, size_t o_size)
{
  char buf[87];
  int s;

  if (count < ARGON2_MIN_TIME || count > ARGON2_MAX_TIME ||
      nrbytes < ARGON2_MIN_SALT_LENGTH || nrbytes > ARGON2_MAX_SALT_LENGTH)
    {
      errno = ERANGE;
      return;
    }

  if (argon2_encode64 (buf, sizeof(buf), rbytes, nrbytes) == (size_t) -1)
    {
      errno = ERANGE;
      return;
    }

  s = snprintf ((char *) output, o_size, "$%s$v=%d$m=4096,t=%lu,p=1$%s$",
                type, ARGON2_VERSION_NUMBER, count, buf);
  if (s < 0 || (size_t) s >= o_size)
    {
      errno = ERANGE;
      return;
    }
}

#if INCLUDE_argon2_d
void
gensalt_argon2_d_rn (unsigned long count,
                     const uint8_t *rbytes, size_t nrbytes,
                     uint8_t *output, size_t o_size)
{
  gensalt_argon2_rn("argon2d", count, rbytes, nrbytes, output, o_size);
}
#endif /* INCLUDE_argon2_d */

#if INCLUDE_argon2_i
void
gensalt_argon2_i_rn (unsigned long count,
                     const uint8_t *rbytes, size_t nrbytes,
                     uint8_t *output, size_t o_size)
{
  gensalt_argon2_rn("argon2i", count, rbytes, nrbytes, output, o_size);
}
#endif /* INCLUDE_argon2_i */

#if INCLUDE_argon2_id
void
gensalt_argon2_id_rn (unsigned long count,
                      const uint8_t *rbytes, size_t nrbytes,
                      uint8_t *output, size_t o_size)
{
  gensalt_argon2_rn("argon2id", count, rbytes, nrbytes, output, o_size);
}
#endif /* INCLUDE_argon2_id */

#endif /* INCLUDE_argon2_d || INCLUDE_argon2_i || INCLUDE_argon2_id */

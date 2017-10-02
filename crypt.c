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

#include "crypt-port.h"
#include "crypt-private.h"
#include "crypt-obsolete.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_SWAPCONTEXT
#include <limits.h>
#include <ucontext.h>
#endif

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
#ifdef USE_SWAPCONTEXT
  char inner_stack[16384];
  ucontext_t inner_ctx;
#endif
};

static_assert(sizeof(struct crypt_internal) + alignof(struct crypt_internal)
              <= sizeof(((struct crypt_data){0}).internal),
              "crypt_data.internal is too small for crypt_internal");

/* struct crypt_data is allocated by application code and contains
   only char-typed fields, so its 'internal' field may not be
   sufficiently aligned.  */
static inline struct crypt_internal *
get_internal (struct crypt_data *data)
{
  uintptr_t internalp = (uintptr_t) data->internal;
  uintptr_t align = alignof (struct crypt_internal);
  internalp = (internalp + align - 1) & ~align;
  return (struct crypt_internal *)internalp;
}

typedef uint8_t *(*crypt_fn) (const char *phrase, const char *setting,
                              uint8_t *output, size_t o_size,
                              void *scratch, size_t s_size);

typedef uint8_t *(*gensalt_fn) (unsigned long count,
                                const uint8_t *rbytes, size_t nrbytes,
                                uint8_t *output, size_t output_size);


/* If getcontext, makecontext, and swapcontext are available, we use
   them to force the stack frames and register state for the actual
   hash algorithm to be saved in a place (inside struct crypt_internal)
   where we can erase them after we're done.  Passing arguments into
   the makecontext callback is somewhat awkward; you can call any
   function that takes any number of 'int' arguments and returns
   nothing.  We need to pass a whole bunch of pointers, which don't
   necessarily fit, and we need to get a return value back out.  The
   code below handles only the case where a pointer to a struct fits
   in one 'int', and the case where it fits in two 'int's.  */

#ifdef USE_SWAPCONTEXT
struct crypt_fn_args
{
  crypt_fn cfn;
  const char *phrase;
  const char *setting;
  uint8_t *output;
  size_t o_size;
  void *scratch;
  size_t s_size;
  uint8_t *rv;
};

#if UINTPTR_MAX == UINT_MAX
static_assert (sizeof (uintptr_t) == sizeof (int),
  "UINTPTR_MAX matches UINT_MAX but sizeof (uintptr_t) != sizeof (int)");

static_assert (sizeof (struct crypt_fn_args *) == sizeof (int),
  "UINTPTR_MAX matches UINT_MAX but sizeof (crypt_fn_args *) != sizeof (int)");

#define SWIZZLE_PTR(ptr) 1, ((int)(uintptr_t)(ptr))
#define UNSWIZZLE_PTR(val) ((struct crypt_fn_args *)(uintptr_t)(val))
#define CCF1_ARGDECL int arg
#define CCF1_ARGS arg
#define CCF1_UNSWIZZLE_ARGS UNSWIZZLE_PTR (CCF1_ARGS)

#elif UINTPTR_MAX == ULONG_MAX
static_assert (sizeof (uintptr_t) == 2*sizeof (int),
  "UINTPTR_MAX matches ULONG_MAX but sizeof (uintptr_t) != 2*sizeof (int)");

static_assert (sizeof (struct crypt_fn_args *) == 2*sizeof (int),
"UINTPTR_MAX matches ULONG_MAX but sizeof (crypt_fn_args *) != 2*sizeof (int)");

#define SWIZZLE_PTR(ptr) 2,                                             \
    (int)((((uintptr_t)ptr) >> (sizeof(int)*CHAR_BIT)) & UINT_MAX),     \
    (int)((((uintptr_t)ptr) >> 0)                      & UINT_MAX)

#define UNSWIZZLE_PTR(a, b)                                             \
  ((struct crypt_fn_args *)                                             \
   ((((uintptr_t)(unsigned int)a) << (sizeof(int)*CHAR_BIT)) |          \
    (((uintptr_t)(unsigned int)b) << 0)))

#define UNSWIZZLE_PTR_(ARGS) UNSWIZZLE_PTR (ARGS)

#define CCF1_ARGDECL int a1, int a2
#define CCF1_ARGS a1, a2
#define CCF1_UNSWIZZLE_ARGS UNSWIZZLE_PTR_ (CCF1_ARGS)

#else
#error "Don't know how to swizzle pointers for makecontext with this ABI"
#endif

static void
call_crypt_fn_1 (CCF1_ARGDECL)
{
  struct crypt_fn_args *a = CCF1_UNSWIZZLE_ARGS;
  a->rv = a->cfn (a->phrase, a->setting, a->output, a->o_size,
                  a->scratch, a->s_size);
}
#endif /* USE_SWAPCONTEXT */

static char *
call_crypt_fn (crypt_fn cfn,
               const char *phrase, const char *setting,
               struct crypt_data *data)
{
  struct crypt_internal *cint = get_internal (data);
  unsigned char *rv;

#ifdef USE_SWAPCONTEXT
  ucontext_t outer_ctx;
  struct crypt_fn_args a;

  if (getcontext (&cint->inner_ctx))
    return 0;

  a.cfn     = cfn;
  a.phrase  = phrase;
  a.setting = setting;
  a.output  = (unsigned char *)data->output;
  a.o_size  = sizeof data->output;
  a.scratch = cint->alg_specific;
  a.s_size  = sizeof cint->alg_specific;
  a.rv      = 0;

  cint->inner_ctx.uc_stack.ss_sp   = cint->inner_stack;
  cint->inner_ctx.uc_stack.ss_size = sizeof cint->inner_stack;
  cint->inner_ctx.uc_link = &outer_ctx;
  makecontext (&cint->inner_ctx,
               (void (*)(void))call_crypt_fn_1,
               SWIZZLE_PTR (&a));

  if (swapcontext (&outer_ctx, &cint->inner_ctx))
    return 0;

  rv = a.rv;

#else
  rv = cfn (phrase, setting,
            (unsigned char *)data->output, sizeof data->output,
            cint->alg_specific, sizeof cint->alg_specific);
#endif

  memset (data->internal, 0, sizeof data->internal);
  return (char *)rv;
}

struct hashfn
{
  const char *prefix;
  crypt_fn crypt;
  gensalt_fn gensalt;
};

/* This table should always begin with the algorithm that should be used
   for new encryptions.  */
static const struct hashfn tagged_hashes[] = {
  /* bcrypt */
  { "$2a$", crypt_bcrypt_rn, gensalt_bcrypt_a_rn },
  { "$2b$", crypt_bcrypt_rn, gensalt_bcrypt_b_rn },
  { "$2x$", crypt_bcrypt_rn, gensalt_bcrypt_x_rn },
  { "$2y$", crypt_bcrypt_rn, gensalt_bcrypt_y_rn },

  /* legacy hashes */
#if ENABLE_WEAK_HASHES
  { "$1$", crypt_md5_rn, gensalt_md5_rn },
#endif
  { "$5$", crypt_sha256_rn, gensalt_sha256_rn },
  { "$6$", crypt_sha512_rn, gensalt_sha512_rn },
  { 0, 0, 0 }
};

#if ENABLE_WEAK_HASHES
/* BSD-style extended DES */
static const struct hashfn bsdi_extended_hash = {
  "_", crypt_des_xbsd_rn, gensalt_des_xbsd_rn
};

/* Traditional DES or bigcrypt-style extended DES */
static const struct hashfn traditional_hash = {
  "", crypt_des_trd_or_big_rn, gensalt_des_trd_rn
};

static int
is_des_salt_char (char c)
{
  return ((c >= 'a' && c <= 'z') ||
          (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') ||
          c == '.' || c == '/');
}
#endif /* ENABLE_WEAK_HASHES */

static const struct hashfn *
get_hashfn (const char *setting)
{
  if (setting[0] == '$')
    {
      const struct hashfn *h;
      for (h = tagged_hashes; h->prefix; h++)
        if (!strncmp (setting, h->prefix, strlen (h->prefix)))
          return h;
      return NULL;
    }
#if ENABLE_WEAK_HASHES
  else if (setting[0] == '_')
    return &bsdi_extended_hash;
  else if (setting[0] == '\0' ||
           (is_des_salt_char (setting[0]) && is_des_salt_char (setting[1])))
    return &traditional_hash;
#endif
  else
    return NULL;
}

/* For historical reasons, crypt and crypt_r are not expected ever
   to return NULL.  This function generates a "failure token" in the
   output buffer, which is guaranteed not to be equal to any valid
   password hash, or to the setting(+hash) string; thus, a subsequent
   blind attempt to authenticate someone by comparing the output to
   a previously recorded hash string will fail, even if that string
   is itself one of these "failure tokens".

   crypt_gensalt_rn also uses this technique, for extra defensiveness
   in case someone doesn't bother checking the return value.  */

static void
make_failure_token (const char *setting, char *output, int size)
{
  if (size >= 3)
    {
      output[0] = '*';
      output[1] = '0';
      output[2] = '\0';

      if (setting[0] == '*' && setting[1] == '0')
        output[1] = '1';
    }

  /* If there's not enough space for the full failure token, do the
     best we can.  */
  else if (size == 2)
    {
      output[0] = '*';
      output[1] = '\0';
    }
  else if (size == 1)
    {
      output[0] = '\0';
    }
}

static char *
do_crypt_rn (const char *phrase, const char *setting, void *data, int size)
{
  if (size < 0 || (size_t)size < sizeof (struct crypt_data))
    {
      errno = ERANGE;
      return NULL;
    }
  const struct hashfn *h = get_hashfn (setting);
  if (!h)
    {
      /* Unrecognized hash algorithm */
      errno = EINVAL;
      return NULL;
    }
  return call_crypt_fn (h->crypt, phrase, setting, data);
}

static char *
do_crypt_ra (const char *phrase, const char *setting, void **data, int *size)
{
  const struct hashfn *h = get_hashfn (setting);
  if (!h)
    {
      /* Unrecognized hash algorithm */
      errno = EINVAL;
      return NULL;
    }

  if (!*data)
    {
      *data = malloc (sizeof (struct crypt_data));
      if (!*data)
        return NULL;
      *size = sizeof (struct crypt_data);
    }

  if (*size <= 0)
    {
      errno = ERANGE;
      return NULL;
    }

  return call_crypt_fn (h->crypt, phrase, setting, *data);
}

#if INCLUDE_crypt_rn
char *
crypt_rn (const char *phrase, const char *setting, void *data, int size)
{
  char *retval = do_crypt_rn (phrase, setting, data, size);
  if (!retval)
    make_failure_token (setting, data, size);
  return retval;
}
SYMVER_crypt_rn;
#endif

#if INCLUDE_crypt_ra
char *
crypt_ra (const char *phrase, const char *setting, void **data, int *size)
{
  char *retval = do_crypt_ra (phrase, setting, data, size);
  if (!retval)
    make_failure_token (setting, *data, *size);
  return retval;
}
SYMVER_crypt_ra;
#endif

#if INCLUDE_crypt_r
char *
crypt_r (const char *phrase, const char *setting, struct crypt_data *data)
{
  char *retval = crypt_rn (phrase, setting, (char *) data, sizeof (*data));
  if (!retval)
    return (char *)data; /* return the failure token */
  return retval;
}
SYMVER_crypt_r;
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
      return NULL;
    }

  /* Empty rbytes may be supported on some platforms in the future.
     Individual gensalt functions will check for sufficient random bits
     for their own breed of setting, but the shortest possible one has
     64**2 = 4096 possibilitiesm, which requires two bytes of input.  */
  if (!rbytes || nrbytes < 2)
    {
      errno = EINVAL;
      return NULL;
    }

  const struct hashfn *h = get_hashfn (prefix);
  if (!h)
    {
      errno = EINVAL;
      return NULL;
    }

  return (char *)h->gensalt (count,
                             (const unsigned char *)rbytes, (size_t)nrbytes,
                             (unsigned char *)output, (size_t)output_size);
}
SYMVER_crypt_gensalt_rn;
#endif

#if INCLUDE_crypt_gensalt_ra
char *
crypt_gensalt_ra (const char *prefix, unsigned long count,
                  const char *rbytes, int nrbytes)
{
  char *output = malloc (CRYPT_GENSALT_OUTPUT_SIZE);
  if (!output)
    return output;

  return crypt_gensalt_rn (prefix, count, rbytes, nrbytes, output,
                           CRYPT_GENSALT_OUTPUT_SIZE);
}
SYMVER_crypt_gensalt_ra;
#endif

#if INCLUDE_crypt_gensalt
char *
crypt_gensalt (const char *prefix, unsigned long count,
               const char *rbytes, int nrbytes)
{
  static char output[CRYPT_GENSALT_OUTPUT_SIZE];

  return crypt_gensalt_rn (prefix, count,
                           rbytes, nrbytes, output, sizeof (output));
}
SYMVER_crypt_gensalt;
#endif

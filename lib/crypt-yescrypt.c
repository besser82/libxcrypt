/* Copyright (C) 2018 vt@altlinux.org
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
#include "alg-yescrypt.h"

#include <errno.h>

#if INCLUDE_yescrypt || INCLUDE_scrypt

/* For use in scratch space by crypt_yescrypt_rn().  */
typedef struct
{
  yescrypt_local_t local;
  uint8_t outbuf[CRYPT_OUTPUT_SIZE];
  uint8_t *retval;
} crypt_yescrypt_internal_t;

static_assert (sizeof (crypt_yescrypt_internal_t) <= ALG_SPECIFIC_SIZE,
               "ALG_SPECIFIC_SIZE is too small for YESCRYPT.");

void
crypt_yescrypt_rn (const char *phrase, size_t phr_size,
                   const char *setting, size_t set_size,
                   uint8_t *output, size_t o_size,
                   void *scratch, size_t s_size)
{
#if !INCLUDE_scrypt

  /* If scrypt is disabled fail when called with its prefix.  */
  if (!strncmp (setting, "$7$", 3))
    {
      errno = EINVAL;
      return;
    }

#endif /* !INCLUDE_scrypt */

#if !INCLUDE_yescrypt

  /* If yescrypt is disabled fail when called with its prefix.  */
  if (!strncmp (setting, "$y$", 3))
    {
      errno = EINVAL;
      return;
    }

#endif /* !INCLUDE_yescrypt */

  if (o_size < set_size + 1 + 43 + 1 ||
      CRYPT_OUTPUT_SIZE < set_size + 1 + 43 + 1 ||
      s_size < sizeof (crypt_yescrypt_internal_t))
    {
      errno = ERANGE;
      return;
    }

  crypt_yescrypt_internal_t *intbuf = scratch;

  if (yescrypt_init_local (&intbuf->local))
    return;

  intbuf->retval = yescrypt_r (NULL, &intbuf->local,
                               (const uint8_t *)phrase, phr_size,
                               (const uint8_t *)setting, NULL,
                               intbuf->outbuf, o_size);

  if (!intbuf->retval)
    errno = EINVAL;

  if (yescrypt_free_local (&intbuf->local) || !intbuf->retval)
    return;

  XCRYPT_STRCPY_OR_ABORT (output, o_size, intbuf->outbuf);
  return;
}

#endif /* INCLUDE_yescrypt || INCLUDE_scrypt */

#if INCLUDE_gost_yescrypt || INCLUDE_yescrypt

/*
 * As OUTPUT is initialized with a failure token before gensalt_yescrypt_rn
 * is called, in case of an error we could just set an appropriate errno
 * and return.
 * Since O_SIZE is guaranteed to be greater than 2, we may fill OUTPUT
 * with a short failure token when need.
 */
void
gensalt_yescrypt_rn (unsigned long count,
                     const uint8_t *rbytes, size_t nrbytes,
                     uint8_t *output, size_t o_size)
{
  if (o_size < 3 + 8 * 6 + BASE64_LEN (nrbytes) + 1 ||
      CRYPT_GENSALT_OUTPUT_SIZE < 3 + 8 * 6 + BASE64_LEN (nrbytes) + 1)
    {
      errno = ERANGE;
      return;
    }

  if (count > 11 || nrbytes < 16)
    {
      errno = EINVAL;
      return;
    }

  /* Temporary buffer for operation.  The buffer is guaranteed to be
     large enough to hold the maximum size of the generated salt.  */
  uint8_t outbuf[CRYPT_GENSALT_OUTPUT_SIZE];

  yescrypt_params_t params =
  {
    .flags = YESCRYPT_DEFAULTS,
    .p = 1,
  };

  /* Valid cost parameters are from 1 to 11.  The default is 5.
     These are used to set yescrypt's 'N' and 'r' parameters as
     follows:
     N (block count) is specified in units of r (block size,
     adjustable in steps of 128 bytes).

     128 bytes * r = size of each memory block

     128 bytes * r * N = total amount of memory used for hashing
                         in N blocks of r * 128 bytes.

     The author of yescrypt recommends in the documentation to use
     r=8 (a block size of 1 KiB) for total sizes of 2 MiB and less,
     and r=32 (a block size of 4KiB) above that.
     This has to do with the typical per-core last-level cache sizes
     of current CPUs.  */

  if (count == 0)
    count = 5;

  if (count < 3)
    {
      params.r = 8;                   // N in 1KiB
      params.N = 1ULL << (count + 9); // 1 -> 1024, 2 -> 2048
    }
  else
    {
      params.r = 32;                  // N in 4KiB
      params.N = 1ULL << (count + 7); // 3 -> 1024, 4 -> 2048, ... 11 -> 262144
    }

  if (!yescrypt_encode_params_r (&params, rbytes, nrbytes, outbuf, o_size))
    {
      errno = ERANGE;
      return;
    }

  XCRYPT_STRCPY_OR_ABORT (output, o_size, outbuf);
  return;
}

#endif /* INCLUDE_gost_yescrypt || INCLUDE_yescrypt */

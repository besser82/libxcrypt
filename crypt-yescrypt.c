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
#include "crypt-private.h"
#include "byteorder.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "alg-yescrypt.h"

#if INCLUDE_yescrypt

/*
 * As OUTPUT is initialized with a failure token before gensalt_yescrypt_rn
 * is called, in case of an error we could just set an appropriate errno
 * and return.
 * Since O_SIZE is guaranteed to be greater than 2, we may fill OUTPUT
 * with a short failure token when need.
 */
void
gensalt_yescrypt_rn(unsigned long count,
                    const uint8_t *rbytes, size_t nrbytes,
                    uint8_t *output, size_t o_size)
{
  if (count > 11)
    {
      errno = EINVAL;
      return;
    }

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

  if (!yescrypt_encode_params_r(&params, rbytes, nrbytes, output, o_size))
    {
      /*
       * As the output could have already been written,
       * overwrite it with a short failure token.
       */
      output[0] = '*';
      output[1] = '\0';
      errno = ERANGE;
      return;
    }
}

void
crypt_yescrypt_rn(const char *phrase, size_t phr_size,
                  const char *setting, size_t ARG_UNUSED (set_size),
                  uint8_t *output, size_t o_size,
                  ARG_UNUSED(void *scratch), ARG_UNUSED(size_t s_size))
{
  yescrypt_local_t local;
  uint8_t *retval;

  if (o_size < 3)
    {
      errno = ERANGE;
      return;
    }
  if (yescrypt_init_local(&local))
    {
      errno = ENOMEM;
      return;
    }
  retval = yescrypt_r(NULL, &local,
                      (const uint8_t *)phrase, phr_size,
                      (const uint8_t *)setting, NULL,
                      output, o_size);
  if (yescrypt_free_local(&local) ||
      !retval)
    {
      /*
       * As the output could have already been written,
       * overwrite it with a failure token.
       */
      output[0] = '*';
      output[1] = '0';
      output[2] = '\0';
      errno = EINVAL;
    }
}

#endif /* INCLUDE_yescrypt */

/* Copyright (C) 2018 vt@altlinux.org
 * Copyright (C) 2018 Björn Esser besser82@fedoraproject.org
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

#if INCLUDE_gost_yescrypt

#define YESCRYPT_INTERNAL
#include "alg-yescrypt.h"
#undef YESCRYPT_INTERNAL

#include "alg-gost3411-2012-hmac.h"

#include <errno.h>

/* upper level hmac for tests */
#ifndef outer_gost_hmac256
#define outer_gost_hmac256 gost_hmac256
#endif

/* For use in scratch space by crypt_gost_yescrypt_rn().  */
typedef struct
{
  yescrypt_local_t local;
  gost_hmac_256_t gostbuf;
  uint8_t outbuf[CRYPT_OUTPUT_SIZE];
  uint8_t gsetting[CRYPT_OUTPUT_SIZE];
  uint8_t hk[32], interm[32], y[32];
  uint8_t *retval;
} crypt_gost_yescrypt_internal_t;

static_assert (sizeof (crypt_gost_yescrypt_internal_t) <= ALG_SPECIFIC_SIZE,
               "ALG_SPECIFIC_SIZE is too small for GOST-YESCRYPT.");

/*
 * As OUTPUT is initialized with a failure token before gensalt_yescrypt_rn
 * is called, in case of an error we could just set an appropriate errno
 * and return.
 */
void
gensalt_gost_yescrypt_rn (unsigned long count,
                          const uint8_t *rbytes, size_t nrbytes,
                          uint8_t *output, size_t o_size)
{
  if (o_size < 4 + 8 * 6 + BASE64_LEN (nrbytes) + 1 ||
      CRYPT_GENSALT_OUTPUT_SIZE < 4 + 8 * 6 + BASE64_LEN (nrbytes) + 1)
    {
      errno = ERANGE;
      return;
    }

  /* We pass 'o_size - 1' to gensalt, because we need to shift
           the prefix by 1 char to insert the gost marker.  */
  gensalt_yescrypt_rn (count, rbytes, nrbytes, output, o_size - 1);

  /* Check for failures.  */
  if (output[0] == '*')
    return;

  /* Shift output one byte further.  */
  memmove (output + 1, output, strlen ((const char *) output) + 1);

  /* Insert the gost marker.  */
  output[1] = 'g';
}

void
crypt_gost_yescrypt_rn (const char *phrase, size_t phr_size,
                        const char *setting, size_t set_size,
                        uint8_t *output, size_t o_size,
                        void *scratch, size_t s_size)
{
  if (o_size < set_size + 1 + 43 + 1 ||
      CRYPT_OUTPUT_SIZE < set_size + 1 + 43 + 1 ||
      s_size < sizeof (crypt_gost_yescrypt_internal_t))
    {
      errno = ERANGE;
      return;
    }

  /* Fail when called with wrong prefix.  */
  if (strncmp (setting, "$gy$", 4))
    {
      errno = EINVAL;
      return;
    }

  crypt_gost_yescrypt_internal_t *intbuf = scratch;

  if (yescrypt_init_local (&intbuf->local))
    return;

  /* convert gost setting to yescrypt setting */
  intbuf->gsetting[0] = '$';
  intbuf->gsetting[1] = 'y';
  intbuf->gsetting[2] = '$';
  XCRYPT_STRCPY_OR_ABORT (&intbuf->gsetting[3], set_size - 3, setting + 4);

  intbuf->retval = yescrypt_r (NULL, &intbuf->local,
                               (const uint8_t *) phrase, phr_size,
                               intbuf->gsetting, NULL,
                               intbuf->outbuf + 1, o_size - 1);

  if (!intbuf->retval)
    errno = EINVAL;

  if (yescrypt_free_local (&intbuf->local) || !intbuf->retval)
    return;

  intbuf->outbuf[0] = '$';
  intbuf->outbuf[1] = 'g';

  /* extract yescrypt output from "$y$param$salt$output" */
  char *hptr = strchr ((const char *) intbuf->retval + 3, '$');
  if (!hptr)
    {
      errno = EINVAL;
      return;
    }
  hptr = strchr (hptr + 1, '$');
  if (!hptr)
    {
      errno = EINVAL;
      return;
    }
  hptr++; /* start of output */

  /* decode yescrypt output into its raw 256-bit form */
  size_t ylen = sizeof (intbuf->y);
  if (!decode64 (intbuf->y, &ylen, (uint8_t *) hptr, strlen (hptr)) ||
      ylen != sizeof (intbuf->y))
    {
      errno = EINVAL;
      return;
    }

  /*
   * HMAC_GOSTR3411_2012_256(
   *   HMAC_GOSTR3411_2012_256(GOST2012_256(K), S),
   *   yescrypt(K, S)
   * )
   * yescrypt output is used in place of message,
   * thus, its crypto properties are superseded by GOST.
   * Password is always hashed for inner hmac to avoid
   * collisions between hashed and unhashed passwords.
   */
  gost_hash256 ((const uint8_t *) phrase, phr_size, intbuf->hk, &intbuf->gostbuf.ctx);
  gost_hmac256 (intbuf->hk, sizeof (intbuf->hk),
                (const uint8_t *) setting,
                (size_t) ((uint8_t *) hptr - intbuf->retval),
                intbuf->interm, &intbuf->gostbuf);
  outer_gost_hmac256 (intbuf->interm, sizeof (intbuf->interm),
                      intbuf->y, sizeof (intbuf->y), intbuf->y, &intbuf->gostbuf);

  encode64 ((uint8_t *) hptr, o_size - (size_t) ((uint8_t *) hptr - intbuf->retval),
            intbuf->y, sizeof (intbuf->y));

  XCRYPT_STRCPY_OR_ABORT (output, o_size, intbuf->outbuf);
  return;
}

#endif /* INCLUDE_gost_yescrypt */

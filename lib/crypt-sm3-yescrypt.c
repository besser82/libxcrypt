/* Copyright (C) 2024 Björn Esser besser82@fedoraproject.org
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

#if INCLUDE_sm3_yescrypt

#define YESCRYPT_INTERNAL
#include "alg-yescrypt.h"
#undef YESCRYPT_INTERNAL

#include "alg-sm3-hmac.h"

#include <errno.h>

/* upper level hmac for tests */
#ifndef outer_sm3_hmac
#define outer_sm3_hmac sm3_hmac
#endif

/* For use in scratch space by crypt_gost_yescrypt_rn().  */
typedef struct
{
  sm3_hmac_ctx_t sm3buf;
  yescrypt_local_t local;
  uint8_t outbuf[CRYPT_OUTPUT_SIZE],
          sm3setting[CRYPT_OUTPUT_SIZE],
          hk[SM3_DIGEST_SIZE],
          interm[SM3_DIGEST_SIZE],
          y[SM3_DIGEST_SIZE],
          *retval;
} crypt_sm3_yescrypt_internal_t;

static_assert (sizeof (crypt_sm3_yescrypt_internal_t) <= ALG_SPECIFIC_SIZE,
               "ALG_SPECIFIC_SIZE is too small for SM3-YESCRYPT.");

/*
 * As OUTPUT is initialized with a failure token before gensalt_yescrypt_rn
 * is called, in case of an error we could just set an appropriate errno
 * and return.
 */
void
gensalt_sm3_yescrypt_rn (unsigned long count,
                         const uint8_t *rbytes, size_t nrbytes,
                         uint8_t *output, size_t o_size)
{
  /* Up to 512 bits (64 bytes) of entropy for computing the salt portion
     of the MCF-setting are supported.  */
  nrbytes = (nrbytes > 64 ? 64 : nrbytes);

  if (o_size < 6 + 8 * 6 + BASE64_LEN (nrbytes) + 1 ||
      CRYPT_GENSALT_OUTPUT_SIZE < 6 + 8 * 6 + BASE64_LEN (nrbytes) + 1)
    {
      errno = ERANGE;
      return;
    }

  /* We pass 'o_size - 3' to gensalt, because we need to shift
           the prefix by 3 chars to insert the sm3 marker.  */
  gensalt_yescrypt_rn (count, rbytes, nrbytes, output, o_size - 3);

  /* Check for failures.  */
  if (output[0] == '*')
    return;

  /* Shift output three bytes further.  */
  memmove (output + 3, output, strlen ((const char *) output) + 1);

  /* Insert the sm3 marker.  */
  output[1] = 's';
  output[2] = 'm';
  output[3] = '3';
}

void
crypt_sm3_yescrypt_rn (const char *phrase, size_t phr_size,
                       const char *setting, size_t set_size,
                       uint8_t *output, size_t o_size,
                       void *scratch, size_t s_size)
{
  if (o_size < set_size + 1 + 43 + 1 ||
      CRYPT_OUTPUT_SIZE < set_size + 1 + 43 + 1 ||
      s_size < sizeof (crypt_sm3_yescrypt_internal_t))
    {
      errno = ERANGE;
      return;
    }

  /* Fail when called with wrong prefix.  */
  if (strncmp (setting, "$sm3y$", 6))
    {
      errno = EINVAL;
      return;
    }

  crypt_sm3_yescrypt_internal_t *intbuf = scratch;

  if (yescrypt_init_local (&intbuf->local))
    return;

  /* convert gost setting to yescrypt setting */
  intbuf->sm3setting[0] = '$';
  intbuf->sm3setting[1] = 'y';
  intbuf->sm3setting[2] = '$';
  strcpy_or_abort (&intbuf->sm3setting[3], set_size - 3, setting + 6);

  intbuf->retval = yescrypt_r (NULL, &intbuf->local,
                               (const uint8_t *) phrase, phr_size,
                               intbuf->sm3setting, NULL,
                               intbuf->outbuf + 3, o_size - 3);

  if (!intbuf->retval)
    errno = EINVAL;

  if (yescrypt_free_local (&intbuf->local) || !intbuf->retval)
    return;

  intbuf->outbuf[0] = '$';
  intbuf->outbuf[1] = 's';
  intbuf->outbuf[2] = 'm';
  intbuf->outbuf[3] = '3';

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
   * SM3_HMAC(
   *   SM3_HMAC(SM3(K), S),
   *   yescrypt(K, S)
   * )
   * yescrypt output is used in place of message,
   * thus, its crypto properties are superseded by SM3.
   * Password is always hashed for inner hmac to avoid
   * collisions between hashed and unhashed passwords.
   */
  sm3_hash ((const uint8_t *) phrase, phr_size, intbuf->hk,
            &intbuf->sm3buf.sm3_ctx);
  sm3_hmac (intbuf->hk, sizeof (intbuf->hk),
                (const uint8_t *) setting,
                (size_t) ((uint8_t *) hptr - intbuf->retval),
                intbuf->interm, &intbuf->sm3buf);
  outer_sm3_hmac (intbuf->interm, sizeof (intbuf->interm),
                  intbuf->y, sizeof (intbuf->y), intbuf->y,
                  &intbuf->sm3buf);

  encode64 ((uint8_t *) hptr, o_size - (size_t) ((uint8_t *) hptr - intbuf->retval),
            intbuf->y, sizeof (intbuf->y));

  strcpy_or_abort (output, o_size, intbuf->outbuf);
  return;
}

#endif /* INCLUDE_sm3_yescrypt */

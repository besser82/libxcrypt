/* Copyright (C) 2013 Alexander Peslyak
 * Copyright (C) 2018 Björn Esser <besser82@fedoraproject.org>
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

#if INCLUDE_scrypt

static int
check_salt_char (char ch)
{
  if (ch > 'z')
    return 0;
  if (ch >= 'a')
    return 1;
  if (ch > 'Z')
    return 0;
  if (ch >= 'A')
    return 1;
  if (ch > '9')
    return 0;
  if (ch >= '.' || ch == '$')
    return 1;
  return 0;
}

static int
verify_salt (const char *setting, size_t set_size)
{
  for (size_t i = 3 + 1 + 5 * 2; i < set_size; i++)
    {
      if (!check_salt_char (setting[i]))
        {
          /* Salt is terminated properly.
             Following characters don't matter.  */
          if (setting[i - 1] == '$')
            break;

          /* Salt has an invalid character.  */
          return 0;
        }
    }
  return 1;
}

static uint8_t *
encode64_uint32 (uint8_t * dst, ssize_t dstlen,
                 uint32_t src, uint32_t srcbits)
{
  uint32_t bit;

  for (bit = 0; bit < srcbits; bit += 6)
    {
      if (dstlen < 1)
        {
          errno = ERANGE;
          return NULL;
        }
      *dst++ = ascii64[src & 0x3f];
      dstlen--;
      src >>= 6;
    }

  *dst = '\0';
  return dst;
}

static uint8_t *
encode64 (uint8_t * dst, ssize_t dstlen,
          const uint8_t * src, size_t srclen)
{
  size_t i;

  for (i = 0; i < srclen; )
    {
      uint8_t * dnext;
      uint32_t value = 0, bits = 0;
      do
        {
          value |= (uint32_t) src[i++] << bits;
          bits += 8;
        }
      while (bits < 24 && i < srclen);
      dnext = encode64_uint32 (dst, dstlen, value, bits);
      if (!dnext)
        {
          errno = ERANGE;
          return NULL;
        }
      dstlen -= (dnext - dst);
      dst = dnext;
    }

  *dst = '\0';
  return dst;
}

static uint32_t
N2log2 (uint64_t N)
{
  uint32_t N_log2;

  if (N < 2)
    return 0;

  N_log2 = 2;
  while (N >> N_log2 != 0)
    N_log2++;
  N_log2--;

  if (N >> N_log2 != 1)
    return 0;

  return N_log2;
}

/*
 * Wrapper for crypt_yescrypt_rn to compute the hash.
 */
void
crypt_scrypt_rn (const char *phrase, size_t phr_size,
                 const char *setting, size_t set_size,
                 uint8_t *output, size_t o_size,
                 void *scratch, size_t s_size)
{
  if (o_size < set_size + 1 + 43 + 1 ||
      CRYPT_OUTPUT_SIZE < set_size + 1 + 43 + 1)
    {
      errno = ERANGE;
      return;
    }

  /* Setting is invalid.  */
  if (strncmp (setting, "$7$", 3) || !verify_salt (setting, set_size))
    {
      errno = EINVAL;
      return;
    }

  crypt_yescrypt_rn (phrase, phr_size, setting, set_size,
                     output, o_size, scratch, s_size);
  return;
}

void
gensalt_scrypt_rn (unsigned long count,
                   const uint8_t *rbytes, size_t nrbytes,
                   uint8_t *output, size_t o_size)
{
  if (o_size < 3 + 1 + 5 * 2 + BASE64_LEN (nrbytes) + 1 ||
      CRYPT_GENSALT_OUTPUT_SIZE < 3 + 1 + 5 * 2 + BASE64_LEN (nrbytes) + 1)
    {
      errno = ERANGE;
      return;
    }

  if ((count > 0 && count < 6) || count > 11 || nrbytes < 16)
    {
      errno = EINVAL;
      return;
    }

  /* Temporary buffer for operation.  The buffer is guaranteed to be
     large enough to hold the maximum size of the generated salt.  */
  uint8_t outbuf[CRYPT_GENSALT_OUTPUT_SIZE];
  uint8_t *out_p = outbuf + 4;
  ssize_t out_s = CRYPT_GENSALT_OUTPUT_SIZE - (out_p - outbuf);

  /* Valid cost parameters are from 6 to 11.  The default is 7.
     Any cost parameter below 6 is not to be considered strong
     enough anymore, because using less than 32 MiBytes of RAM
     when computing a hash is even weaker than bcrypt ($2y$).
     These are used to set scrypt's 'N' and 'r' parameters as
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
    count = 7;

  uint32_t p = 1;
  uint32_t r = 32;
  uint64_t N = 1ULL << (count + 7); // 6 -> 8192, 7 -> 16384, ... 11 -> 262144

  if (out_s > (ssize_t) BASE64_LEN (30))
    {
      outbuf[0] = '$';
      outbuf[1] = '7';
      outbuf[2] = '$';
      outbuf[3] = ascii64[N2log2 (N)];

      out_p = encode64_uint32 (out_p, out_s, r, 30);
      out_s -= (out_p - outbuf);
    }

  if (out_p && out_s > (ssize_t) BASE64_LEN (30))
    {
      out_p = encode64_uint32 (out_p, out_s, p, 30);
      out_s -= (out_p - outbuf);
    }

  if (out_p && out_s > (ssize_t) BASE64_LEN (nrbytes))
    {
      out_p = encode64 (out_p, out_s, rbytes, nrbytes);
    }

  if (out_p)
    {
      XCRYPT_STRCPY_OR_ABORT (output, o_size, outbuf);
    }

  return;
}

#endif /* INCLUDE_scrypt */

/* Copyright (C) 2018-2019 Björn Esser <besser82@fedoraproject.org>
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

/* Simple commonly used helper functions.  */

#include "crypt-port.h"

const unsigned char ascii64[65] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/* 0000000000111111111122222222223333333333444444444455555555556666 */
/* 0123456789012345678901234567890123456789012345678901234567890123 */

/* Provide a safe way to copy strings with the guarantee src,
   including its terminating '\0', will fit d_size bytes.
   The trailing bytes of d_size will be filled with '\0'.
   dst and src must not be NULL.  Returns strlen (src).  */
size_t
_crypt_strcpy_or_abort (void *dst, const size_t d_size,
                        const void *src)
{
  assert (dst != NULL);
  assert (src != NULL);
  const size_t s_size = strlen ((const char *) src);
  assert (d_size >= s_size + 1);
  memcpy (dst, src, s_size);
  XCRYPT_SECURE_MEMSET ((char *) dst + s_size, d_size - s_size);
  return s_size;
}

#if INCLUDE_XCRYPT_SECURE_MEMSET
/* The best hope we without any other implementation to
   securely wipe data stored in memory.  */
void
_crypt_secure_memset (void *s, size_t len)
{
  volatile unsigned char *c = s;
  while (len--)
    *c++ = 0x00;
}
#endif

/* Fill the output buffer with a failure token.  */
void
make_failure_token (const char *setting, char *output, int size)
{
  if (size >= 3)
    {
      output[0] = '*';
      output[1] = '0';
      output[2] = '\0';

      if (setting && setting[0] == '*' && setting[1] == '0')
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

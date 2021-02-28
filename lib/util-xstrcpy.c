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

/* Provide a safe way to copy strings with the guarantee src,
   including its terminating '\0', will fit d_size bytes.
   The trailing bytes of d_size will be filled with '\0'.
   dst and src must not be NULL.  Returns strlen (src).  */
size_t
strcpy_or_abort (void *dst, size_t d_size, const void *src)
{
  assert (dst != NULL);
  assert (src != NULL);
  size_t s_size = strlen ((const char *)src);
  assert (d_size >= s_size + 1);

  memcpy (dst, src, s_size);
  memset (((char *)dst) + s_size, 0, d_size - s_size);
  return s_size;
}

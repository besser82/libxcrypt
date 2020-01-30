/* Copyright (C) 2018-2020 Björn Esser, Zack Weinberg
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
#include "crypt-internal.h"

/* Copy the C string 'src' into the buffer 'dst', which is of length
   'd_size'.  Fill all of the trailing space in 'dst' with NULs.
   If either dst or src is NULL, or if src (including its terminator)
   does not fit into dst, crash the program.
   Returns strlen (src).
   Arguments are void * rather than char * to allow some callers to
   pass char * while others pass unsigned char *.  */
size_t
strcpy_or_abort (void *dst, size_t d_size, const void *src)
{
  assert (dst != NULL);
  assert (src != NULL);

  const char *s = src;
  char *d = dst;

  size_t s_size = strlen (s);
  assert (d_size >= s_size + 1);

  memcpy (d, s, s_size);
  memset (d + s_size, 0x00, d_size - s_size);
  return s_size;
}

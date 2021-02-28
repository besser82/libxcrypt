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

#include "crypt-port.h"

#if INCLUDE_explicit_bzero
/* As long as this function is defined in a translation unit all by
   itself, and we aren't doing LTO, it would be enough for it to just
   call memset.  While compiling _this_ translation unit, the compiler
   has no information about what the callers do with the buffer, so it
   cannot eliminate the memset.  While compiling code that _calls_
   this function, the compiler doesn't know what it does, so it cannot
   eliminate the call (if it has special knowledge of a function with
   this name, we would hope that it knows _not_ to optimize it out!)

   However, in anticipation of doing LTO on this library one day, we
   add two more defensive measures, when we know how: the function is
   marked no-inline, and there is a no-op assembly insert immediately
   after the memset call, declared to read the memory that the memset
   writes.  */

#if defined __GNUC__ && __GNUC__ >= 3
/* This construct is known to work with GCC and *probably* also works
   with clang.  It uses a VLA, which is normally forbidden in
   libxcrypt, but not in a way that can cause arbitrarily large stack
   allocations (which is *why* they are forbidden); disable the error
   for this file only.  */

# define OBSERVE_MEM(s, len) \
  asm volatile ("" : : "m" (*(const char (*)[len]) s))

#  if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
#   pragma GCC diagnostic ignored "-Wvla"
#  elif defined __clang_major__ && __clang_major__ >= 4
#   pragma clang diagnostic ignored "-Wvla"
#  endif

#else
# error "Don't know how to observe memory access"
#endif

NO_INLINE void
explicit_bzero (void *s, size_t len)
{
  memset (s, 0, len);
  OBSERVE_MEM (s, len);
}
#endif

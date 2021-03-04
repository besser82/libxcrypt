/* Obsolete DES symmetric cipher interfaces (encrypt, setkey).

   Copyright (c) 1994-2021 David Burren, Geoffrey M. Rehmet,
   Mark R V Murray, Zack Weinberg, and Björn Esser.
   Originally part of FreeSec (libcrypt for NetBSD).

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   3. Neither the name of the author nor the names of other contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND ANY
   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
   THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  */

#include "crypt-port.h"
#include "crypt-obsolete.h"

/* A program that uses encrypt necessarily uses setkey as well,
   and vice versa.  Therefore, we bend the usual 'one entry point per
   file' principle and have both encrypt and setkey in this file,
   and the cpp conditionals do not allow for only one of them being
   included in the library.  */

#if INCLUDE_encrypt

#if ENABLE_OBSOLETE_API_ENOSYS
#define encrypt_ctx 0
#else
/* Use a separate crypt_data object from the main library's crypt().  */
static struct crypt_data encrypt_ctx_;
#define encrypt_ctx (&encrypt_ctx_)
#endif

void
setkey (const char *key)
{
  setkey_r (key, encrypt_ctx);
}
SYMVER_setkey;

void
encrypt (char *block, int edflag)
{
  encrypt_r (block, edflag, encrypt_ctx);
}
SYMVER_encrypt;

#endif

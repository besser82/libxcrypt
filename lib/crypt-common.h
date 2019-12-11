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

/* Simple commonly used helper constants.  */

#ifndef _CRYPT_COMMON_H
#define _CRYPT_COMMON_H 1

/* The base-64 encoding table used by most hashing methods.
   (bcrypt uses a slightly different encoding.)  Size 65
   because it's used as a C string in a few places.  */
extern const unsigned char ascii64[65];

/* Same table gets used with other names in various places.  */
#define b64t   ((const char *) ascii64)
#define itoa64 ascii64

/* For historical reasons, crypt and crypt_r are not expected ever
   to return 0, and for internal implementation reasons (see
   call_crypt_fn, in crypt.c), it is simpler if the individual
   algorithms' crypt and gensalt functions return nothing.

   This function generates a "failure token" in the output buffer,
   which is guaranteed not to be equal to any valid password hash or
   setting string, nor to the setting(+hash) string that was passed
   in; thus, a subsequent blind attempt to authenticate someone by
   comparing the output to a previously recorded hash string will
   fail, even if that string is itself one of these "failure tokens".

   We always call this function on the output buffer as the first
   step.  If the individual algorithm's crypt or gensalt function
   succeeds, it overwrites the failure token with real output;
   otherwise the token is left intact, and the API functions that
   _can_ return 0 on error notice it.  */
extern void
make_failure_token (const char *setting, char *output, int size);

#endif /* crypt-common.h */

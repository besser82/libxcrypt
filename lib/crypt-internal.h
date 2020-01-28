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

/* Internal helper functions and constants.  */

#ifndef _CRYPT_COMMON_H
#define _CRYPT_COMMON_H 1

/* Provide a guaranteed way to erase sensitive memory at the best we
   can, given the possibilities of the system.  */
#if defined HAVE_MEMSET_S
/* Will never be optimized out.  */
#define XCRYPT_SECURE_MEMSET(s, len) \
  memset_s (s, len, 0x00, len)
#elif defined HAVE_EXPLICIT_BZERO
/* explicit_bzero() should give us enough guarantees.  */
#define XCRYPT_SECURE_MEMSET(s, len) \
  explicit_bzero(s, len)
#elif defined HAVE_EXPLICIT_MEMSET
/* Same guarantee goes for explicit_memset().  */
#define XCRYPT_SECURE_MEMSET(s, len) \
  explicit_memset (s, 0x00, len)
#else
/* The best hope we have in this case.  */
#define INCLUDE_XCRYPT_SECURE_MEMSET 1
extern void secure_memset (void *, size_t);
#define XCRYPT_SECURE_MEMSET(s, len) \
  secure_memset (s, len)
#endif
#ifndef INCLUDE_XCRYPT_SECURE_MEMSET
#define INCLUDE_XCRYPT_SECURE_MEMSET 0
#endif

/* Alternative name used by some code.  */
#define insecure_memzero XCRYPT_SECURE_MEMSET

/* Provide a safe way to copy strings with the guarantee src,
   including its terminating '\0', will fit d_size bytes.
   The trailing bytes of d_size will be filled with '\0'.
   dst and src must not be NULL.  Returns strlen (src).  */
extern size_t strcpy_or_abort (void *, const size_t, const void *);
#define XCRYPT_STRCPY_OR_ABORT(dst, d_size, src) \
  strcpy_or_abort (dst, d_size, src)

/* We need a prototype for fcrypt for some tests.  */
#if ENABLE_OBSOLETE_API
char *fcrypt (const char *key, const char *setting);
#endif

/* Utility functions */
bool get_random_bytes (void *buf, size_t buflen);

extern void gensalt_sha_rn (char tag, size_t maxsalt, unsigned long defcount,
                            unsigned long mincount, unsigned long maxcount,
                            unsigned long count,
                            const uint8_t *rbytes, size_t nrbytes,
                            uint8_t *output, size_t output_size);

extern char *crypt_gensalt_internal (const char *prefix, unsigned long count,
                                     const char *rbytes, int nrbytes,
                                     char *output, int output_size);

typedef void (*crypt_fn) (const char *phrase, size_t phr_size,
                          const char *setting, size_t set_size,
                          uint8_t *output, size_t out_size,
                          void *scratch, size_t scr_size);

typedef void (*gensalt_fn) (unsigned long count,
                            const uint8_t *rbytes, size_t nrbytes,
                            uint8_t *output, size_t output_size);

struct hashfn
{
  const char *prefix;
  size_t plen;
  crypt_fn crypt;
  gensalt_fn gensalt;
  /* The type of this field is unsigned char to ensure that it cannot
     be set larger than the size of an internal buffer in crypt_gensalt_rn.  */
  unsigned char nrbytes;
};

extern const struct hashfn *get_hashfn (const char *setting);

struct crypt_data;
extern void do_crypt (const char *phrase, const char *setting,
                      struct crypt_data *data);

/* Calculate the size of a base64 encoding of N bytes:
   6 bits per output byte, rounded up.  */
#define BASE64_LEN(bytes) ((((bytes) * 8) + 5) / 6)

/* The "scratch" area passed to each of the individual hash functions is
   this big.  */
#define ALG_SPECIFIC_SIZE 8192

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

#endif /* crypt-internal.h */

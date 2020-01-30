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

#ifndef _CRYPT_INTERNAL_H
#define _CRYPT_INTERNAL_H 1

/* Erase sensitive data stored in memory.  The compiler will not
   optimize out a call to secure_erase(), even if no *conforming* C
   program could tell whether it had been called.  The C library may
   provide this functionality; if not, we have a fallback definition
   in fn-secure-erase.c.  */
#if defined HAVE_MEMSET_S
#define secure_erase(s, len)        memset_s (s, len, 0x00, len)
#elif defined HAVE_EXPLICIT_BZERO
#define secure_erase(s, len)        explicit_bzero (s, len)
#elif defined HAVE_EXPLICIT_MEMSET
#define secure_erase(s, len)        explicit_memset (s, 0x00, len)
#else
extern void secure_erase (void *s, size_t len) attribute_noinline;
#endif

/* Alternative name for secure_erase used by some code.  */
#define insecure_memzero secure_erase

/* Copy the C string 'src' into the buffer 'dst', which is of length
   'd_size'.  Fill all of the trailing space in 'dst' with NULs.
   If either dst or src is NULL, or if src (including its terminator)
   does not fit into dst, crash the program.
   Returns strlen (src).
   Arguments are void * rather than char * to allow some callers to
   pass char * while others pass unsigned char *.  */
extern size_t strcpy_or_abort (void *dst, size_t d_size, const void *src);

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

/* For historical reasons, crypt and crypt_r are not expected ever to
   return 0, and for internal historical reasons, the individual
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

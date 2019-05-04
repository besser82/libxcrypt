/*
 * Copyright (c) 2004, Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "crypt-port.h"
#include "alg-hmac-sha1.h"
#include "byteorder.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#if INCLUDE_sha1crypt

/*
 * The default iterations - should take >0s on a fast CPU
 * but not be insane for a slow CPU.
 */
#ifndef CRYPT_SHA1_ITERATIONS
# define CRYPT_SHA1_ITERATIONS 262144
#endif
/*
 * Support a reasonably? long salt.
 */
#ifndef CRYPT_SHA1_SALT_LENGTH
# define CRYPT_SHA1_SALT_LENGTH 64
#endif

#define SHA1_SIZE 20         /* size of raw SHA1 digest, 160 bits */
#define SHA1_OUTPUT_SIZE 28  /* size of base64-ed output string */

static inline void
to64 (uint8_t *s, unsigned long v, int n)
{
  while (--n >= 0)
    {
      *s++ = itoa64[v & 0x3f];
      v >>= 6;
    }
}

/*
 * UNIX password using hmac_sha1
 * This is PBKDF1 from RFC 2898, but using hmac_sha1.
 *
 * The format of the encrypted password is:
 * $<tag>$<iterations>$<salt>$<digest>
 *
 * where:
 * 	<tag>		is "sha1"
 *	<iterations>	is an unsigned int identifying how many rounds
 * 			have been applied to <digest>.  The number
 * 			should vary slightly for each password to make
 * 			it harder to generate a dictionary of
 * 			pre-computed hashes.  See gensalt_sha1crypt_rn.
 * 	<salt>		up to 64 bytes of random data, 8 bytes is
 * 			currently considered more than enough.
 *	<digest>	the hashed password.
 *
 * NOTE:
 * To be FIPS 140 compliant, the password which is used as a hmac key,
 * should be between 10 and 20 characters to provide at least 80bits
 * strength, and avoid the need to hash it before using as the
 * hmac key.
 */
void
crypt_sha1crypt_rn (const char *phrase, size_t phr_size,
                    const char *setting, size_t ARG_UNUSED (set_size),
                    uint8_t *output, size_t out_size,
                    void *scratch, size_t scr_size)
{
  static const char *magic = "$sha1$";

  if ((out_size < (strlen (magic) + 2 + 10 + CRYPT_SHA1_SALT_LENGTH +
                   SHA1_OUTPUT_SIZE)) ||
      scr_size < SHA1_SIZE)
    {
      errno = ERANGE;
      return;
    }

  const char *sp;
  uint8_t *ep;
  unsigned long ul;
  size_t sl;
  size_t pl = phr_size;
  int dl;
  unsigned long iterations;
  unsigned long i;
  /* XXX silence -Wpointer-sign (would be nice to fix this some other way) */
  const uint8_t *pwu = (const uint8_t *)phrase;
  uint8_t *hmac_buf = scratch;

  /*
   * Salt format is
   * $<tag>$<iterations>$salt[$]
   */

  /* If the string doesn't starts with the magic prefix, we shouldn't have been called */
  if (strncmp (setting, magic, strlen (magic)))
    {
      errno = EINVAL;
      return;
    }

  setting += strlen (magic);
  /* get the iteration count */
  iterations = (unsigned long)strtoul (setting, (char **)&ep, 10);
  if (*ep != '$')
    {
      errno = EINVAL;
      return;  /* invalid input */
    }
  setting = (char *)ep + 1;  /* skip over the '$' */

  /* The next 1..CRYPT_SHA1_SALT_LENGTH bytes should be itoa64 characters,
     followed by another '$' (or end of string).  */
  sp = setting + strspn (setting, (const char *)itoa64);
  if (sp == setting || (*sp && *sp != '$'))
    {
      errno = EINVAL;
      return;
    }

  sl = (size_t)(sp - setting);

  /*
   * Now get to work...
   * Prime the pump with <salt><magic><iterations>
   */
  dl = snprintf ((char *)output, out_size, "%.*s%s%lu",
                 (int)sl, setting, magic, iterations);
  /*
   * Then hmac using <phrase> as key, and repeat...
   */
  hmac_sha1_process_data ((const unsigned char *)output, (size_t)dl,
                          pwu, pl, hmac_buf);
  for (i = 1; i < iterations; ++i)
    {
      hmac_sha1_process_data (hmac_buf, SHA1_SIZE, pwu, pl, hmac_buf);
    }
  /* Now output... */
  pl = (size_t)snprintf ((char *)output, out_size, "%s%lu$%.*s$",
                         magic, iterations, (int)sl, setting);
  ep = output + pl;

  /* Every 3 bytes of hash gives 24 bits which is 4 base64 chars */
  for (i = 0; i < SHA1_SIZE - 3; i += 3)
    {
      ul = (unsigned long)((hmac_buf[i+0] << 16) |
                           (hmac_buf[i+1] << 8) |
                           hmac_buf[i+2]);
      to64 (ep, ul, 4);
      ep += 4;
    }
  /* Only 2 bytes left, so we pad with byte0 */
  ul = (unsigned long)((hmac_buf[SHA1_SIZE - 2] << 16) |
                       (hmac_buf[SHA1_SIZE - 1] << 8) |
                       hmac_buf[0]);
  to64 (ep, ul, 4);
  ep += 4;
  *ep = '\0';

  /* Don't leave anything around in vm they could use. */
  XCRYPT_SECURE_MEMSET (scratch, scr_size);
}

/* Modified excerpt from:
   http://cvsweb.netbsd.org/bsdweb.cgi/~checkout~/src/lib/libcrypt/pw_gensalt.c */
void
gensalt_sha1crypt_rn (unsigned long count,
                      const uint8_t *rbytes, size_t nrbytes,
                      uint8_t *output, size_t o_size)
{
  static_assert (sizeof (uint32_t) == 4,
                 "space calculations below assume 8-bit bytes");

  /* Make sure we have enough random bytes to use for the salt.
     The format supports using up to 48 random bytes, but 12 is
     enough.  We require another 4 bytes of randomness to perturb
     'count' with.  */
  if (nrbytes < 12 + 4)
    {
      errno = EINVAL;
      return;
    }

  /* Make sure we have enough output space, given the amount of
     randomness available.  $sha1$<10digits>$<(nrbytes-4)*4/3>$ */
  if (o_size < (nrbytes - 4) * 4 / 3 + sizeof "$sha1$$$" + 10)
    {
      errno = ERANGE;
      return;
    }

  /*
   * We treat 'count' as a hint.
   * Make it harder for someone to pre-compute hashes for a
   * dictionary attack by not using the same iteration count for
   * every entry.
   */
  uint32_t rounds, random = le32_to_cpu (rbytes);

  if (count == 0)
    count = CRYPT_SHA1_ITERATIONS;
  if (count < 4)
    count = 4;
  if (count > UINT32_MAX)
    count = UINT32_MAX;
  rounds = (uint32_t) (count - (random % (count / 4)));

  uint32_t encbuf;
  int n = snprintf((char *)output, o_size, "$sha1$%u$", (unsigned int)rounds);
  assert (n >= 1 && (size_t)n + 2 < o_size);

  const uint8_t *r = rbytes + 4;
  const uint8_t *rlim = rbytes + nrbytes;
  uint8_t *o = output + n;
  uint8_t *olim = output + n + CRYPT_SHA1_SALT_LENGTH;
  if (olim + 2 > output + o_size)
    olim = output + o_size - 2;

  for (; r + 3 < rlim && o + 4 < olim; r += 3, o += 4)
    {
      encbuf = ((((uint32_t)r[0]) << 16) |
                (((uint32_t)r[1]) <<  8) |
                (((uint32_t)r[2]) <<  0));
      to64 (o, encbuf, 4);
    }

  o[0] = '$';
  o[1] = '\0';
}

#endif

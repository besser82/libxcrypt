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
#include "crypt-private.h"
#include "alg-hmac-sha1.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

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

#define SHA1_SIZE 20

static const uint8_t itoa64[] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

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
 * This may be called from crypt_sha1 or gensalt.
 *
 * The value returned will be slightly less than <hint> which defaults
 * to 24680.  The goals are that the number of iterations should take
 * non-zero amount of time on a fast cpu while not taking insanely
 * long on a slow cpu.  The current default will take about 5 seconds
 * on a 100MHz sparc, and about 0.04 seconds on a 3GHz i386.
 * The number is varied to frustrate those attempting to generate a
 * dictionary of pre-computed hashes.
 */
static unsigned long
crypt_sha1_iterations (unsigned long hint)
{
  unsigned long random;

  /*
   * We treat CRYPT_SHA1_ITERATIONS as a hint.
   * Make it harder for someone to pre-compute hashes for a
   * dictionary attack by not using the same iteration count for
   * every entry.
   */
  get_random_bytes (&random, sizeof (unsigned long));
  if (hint == 0)
    hint = CRYPT_SHA1_ITERATIONS;
  return hint - (random % (hint / 4));
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
 * 			pre-computed hashes.  See crypt_sha1_iterations.
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
crypt_sha1_rn (const char *phrase, const char *setting,
               uint8_t *output, size_t o_size,
               void *scratch, size_t s_size)
{
  static const char *magic = "$sha1$";

  if ((o_size < (strlen (magic) + 2 + 10 + CRYPT_SHA1_SALT_LENGTH + SHA1_SIZE)) ||
      s_size < SHA1_SIZE)
    {
      errno = ERANGE;
      return;
    }

  const char *sp;
  uint8_t *ep;
  unsigned long ul;
  size_t sl;
  size_t pl;
  char *salt;
  int dl;
  unsigned long iterations;
  unsigned long i;
  /* XXX silence -Wpointer-sign (would be nice to fix this some other way) */
  const uint8_t *pwu = (const uint8_t *)phrase;
  uint8_t *hmac_buf = scratch;

  /*
   * Salt format is
   * $<tag>$<iterations>$salt[$]
   * If it does not start with $ we use our default iterations.
   */

  /* If it starts with the magic string, then skip that */
  if (!strncmp (setting, magic, strlen (magic)))
    {
      setting += strlen (magic);
      /* and get the iteration count */
      iterations = (unsigned long)strtoul (setting, (char **)&ep, 10);
      if (*ep != '$')
        {
          errno = EINVAL;
          return;  /* invalid input */
        }
      setting = (char *)ep + 1;  /* skip over the '$' */
    }
  else
    {
      iterations = (unsigned long)crypt_sha1_iterations (0);
    }

  /* It stops at the next '$', max CRYPT_SHA1_ITERATIONS chars */
  for (sp = setting; *sp && *sp != '$' && sp < (setting + CRYPT_SHA1_ITERATIONS); sp++)
    continue;

  /* Get the length of the actual salt */
  sl = (size_t)(sp - setting);

  salt = malloc (sl + 1);
  strncpy (salt, setting, sl);
  salt[sl] = '\0';

  pl = strlen (phrase);

  /*
   * Now get to work...
   * Prime the pump with <salt><magic><iterations>
   */
  dl = snprintf ((char *)output, o_size, "%s%s%lu",
                 salt, magic, iterations);
  /*
   * Then hmac using <phrase> as key, and repeat...
   */
  hmac_sha1_process_data ((const unsigned char *)output, (size_t)dl, pwu, pl, hmac_buf);
  for (i = 1; i < iterations; ++i)
    {
      hmac_sha1_process_data (hmac_buf, SHA1_SIZE, pwu, pl, hmac_buf);
    }
  /* Now output... */
  pl = (size_t)snprintf ((char *)output, o_size, "%s%lu$%s$",
                         magic, iterations, salt);
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
  XCRYPT_SECURE_MEMSET (scratch, s_size)
}

/* Modified excerpt from:
   http://cvsweb.netbsd.org/bsdweb.cgi/~checkout~/src/lib/libcrypt/pw_gensalt.c */
void
gensalt_sha1_rn (unsigned long count,
                 const uint8_t *rbytes, size_t nrbytes,
                 uint8_t *output, size_t o_size)
{
  /* The salt can be up to 64 bytes, but 32
     is considered enough for now.  */
  const uint8_t saltlen = 16;

  const size_t  enclen  = sizeof (unsigned long)*4/3;

  if ((o_size < (size_t)(6 + CRYPT_SHA1_SALT_LENGTH + 2)) ||
      ((nrbytes*4/3) < saltlen))
    {
      errno = ERANGE;
      return;
    }

  unsigned long c, encbuf;

  unsigned int n = (unsigned int) snprintf((char *)output, o_size, "$sha1$%u$",
                   (unsigned int)crypt_sha1_iterations(count));

  for (c = 0; (c * sizeof (unsigned long)) + sizeof (unsigned long) <= nrbytes &&
       (c * enclen) + enclen <= CRYPT_SHA1_SALT_LENGTH; ++c)
    {
      memcpy (&encbuf, rbytes + (c * enclen), sizeof (unsigned long));
      to64 (output + n + (c * enclen), encbuf, (int)enclen);
    }

  output[n + (c * enclen)]     = '$';
  output[n + (c * enclen) + 1] = '\0';
}

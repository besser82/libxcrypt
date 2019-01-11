/* Copyright (c) 2018 Zack Weinberg.
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
 *
 * This is a clean-room reimplementation of the Sun-MD5 password hash,
 * based on the prose description of the algorithm in the Passlib v1.7.1
 * documentation:
 * https://passlib.readthedocs.io/en/stable/lib/passlib.hash.sun_md5_crypt.html
 */

#include "crypt-port.h"
#include "alg-md5.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#if INCLUDE_sunmd5

#define SUNMD5_PREFIX           "$md5"
#define SUNMD5_PREFIX_LEN       4
#define SUNMD5_SALT_LEN         8
#define SUNMD5_MAX_SETTING_LEN  32 /* $md5,rounds=4294963199$12345678$ */
#define SUNMD5_BARE_OUTPUT_LEN  22 /* not counting the setting or the NUL */
#define SUNMD5_MAX_ROUNDS       (0xFFFFFFFFul)

/* At each round of the algorithm, this string (including the trailing
   NUL) may or may not be included in the input to MD5, depending on a
   pseudorandom coin toss.  It is Hamlet's famous soliloquy from the
   play of the same name, which is in the public domain.  Text from
   <https://www.gutenberg.org/files/1524/old/2ws2610.tex> with double
   blank lines replaced with `\n`.  Note that more recent Project
   Gutenberg editions of _Hamlet_ are punctuated differently.  */
static const char hamlet_quotation[] =
  "To be, or not to be,--that is the question:--\n"
  "Whether 'tis nobler in the mind to suffer\n"
  "The slings and arrows of outrageous fortune\n"
  "Or to take arms against a sea of troubles,\n"
  "And by opposing end them?--To die,--to sleep,--\n"
  "No more; and by a sleep to say we end\n"
  "The heartache, and the thousand natural shocks\n"
  "That flesh is heir to,--'tis a consummation\n"
  "Devoutly to be wish'd. To die,--to sleep;--\n"
  "To sleep! perchance to dream:--ay, there's the rub;\n"
  "For in that sleep of death what dreams may come,\n"
  "When we have shuffled off this mortal coil,\n"
  "Must give us pause: there's the respect\n"
  "That makes calamity of so long life;\n"
  "For who would bear the whips and scorns of time,\n"
  "The oppressor's wrong, the proud man's contumely,\n"
  "The pangs of despis'd love, the law's delay,\n"
  "The insolence of office, and the spurns\n"
  "That patient merit of the unworthy takes,\n"
  "When he himself might his quietus make\n"
  "With a bare bodkin? who would these fardels bear,\n"
  "To grunt and sweat under a weary life,\n"
  "But that the dread of something after death,--\n"
  "The undiscover'd country, from whose bourn\n"
  "No traveller returns,--puzzles the will,\n"
  "And makes us rather bear those ills we have\n"
  "Than fly to others that we know not of?\n"
  "Thus conscience does make cowards of us all;\n"
  "And thus the native hue of resolution\n"
  "Is sicklied o'er with the pale cast of thought;\n"
  "And enterprises of great pith and moment,\n"
  "With this regard, their currents turn awry,\n"
  "And lose the name of action.--Soft you now!\n"
  "The fair Ophelia!--Nymph, in thy orisons\n"
  "Be all my sins remember'd.\n";

/* Decide, pseudorandomly, whether or not to include the above quotation
   in the input to MD5.  */
static inline bool
get_nth_bit (const uint8_t digest[16], unsigned int n)
{
  unsigned int byte = (n % 128) / 8;
  unsigned int bit  = (n % 128) % 8;
  return !!(digest[byte] & (1 << bit));
}

static bool
muffet_coin_toss (const uint8_t prev_digest[16], unsigned int round_count)
{
  unsigned int x, y, a, b, r, v, i;
  for (i = 0, x = 0, y = 0; i < 8; i++)
    {
      a = prev_digest[(i + 0) % 16];
      b = prev_digest[(i + 3) % 16];
      r = a >> (b % 5);
      v = prev_digest[r % 16];
      if (b & (1u << (a % 8)))
        v /= 2;
      x |= ((unsigned int) +get_nth_bit (prev_digest, v)) << i;

      a = prev_digest[(i + 8)  % 16];
      b = prev_digest[(i + 11) % 16];
      r = a >> (b % 5);
      v = prev_digest[r % 16];
      if (b & (1u << (a % 8)))
        v /= 2;
      y |= ((unsigned int) +get_nth_bit (prev_digest, v)) << i;
    }

  if (get_nth_bit (prev_digest, round_count))
    x /= 2;
  if (get_nth_bit (prev_digest, round_count + 64))
    y /= 2;

  return !!(get_nth_bit (prev_digest, x) ^ get_nth_bit (prev_digest, y));
}

static inline void
write_itoa64_4 (uint8_t *output,
                unsigned int b0, unsigned int b1, unsigned int b2)
{
  unsigned int value = (b0 << 0) | (b1 << 8) | (b2 << 16);
  output[0] = itoa64[value & 0x3f];
  output[1] = itoa64[(value >> 6) & 0x3f];
  output[2] = itoa64[(value >> 12) & 0x3f];
  output[3] = itoa64[(value >> 18) & 0x3f];
}

/* used only for the last two bytes of crypt_sunmd5_rn output */
static inline void
write_itoa64_2 (uint8_t *output,
                unsigned int b0, unsigned int b1, unsigned int b2)
{
  unsigned int value = (b0 << 0) | (b1 << 8) | (b2 << 16);
  output[0] = itoa64[value & 0x3f];
  output[1] = itoa64[(value >> 6) & 0x3f];
}

/* Module entry points.  */

void
crypt_sunmd5_rn (const char *phrase, size_t phr_size,
                 const char *setting, size_t ARG_UNUSED (set_size),
                 uint8_t *output, size_t out_size,
                 void *scratch, size_t scr_size)
{
  struct crypt_sunmd5_scratch
  {
    MD5_CTX ctx;
    uint8_t dg[16];
    char    rn[16];
  };

  /* If 'setting' doesn't start with the prefix, we should not have
     been called in the first place.  */
  if (strncmp (setting, SUNMD5_PREFIX, SUNMD5_PREFIX_LEN)
      || (setting[SUNMD5_PREFIX_LEN] != '$'
          && setting[SUNMD5_PREFIX_LEN] != ','))
    {
      errno = EINVAL;
      return;
    }

  /* For bug-compatibility with the original implementation, we allow
     'rounds=' to follow either '$md5,' or '$md5$'.  */
  const char *p = setting + SUNMD5_PREFIX_LEN + 1;
  unsigned int nrounds = 4096;
  if (!strncmp (p, "rounds=", sizeof "rounds=" - 1))
    {
      p += sizeof "rounds=" - 1;
      /* Do not allow an explicit setting of zero additional rounds,
         nor leading zeroes on the number of rounds.  */
      if (!(*p >= '1' && *p <= '9'))
        {
          errno = EINVAL;
          return;
        }

      errno = 0;
      char *endp;
      unsigned long arounds = strtoul (p, &endp, 10);
      if (endp == p || arounds > SUNMD5_MAX_ROUNDS || errno)
        {
          errno = EINVAL;
          return;
        }
      nrounds += (unsigned int)arounds;
      p = endp;
      if (*p != '$')
        {
          errno = EINVAL;
          return;
        }
      p += 1;
    }

  /* p now points to the beginning of the actual salt.  */
  p += strspn (p, (const char *)itoa64);
  if (*p != '\0' && *p != '$')
    {
      errno = EINVAL;
      return;
    }
  /* For bug-compatibility with the original implementation, if p
     points to a '$' and the following character is either another '$'
     or NUL, the first '$' should be included in the salt.  */
  if (p[0] == '$' && (p[1] == '$' || p[1] == '\0'))
    p += 1;

  size_t saltlen = (size_t) (p - setting);
  /* Do we have enough space?  */
  if (scr_size < sizeof (struct crypt_sunmd5_scratch)
      || out_size < saltlen + SUNMD5_BARE_OUTPUT_LEN + 2)
    {
      errno = ERANGE;
      return;
    }

  struct crypt_sunmd5_scratch *s = scratch;

  /* Initial round.  */
  MD5_Init (&s->ctx);
  MD5_Update (&s->ctx, phrase, phr_size);
  MD5_Update (&s->ctx, setting, saltlen);
  MD5_Final (s->dg, &s->ctx);

  /* Stretching rounds.  */
  for (unsigned int i = 0; i < nrounds; i++)
    {
      MD5_Init (&s->ctx);

      MD5_Update (&s->ctx, s->dg, sizeof s->dg);

      /* The trailing nul is intentionally included.  */
      if (muffet_coin_toss (s->dg, i))
        MD5_Update (&s->ctx, hamlet_quotation, sizeof hamlet_quotation);

      int nwritten = snprintf (s->rn, sizeof s->rn, "%u", i);
      assert (nwritten >= 1 && (unsigned int)nwritten + 1 <= sizeof s->rn);
      MD5_Update (&s->ctx, s->rn, (unsigned int)nwritten);

      MD5_Final (s->dg, &s->ctx);
    }

  memcpy (output, setting, saltlen);
  *(output + saltlen + 0) = '$';
  /* This is the same permuted order used by BSD md5-crypt ($1$).  */
  write_itoa64_4 (output + saltlen +  1, s->dg[12], s->dg[ 6], s->dg[0]);
  write_itoa64_4 (output + saltlen +  5, s->dg[13], s->dg[ 7], s->dg[1]);
  write_itoa64_4 (output + saltlen +  9, s->dg[14], s->dg[ 8], s->dg[2]);
  write_itoa64_4 (output + saltlen + 13, s->dg[15], s->dg[ 9], s->dg[3]);
  write_itoa64_4 (output + saltlen + 17, s->dg[ 5], s->dg[10], s->dg[4]);
  write_itoa64_2 (output + saltlen + 21, s->dg[11], 0, 0);
  *(output + saltlen + 23) = '\0';
}

void
gensalt_sunmd5_rn (unsigned long count,
                   const uint8_t *rbytes,
                   size_t nrbytes,
                   uint8_t *output,
                   size_t o_size)
{
  if (o_size < SUNMD5_MAX_SETTING_LEN + 1)
    {
      errno = ERANGE;
      return;
    }
  if (nrbytes < 6 + 2)
    {
      errno = EINVAL;
      return;
    }

  /* The default number of rounds, 4096, is much too low.  The actual
     number of rounds is somewhat randomized to make construction of
     rainbow tables more difficult (effectively this means an extra 16
     bits of entropy are smuggled into the salt via the round number).  */
  if (count < 32768)
    count = 32768;
  else if (count > SUNMD5_MAX_ROUNDS - 65536)
    count = SUNMD5_MAX_ROUNDS - 65536;

  count += ((unsigned long)rbytes[0]) << 8;
  count += ((unsigned long)rbytes[1]) << 0;

  assert (count != 0);

  size_t written = (size_t) snprintf ((char *)output, o_size,
                                      "%s,rounds=%lu$", SUNMD5_PREFIX, count);


  write_itoa64_4(output + written + 0, rbytes[2], rbytes[3], rbytes[4]);
  write_itoa64_4(output + written + 4, rbytes[5], rbytes[6], rbytes[7]);

  output[written + 8] = '$';
  output[written + 9] = '\0';
}

#endif

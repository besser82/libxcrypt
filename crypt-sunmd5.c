/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "crypt-port.h"
#include "crypt-private.h"
#include "alg-md5.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#define CRYPT_ALGNAME      "md5"

/* minimum number of rounds we do, not including the per-user ones */
#define BASIC_ROUND_COUNT  4096  /* enough to make things interesting */
#define DIGEST_LEN         16
#define ROUND_BUFFER_LEN   64

/*
 * Public domain quotation courtesy of Project Gutenberg.
 * ftp://metalab.unc.edu/pub/docs/books/gutenberg/etext98/2ws2610.txt
 * Hamlet III.ii - 1517 bytes, including trailing NUL
 * ANSI-C string constant concatenation is a requirement here.
 */
static const char constant_phrase[] =
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

/* ------------------------------------------------------------------ */

static int
md5bit (uint8_t *digest, int bit_num)
{
  int byte_off;
  int bit_off;

  bit_num %= 128;          /* keep this bounded for convenience */
  byte_off = bit_num / 8;
  bit_off = bit_num % 8;

  /* return the value of bit N from the digest */
  return ((digest[byte_off] & (0x01 << bit_off)) ? 1 : 0);
}

/* 0 ... 63 => ascii - 64 */
static unsigned char itoa64[] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void
to64 (char *s, uint64_t v, int n)
{
  while (--n >= 0)
    {
      *s++ = (char)itoa64[v&0x3f];
      v >>= 6;
    }
}

#define ROUNDS             "rounds="
#define ROUNDSLEN          (sizeof (ROUNDS) - 1)

/*
 * get the integer value after rounds= where ever it occurs in the string.
 * if the last char after the int is a , or $ that is fine anything else is an
 * error.
 */
static uint32_t
getrounds (const char *s)
{
  char *r, *p, *e;
  long val;

  if (s == NULL)
    return (0);

  if ((r = strstr (s, ROUNDS)) == NULL)
    return (0);

  if (strncmp (r, ROUNDS, ROUNDSLEN) != 0)
    return (0);

  p = r + ROUNDSLEN;
  errno = 0;
  val = strtol (p, &e, 10);
  /*
   * An error occured or there is non-numeric stuff at the end
   * which isn't one of the crypt(3c) special chars ',' or '$'
   */
  if (errno != 0 || val < 0 ||
      !(*e == '\0' || *e == ',' || *e == '$'))
    {
      return (0);
    }

  return ((uint32_t)val);
}

void
gensalt_sunmd5_rn (unsigned long count,
                   const uint8_t *rbytes, size_t nrbytes,
                   uint8_t *output, size_t o_size)
{
  /* This should not happen, but.  */
  if ((nrbytes < sizeof (uint64_t)) || (o_size < 32))
    {
      errno = ERANGE;
      return;
    }

  uint64_t rndval;
  char rndstr[sizeof (rndval) + 1];  /* rndval as a base64 string */
  const uint8_t minrounds = 15;      /* Min. number of rounds = 2^X */

  /* Set count to a reasonable random value,
     if count was not set high enough by the
     caller.  */
  if (count < (unsigned long)(1 << minrounds))
    {
      uint64_t rand1, rand2;
      get_random_bytes(&rand1, sizeof (uint64_t));
      get_random_bytes(&rand2, sizeof (uint64_t));
      count  = (long unsigned int)(1 << ((rand1 % 2) + minrounds));
      count += (long unsigned int)(rand2 % (uint64_t)((1 << (minrounds - 1)) + 1));
    }

  memcpy (&rndval, rbytes, sizeof (rndval));
  to64 ((char *)&rndstr, rndval, sizeof (rndval));
  rndstr[sizeof (rndstr) - 1] = '\0';

  /* Generated salt is at least 27 bytes
     and a maximum of 32 bytes long.  */
  snprintf ((char *)output, o_size,
            "$" CRYPT_ALGNAME "," ROUNDS "%u$%s$",
            (unsigned int)count, rndstr);
}

void
crypt_sunmd5_rn (const char *phrase, const char *setting,
                 uint8_t *output, size_t o_size,
                 void *scratch, size_t s_size)
{
  /* put all the sensitive data in a struct */
  struct sunmd5_ctx
  {
    struct md5_ctx context;             /* working buffer for MD5 algorithm */
    uint8_t digest[DIGEST_LEN];         /* where the MD5 digest is stored */

    int indirect_4[16];                 /* extracted array of 4bit values */
    int shift_4[16];                    /* shift schedule, vals 0..4 */

    int s7shift;                        /* shift for shift_7 creation, vals  0..7 */
    int indirect_7[16];                 /* extracted array of 7bit values */
    int shift_7[16];                    /* shift schedule, vals 0..1 */

    int indirect_a;                     /* 7bit index into digest */
    int shift_a;                        /* shift schedule, vals 0..1 */

    int indirect_b;                     /* 7bit index into digest */
    int shift_b;                        /* shift schedule, vals 0..1 */

    int bit_a;                          /* single bit for cointoss */
    int bit_b;                          /* single bit for cointoss */

    char roundascii[ROUND_BUFFER_LEN];  /* ascii rep of roundcount */
  };

  /* Scratch space needs to be large enough
     to fit struct sunmd5_ctx.  Output must
     be able to fit up to 32 bytes for the
     setting + '$' + 22 bytes of hash.  */
  if (s_size < sizeof (struct sunmd5_ctx) || (o_size < 32 + 1 + 22))
    {
      errno = ERANGE;
      return;
    }

  /* If the magic does not match, this
     should not have been called.  */
  if (!strncmp ("$" CRYPT_ALGNAME, setting, sizeof ("$" CRYPT_ALGNAME)))
    {
      errno = EINVAL;
      return;
    }

  int i;
  int round;
  uint32_t maxrounds = BASIC_ROUND_COUNT;
  uint32_t l;
  char *puresalt;
  char *saltend;
  char *p;
  struct sunmd5_ctx *data = scratch;

  /*
   * Extract the puresalt (if it exists) from the existing salt string
   * $md5[,rounds=%d]$<puresalt>$<optional existing encoding>
   */
  saltend = strrchr (setting, '$');

  if (saltend == NULL || saltend == setting)
    {
      errno = EINVAL;
      return;
    }

  if (saltend[1] != '\0')
    {
      size_t len = (size_t)(saltend - setting + 1);

      if ((puresalt = malloc (len)) == NULL)
        /* malloc() is supposed to set errno == ENOMEM.  */
        return;

      /* The original implementation used strlcpy(),
         which is not portable.  Since strlcpy()
         always terminated a C string properly after
         copying len - 1 bytes of data, we need to
         do that manually.  */
      (void)strncpy (puresalt, setting, len);
      puresalt[len - 1] = '\0';
    }
  else
    {
      puresalt = strdup(setting);

      if (puresalt == NULL)
        {
          /* strdup() is supposed to set errno == ENOMEM.  */
          return;
        }
    }

  /* There must not be any dollar sign '$', but
     the last character before the terminating
     '\0' in the string containing the salt.  */
  if (puresalt[strlen (puresalt) - 2] == '$')
    {
      errno = EINVAL;
      return;
    }

  maxrounds += getrounds (setting);

  /* initialise the context */
  md5_init_ctx (&(data->context));

  /* update with the (hopefully entropic) plaintext */
  md5_process_bytes ((const unsigned char *)phrase, strlen (phrase), &(data->context));

  /* update with the (publically known) salt */
  md5_process_bytes ((unsigned char *)puresalt, strlen (puresalt), &(data->context));


  /* compute the digest */
  md5_finish_ctx (&(data->context), &(data->digest));

  /*
   * now to delay high-speed md5 implementations that have stuff
   * like code inlining, loops unrolled and table lookup
   */

  for (round = 0; (uint32_t)round < maxrounds; round++)
    {
      /* re-initialise the context */
      md5_init_ctx (&(data->context));

      /* update with the previous digest */
      md5_process_bytes (&(data->digest), sizeof (data->digest), &(data->context));

      /* populate the shift schedules for use later */
      for (i = 0; i < 16; i++)
        {
          int j;

          /* offset 3 -> occasionally span more than 1 int32 fetch */
          j = (i + 3) % 16;
          data->s7shift = data->digest[i] % 8;
          data->shift_4[i] = data->digest[j] % 5;
          data->shift_7[i] = (data->digest[j] >> data->s7shift) & 0x01;
        }

      data->shift_a = md5bit (data->digest, round);
      data->shift_b = md5bit (data->digest, round + 64);

      /* populate indirect_4 with 4bit values extracted from digest */
      for (i = 0; i < 16; i++)
        /* shift the digest byte and extract four bits */
        data->indirect_4[i] = (data->digest[i] >> data->shift_4[i]) & 0x0f;

      /*
       * populate indirect_7 with 7bit values from digest
       * indexed via indirect_4
       */

      for (i = 0; i < 16; i++)
        /* shift the digest byte and extract seven bits */
        data->indirect_7[i] = (data->digest[data->indirect_4[i]]
                               >> data->shift_7[i]) & 0x7f;

      /*
       * use the 7bit values to indirect into digest,
       * and create two 8bit values from the results.
       */
      data->indirect_a = data->indirect_b = 0;

      for (i = 0; i < 8; i++)
        {
          data->indirect_a |= (md5bit (data->digest,
                                       data->indirect_7[i]) << i);

          data->indirect_b |= (md5bit (data->digest,
                                       data->indirect_7[i + 8]) << i);
        }

      /* shall we utilise the top or bottom 7 bits? */
      data->indirect_a = (data->indirect_a >> data->shift_a) & 0x7f;
      data->indirect_b = (data->indirect_b >> data->shift_b) & 0x7f;

      /* extract two data->digest bits */
      data->bit_a = md5bit (data->digest, data->indirect_a);
      data->bit_b = md5bit (data->digest, data->indirect_b);

      /* xor a coin-toss; if true, mix-in the constant phrase */

      if (data->bit_a ^ data->bit_b)
        md5_process_bytes ((const unsigned char *) constant_phrase,
                           sizeof (constant_phrase),
                           &(data->context));

      /* digest a decimal sprintf of the current roundcount */
      snprintf (data->roundascii, ROUND_BUFFER_LEN, "%d", round);
      md5_process_bytes ((unsigned char *) data->roundascii,
                         strlen (data->roundascii),
                         &(data->context));

      /* compute/flush the digest, and loop */
      md5_finish_ctx (&(data->context), &(data->digest));
    }

  (void)snprintf ((char *)output, o_size, "%s$", puresalt);

  free (puresalt);

  p = (char *)output + strlen ((const char *)output);

  l = (uint32_t)((data->digest[ 0]<<16) | (data->digest[ 6]<<8) | data->digest[12]);
  to64 (p, l, 4);
  p += 4;
  l = (uint32_t)((data->digest[ 1]<<16) | (data->digest[ 7]<<8) | data->digest[13]);
  to64 (p, l, 4);
  p += 4;
  l = (uint32_t)((data->digest[ 2]<<16) | (data->digest[ 8]<<8) | data->digest[14]);
  to64 (p, l, 4);
  p += 4;
  l = (uint32_t)((data->digest[ 3]<<16) | (data->digest[ 9]<<8) | data->digest[15]);
  to64 (p, l, 4);
  p += 4;
  l = (uint32_t)((data->digest[ 4]<<16) | (data->digest[10]<<8) | data->digest[ 5]);
  to64 (p, l, 4);
  p += 4;
  l = (uint32_t)data->digest[11];
  to64 (p, l, 2);
  p += 2;
  *p = '\0';
}

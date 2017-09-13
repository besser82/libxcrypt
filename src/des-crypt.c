/*
 * UFC-crypt: ultra fast crypt(3) implementation
 *
 * Copyright (C) 1991, 1992, 1993, 1996, 1997 Free Software Foundation, Inc.
 *
 * The GNU C Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * The GNU C Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the GNU C Library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA.
 *
 * crypt entry points
 *
 * @(#)crypt-entry.c  1.2 12/20/96
 *
 */

#include "xcrypt-private.h"
#include "des.h"

#include <string.h>


/*
 * UNIX crypt function
 */

char *
__des_crypt_r (const char *key, const char *salt,
               struct crypt_data *restrict data)
{
  uint_fast32_t res[4];
  char ktab[9];

  /*
   * Hack DES tables according to salt
   */
  _ufc_setup_salt_r (salt, data);

  /*
   * Setup key schedule
   */
  memset (ktab, 0, sizeof (ktab));
  strncpy (ktab, key, 8);
  _ufc_mk_keytab_r (ktab, data);

  /*
   * Go for the 25 DES encryptions
   */
  memset (res, 0, sizeof (res));
  _ufc_doit_r (25, data, &res[0]);

  /*
   * Do final permutations
   */
  _ufc_dofinalperm_r (res, data);

  /*
   * And convert back to 6 bit ASCII
   */
  _ufc_output_conversion_r (res[0], res[1], salt, data);
  return data->crypt_3_buf;
}

/*
 * This function implements the "bigcrypt" algorithm specifically for
 * Linux-PAM.
 *
 * This algorithm is algorithm 0 (default) shipped with the C2 secure
 * implementation of Digital UNIX.
 *
 * Disclaimer: This work is not based on the source code to Digital
 * UNIX, nor am I connected to Digital Equipment Corp, in any way
 * other than as a customer. This code is based on published
 * interfaces and reasonable guesswork.
 *
 * Description: The cleartext is divided into blocks of SEGMENT_SIZE=8
 * characters or less. Each block is encrypted using the standard UNIX
 * libc crypt function. The result of the encryption for one block
 * provides the salt for the suceeding block.
 *
 * Restrictions: The buffer used to hold the encrypted result is
 * statically allocated. (see MAX_PASS_LEN below).  This is necessary,
 * as the returned pointer points to "static data that are overwritten
 * by each call", (XPG3: XSI System Interface + Headers pg 109), and
 * this is a drop in replacement for crypt();
 *
 * Andy Phillips <atp@mssl.ucl.ac.uk>
 */

/*
 * Max cleartext password length in segments of 8 characters this
 * function can deal with (16 segments of 8 chars= max 128 character
 * password).
 */

#define MAX_PASS_LEN       16
#define SEGMENT_SIZE       8
#define SALT_SIZE          2
#define KEYBUF_SIZE        ((MAX_PASS_LEN*SEGMENT_SIZE)+SALT_SIZE)
#define ESEGMENT_SIZE      11
#define CBUF_SIZE          ((MAX_PASS_LEN*ESEGMENT_SIZE)+SALT_SIZE+1)

/*
 * This function is not really thread safe. We use it internal only
 * in the moment.
 */
char *
__bigcrypt_r (const char *key, const char *salt,
              struct crypt_data *restrict data)
{
  static char dec_c2_cryptbuf[CBUF_SIZE];       /* static storage area */

  unsigned long int keylen, n_seg, j;
  char *cipher_ptr, *plaintext_ptr, *tmp_ptr, *salt_ptr;
  char keybuf[KEYBUF_SIZE + 1];

  /* reset arrays */
  memset (keybuf, 0, KEYBUF_SIZE + 1);
  memset (dec_c2_cryptbuf, 0, CBUF_SIZE);

  /* fill KEYBUF_SIZE with key */
  strncpy (keybuf, key, KEYBUF_SIZE);

  /* deal with case that we are doing a password check for a
     conventially encrypted password: the salt will be
     SALT_SIZE+ESEGMENT_SIZE long. */
  if (strlen (salt) == (SALT_SIZE + ESEGMENT_SIZE))
    keybuf[SEGMENT_SIZE] = '\0';        /* terminate password early(?) */

  keylen = strlen (keybuf);

  if (!keylen)
    {
      n_seg = 1;
    }
  else
    {
      /* work out how many segments */
      n_seg = 1 + ((keylen - 1) / SEGMENT_SIZE);
    }

  if (n_seg > MAX_PASS_LEN)
    n_seg = MAX_PASS_LEN;       /* truncate at max length */

  /* set up some pointers */
  cipher_ptr = dec_c2_cryptbuf;
  plaintext_ptr = keybuf;

  /* do the first block with supplied salt */
  tmp_ptr = __des_crypt_r (plaintext_ptr, salt, data);

  /* and place in the static area */
  strncpy (cipher_ptr, tmp_ptr, 13);
  cipher_ptr += ESEGMENT_SIZE + SALT_SIZE;
  plaintext_ptr += SEGMENT_SIZE;        /* first block of SEGMENT_SIZE */

  /* change the salt (1st 2 chars of previous block) - this was found
     by dowsing */

  salt_ptr = cipher_ptr - ESEGMENT_SIZE;

  /* so far this is identical to "return crypt(key, salt);", if
     there is more than one block encrypt them... */

  if (n_seg > 1)
    {
      for (j = 2; j <= n_seg; j++)
        {

          tmp_ptr = __des_crypt_r (plaintext_ptr, salt_ptr, data);

          /* skip the salt for seg!=0 */
          strncpy (cipher_ptr, (tmp_ptr + SALT_SIZE), ESEGMENT_SIZE);

          cipher_ptr += ESEGMENT_SIZE;
          plaintext_ptr += SEGMENT_SIZE;
          salt_ptr = cipher_ptr - ESEGMENT_SIZE;
        }
    }

  /* this is the <NUL> terminated encrypted password */

  return dec_c2_cryptbuf;
}

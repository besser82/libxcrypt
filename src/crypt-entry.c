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

#ifdef DEBUG
#include <stdio.h>
#endif
#include <string.h>

#ifndef STATIC
#define STATIC static
#endif

#ifndef DOS
#include "ufc-crypt.h"
#else
/*
 * Thanks to greg%wind@plains.NoDak.edu (Greg W. Wettstein)
 * for DOS patches
 */
#include "ufc.h"
#endif
#include "xcrypt-private.h"
#include "crypt-private.h"

/* Prototypes for local functions.  */
#if __STDC__ - 0
#define _ufc_clearmem(start, cnt)   memset(start, 0, cnt)
#endif

/* For use by the old, non-reentrant routines (crypt/encrypt/setkey)  */
extern struct crypt_data _ufc_foobar;

/*
 * UNIX crypt function
 */

char *
__des_crypt_r (key, salt, data)
     const char *key;
     const char *salt;
     struct crypt_data *__restrict data;
{
  ufc_long res[4];
  char ktab[9];
  ufc_long xx = 25; /* to cope with GCC long long compiler bugs */

  /*
   * Hack DES tables according to salt
   */
  _ufc_setup_salt_r (salt, data);

  /*
   * Setup key schedule
   */
  _ufc_clearmem (ktab, (int) sizeof (ktab));
  (void) strncpy (ktab, key, 8);
  _ufc_mk_keytab_r (ktab, data);

  /*
   * Go for the 25 DES encryptions
   */
  _ufc_clearmem ((char *) res, (int) sizeof (res));
  _ufc_doit_r (xx, data, &res[0]);

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

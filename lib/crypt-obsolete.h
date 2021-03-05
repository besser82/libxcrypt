/* Prototypes for obsolete functions in libcrypt.

   Copyright (C) 1991-2017 Free Software Foundation, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see
   <https://www.gnu.org/licenses/>.  */

#ifndef _CRYPT_OBSOLETE_H
#define _CRYPT_OBSOLETE_H 1

/* These API functions are obsolete and provided for binary backward
   compatibility only.  New programs cannot be linked against them,
   and we do not install this header, but we still need it to build the
   library itself.  */

/* Prepare to encrypt or decrypt data with DES, using KEY.  */
extern void setkey (const char *key);

extern void setkey_r (const char *key,
                      struct crypt_data *restrict data);

/* Encrypt data in BLOCK in place if EDFLAG is zero; otherwise decrypt
   block in place.  */
extern void encrypt (char *block, int edflag);

extern void encrypt_r (char *block, int edflag,
                       struct crypt_data *restrict data);

#endif /* crypt-obsolete.h */

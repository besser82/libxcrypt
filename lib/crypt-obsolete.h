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


/* These functions are obsolete and should never be used, but we have to
   keep providing them for binary backward compatibility.  */

/* Setup DES tables according KEY.  */
extern void setkey (const char *__key);

extern void setkey_r (const char *__key,
                      struct crypt_data *restrict __data);

/* Encrypt data in BLOCK in place if EDFLAG is zero; otherwise decrypt
   block in place.  */
extern void encrypt (char *__block, int __edflag);

extern void encrypt_r (char *__block, int __edflag,
                       struct crypt_data *restrict __data);

#endif /* crypt-obsolete.h */

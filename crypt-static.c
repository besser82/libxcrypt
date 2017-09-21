/* Copyright (C) 2007, 2008, 2009 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@thkukuk.de>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#include "crypt-private.h"
#include "crypt-obsolete.h"

/* The functions that use a global state object are isolated in this
   file so that a statically-linked program that doesn't use them will
   not have the state object its data segment.  */

/* Static buffer used by crypt().  */
#if INCLUDE_crypt || INCLUDE_fcrypt
static struct crypt_data nr_crypt_ctx;

char *
crypt (const char *key, const char *salt)
{
  return crypt_r (key, salt, &nr_crypt_ctx);
}
#endif

#if INCLUDE_crypt
SYMVER_crypt;
#endif

#if INCLUDE_fcrypt
strong_alias (crypt, fcrypt);
SYMVER_fcrypt;
#endif

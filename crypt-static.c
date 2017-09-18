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

/* Static buffer used by crypt() and bigcrypt().  */
static struct crypt_data nr_crypt_ctx;

char *
crypt (const char *key, const char *salt)
{
  return crypt_r (key, salt, &nr_crypt_ctx);
}
#if COMPAT_crypt__glibc
default_symbol(crypt, crypt);
#endif

#if COMPAT_crypt__glibc
strong_alias(crypt, crypt__glibc);
compat_symbol(crypt, crypt__glibc);
#endif

#if COMPAT_fcrypt
strong_alias (crypt, fcrypt);
compat_symbol (fcrypt, fcrypt);
#endif

#if COMPAT_bigcrypt
/* Obsolete interface - not to be used in new code.  This function is
   the same as crypt, but it forces the use of the Digital Unix
   "bigcrypt" hash, which is nearly as weak as traditional DES.
   Because it is obsolete, we have not added a reentrant version.  */
char *
bigcrypt (const char *key, const char *salt)
{
  char *retval = crypt_des_big_rn
    (key, salt, (char *)&nr_crypt_ctx, sizeof nr_crypt_ctx);
  if (retval)
    return retval;
  make_failure_token (salt, (char *)&nr_crypt_ctx, sizeof nr_crypt_ctx);
  return (char *)&nr_crypt_ctx;
}
compat_symbol (bigcrypt, bigcrypt);
#endif

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

#include "crypt-port.h"
#include "crypt-base.h"

/* The functions that use global state objects are isolated in their
   own files so that a statically-linked program that doesn't use them
   will not have the state objects in its data segment.  */

#if INCLUDE_crypt_gensalt
char *
crypt_gensalt (const char *prefix, unsigned long count,
               const char *rbytes, int nrbytes)
{
  static char output[CRYPT_GENSALT_OUTPUT_SIZE];

  return crypt_gensalt_rn (prefix, count,
                           rbytes, nrbytes, output, sizeof (output));
}
SYMVER_crypt_gensalt;
#endif

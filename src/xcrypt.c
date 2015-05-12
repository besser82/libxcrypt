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

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xcrypt-private.h"

#define CRYPT_OUTPUT_SIZE		(7 + 22 + 31 + 1)
#define CRYPT_GENSALT_OUTPUT_SIZE	(7 + 22 + 1)


struct plugin_t {
  const char *id;
  char *(*crypt_r) (const char *key, const char *salt, char *data, int size);
  char *(*gensalt_r) (unsigned long count,
                      const char *input, int input_size,
		      char *output, int output_size);
  struct plugin_t *next;
};

static struct plugin_t *plugins;

static struct plugin_t *
get_plugin (const char *hash_id)
{
   struct plugin_t *ptr = plugins;

   while (ptr)
     {
        if (strcmp (hash_id, ptr->id) == 0)
          return ptr;

        ptr = ptr->next;
     }

   void *handle = NULL;
   char *buf;

   if (asprintf (&buf, "%s/libxcrypt_%s.so.1", PLUGINDIR, hash_id) < 0)
     return NULL;

   handle = dlopen (buf, RTLD_NOW);
   free (buf);

   if (handle == NULL)
     return NULL;

   struct plugin_t *new = malloc (sizeof (struct plugin_t));
   new->next = NULL;

   new->id = strdup (hash_id);

   new->crypt_r = dlsym (handle, "__crypt_r");
   new->gensalt_r = dlsym (handle, "__crypt_gensalt_r");

  if (plugins == NULL)
    plugins = new;
  else
    {
      ptr = plugins;

      while (ptr->next != NULL)
        ptr = ptr->next;

      ptr->next = new;
    }

   return new;
}


static char *
_xcrypt_retval_magic (char *retval, __const char *salt, char *output)
{
  if (retval)
    return retval;

  output[0] = '*';
  output[1] = '0';
  output[2] = '\0';

  if (salt[0] == '*' && salt[1] == '0')
    output[1] = '1';

  return output;
}

static char *
__xcrypt_rn (__const char *key, __const char *salt, char *data, size_t size)
{
  if (salt[0] == '$')
    {
      char *hash_id = strdup (&salt[1]);
      char *c = strchr (hash_id, '$');

      if (c == NULL)
	{
	  free (hash_id);
	  return NULL;
	}

      *c = '\0';
      struct plugin_t *plugin = get_plugin (hash_id);

      free (hash_id);

      if (plugin == NULL || plugin->crypt_r == NULL)
        return NULL;

      return plugin->crypt_r (key, salt, (char *) data, size);
    }
  else if (salt[0] != '_' && size >= sizeof (struct crypt_data))
    /* DES crypt and bigcrypt */
    {
      if (strlen (salt) > 13)
	return __bigcrypt_r (key, salt, (struct crypt_data *) data);
      else
	return __des_crypt_r (key, salt, (struct crypt_data *) data);
    }

  /* Unknown salt */
  __set_errno (ERANGE);
  return NULL;
}

char *
__xcrypt_r (__const char *key, __const char *salt, struct crypt_data *data)
{
  return _xcrypt_retval_magic (__xcrypt_rn (key, salt, (char *)data,
					    sizeof (*data)),
			       salt, (char *) data);
}

char *
__xcrypt (__const char *key, __const char *salt)
{
  return _xcrypt_retval_magic (__xcrypt_rn (key, salt, (char *)&_ufc_foobar,
					    sizeof (_ufc_foobar)),
			       salt, (char *) &_ufc_foobar);
}

char *
__bigcrypt (__const char *key, __const char *salt)
{
  return __bigcrypt_r (key, salt, &_ufc_foobar);
}

char *
__xcrypt_gensalt_r (__const char *prefix, unsigned long count,
		    __const char *input, int size, char *output,
		    int output_size)
{
  char *(*use) (unsigned long count,
		__const char *input, int size, char *output, int output_size);

  /* This may be supported on some platforms in the future */
  if (!input)
    {
      __set_errno (EINVAL);
      return NULL;
    }

  if (prefix[0] == '$')
    {
      char *hash_id = strdup (&prefix[1]);
      char *c = strchr (hash_id, '$');

      if (c == NULL)
	{
	  free (hash_id);
	  return NULL;
	}

      *c = '\0';
      struct plugin_t *plugin = get_plugin (hash_id);

      if (plugin == NULL || plugin->gensalt_r == NULL)
	{
	  if (hash_id[0] == '1') /* Special case: MD5 */
	    use = _xcrypt_gensalt_md5_rn;
	  else if (hash_id[0] == '5') /* sha256 */
	    use = _xcrypt_gensalt_sha256_rn;
	  else if (hash_id[0] == '6') /* sha512 */
	    use = _xcrypt_gensalt_sha512_rn;
	  else
	    use = _xcrypt_gensalt_traditional_rn;
	}
      else
	use = plugin->gensalt_r;

      free (hash_id);
    }
  else if (prefix[0] == '_')
    use = _xcrypt_gensalt_extended_rn;
  else if (!prefix[0] ||
	   (prefix[0] && prefix[1] &&
	    memchr (_xcrypt_itoa64, prefix[0], 64) &&
	    memchr (_xcrypt_itoa64, prefix[1], 64)))
    use = _xcrypt_gensalt_traditional_rn;
  else
    {
      __set_errno (EINVAL);
      return NULL;
    }

  return use (count, input, size, output, output_size);
}

char *
__xcrypt_gensalt (__const char *prefix, unsigned long count,
		 __const char *input, int size)
{
  static char output[CRYPT_GENSALT_OUTPUT_SIZE];

  return __xcrypt_gensalt_r (prefix, count,
			     input, size, output, sizeof (output));
}

weak_alias (__xcrypt_r, crypt_r)
weak_alias (__xcrypt_r, xcrypt_r)
weak_alias (__xcrypt, crypt)
weak_alias (__xcrypt, xcrypt)
weak_alias (__xcrypt, fcrypt)
weak_alias (__bigcrypt, bigcrypt)
weak_alias (__xcrypt_gensalt_r, crypt_gensalt_r)
weak_alias (__xcrypt_gensalt, crypt_gensalt)
weak_alias (__xcrypt_gensalt_r, xcrypt_gensalt_r)
weak_alias (__xcrypt_gensalt, xcrypt_gensalt)

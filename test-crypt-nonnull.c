/* Test program for bad DES salt detection in crypt.
   Copyright (C) 2012-2017 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <crypt.h>

static const char *tests[][3] =
{
  { "single char",           "/"    },
  { "first char bad",        "!x"   },
  { "second char bad",       "Z%"   },
  { "both chars bad",        ":@"   },
  { "un$upported algorithm", "$2$"  },
  { "un$upported $etting",   "$2a$" },
  { "un$upported $etting",   "$2b$" },
  { "un$upported $etting",   "$2x$" },
  { "bad salt for BSDi",     "_1"   },
  { "end of page",           NULL   }
};

int
main (void)
{
  int cdsize = sizeof (struct crypt_data);
  int result = 0;
  struct crypt_data cd;
  struct crypt_data *cdptr = &cd;
  size_t n = sizeof (tests) / sizeof (*tests);
  size_t pagesize = (size_t) sysconf (_SC_PAGESIZE);
  char *page;
  const char *saltstr, *special = "%";

  /* Check that crypt won't look at the second character if the first
     one is invalid.  */
  page = mmap (NULL, pagesize * 2, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANON, -1, 0);
  if (page == MAP_FAILED)
    {
      perror ("mmap");
      n--;
    }
  else
    {
      if (mmap (page + pagesize, pagesize, 0,
                MAP_PRIVATE | MAP_ANON | MAP_FIXED,
                -1, 0) != page + pagesize)
        perror ("mmap 2");
      page[pagesize - 1] = special[0];
      tests[n - 1][1] = &page[pagesize - 1];
    }

  for (size_t i = 0; i < n; i++)
    {
      if (crypt_rn (tests[i][0], tests[i][1], cdptr, cdsize))
        {
          result++;
          if (memcmp (&page[pagesize - 1], tests[i][1], 1) != 0)
            saltstr = tests[i][1];
          else
            saltstr = special;
          printf ("%s: crypt_rn returned non-NULL with salt \"%s\"\n",
                  tests[i][0], saltstr);
        }

      if (crypt_ra (tests[i][0], tests[i][1], (void **)&cdptr, &cdsize))
        {
          result++;
          if (memcmp (&page[pagesize - 1], tests[i][1], 1) != 0)
            saltstr = tests[i][1];
          else
            saltstr = special;
          printf ("%s: crypt_ra returned non-NULL with salt \"%s\"\n",
                  tests[i][0], saltstr);
        }
    }

  return result;
}

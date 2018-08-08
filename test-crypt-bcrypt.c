/*
 * Written by Solar Designer <solar at openwall.com> in 2000-2014.
 * No copyright is claimed, and the software is hereby placed in the public
 * domain.  In case this attempt to disclaim copyright and place the software
 * in the public domain is deemed null and void, then the software is
 * Copyright (c) 2000-2014 Solar Designer and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * See crypt_blowfish.c for more information.
 */

#include "crypt-port.h"
#include "crypt-base.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#if INCLUDE_bcrypt

static const char *tests[][3] =
{
  {
    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
    "U*U"
  },
  {
    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
    "U*U*"
  },
  {
    "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
    "U*U*U"
  },
  {
    "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
    "0123456789abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "chars after 72 are ignored"
  },
  {
    "$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e",
    "\xa3"
  },
  {
    "$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e",
    "\xff\xff\xa3"
  },
  {
    "$2y$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e",
    "\xff\xff\xa3"
  },
  {
    "$2a$05$/OK.fbVrR/bpIqNJ5ianF.nqd1wy.pTMdcvrRWxyiGL2eMz.2a85.",
    "\xff\xff\xa3"
  },
  {
    "$2b$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e",
    "\xff\xff\xa3"
  },
  {
    "$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq",
    "\xa3"
  },
  {
    "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq",
    "\xa3"
  },
  {
    "$2b$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq",
    "\xa3"
  },
  {
    "$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi",
    "1\xa3" "345"
  },
  {
    "$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi",
    "\xff\xa3" "345"
  },
  {
    "$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi",
    "\xff\xa3" "34" "\xff\xff\xff\xa3" "345"
  },
  {
    "$2y$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi",
    "\xff\xa3" "34" "\xff\xff\xff\xa3" "345"
  },
  {
    "$2a$05$/OK.fbVrR/bpIqNJ5ianF.ZC1JEJ8Z4gPfpe1JOr/oyPXTWl9EFd.",
    "\xff\xa3" "34" "\xff\xff\xff\xa3" "345"
  },
  {
    "$2y$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e",
    "\xff\xa3" "345"
  },
  {
    "$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e",
    "\xff\xa3" "345"
  },
  {
    "$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS",
    "\xa3" "ab"
  },
  {
    "$2x$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS",
    "\xa3" "ab"
  },
  {
    "$2y$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS",
    "\xa3" "ab"
  },
  {
    "$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS",
    "\xd1\x91"
  },
  {
    "$2x$05$6bNw2HLQYeqHYyBfLMsv/O9LIGgn8OMzuDoHfof8AQimSGfcSWxnS",
    "\xd0\xc1\xd2\xcf\xcc\xd8"
  },
  {
    "$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6",
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
    "chars after 72 are ignored as usual"
  },
  {
    "$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy",
    "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
    "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
    "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
    "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
    "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
    "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
  },
  {
    "$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe",
    "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
    "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
    "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
    "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
    "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
    "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
  },
  {
    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
    ""
  },
  { "*0", "", "$2a$03$CCCCCCCCCCCCCCCCCCCCC." },
  { "*0", "", "$2a$32$CCCCCCCCCCCCCCCCCCCCC." },
  { "*0", "", "$2c$05$CCCCCCCCCCCCCCCCCCCCC." },
  { "*0", "", "$2z$05$CCCCCCCCCCCCCCCCCCCCC." },
  { "*0", "", "$2`$05$CCCCCCCCCCCCCCCCCCCCC." },
  { "*0", "", "$2{$05$CCCCCCCCCCCCCCCCCCCCC." },
  { "*1", "", "*0" },
  { 0 }
};

int
main (void)
{
  void *data = 0;
  int size = 0x12345678;
  int i;
  int status = 0;

  for (i = 0; tests[i][0]; i++)
    {
      const char *hash = tests[i][0];
      const char *key = tests[i][1];
      const char *setting = tests[i][2];
      const char *p;
      int ok = !setting || hash[0] != '*';
      char s_buf[30];
      char o_buf[sizeof (struct crypt_data)];
      int errnm, match;

      if (!setting)
        {
          memcpy (s_buf, hash, sizeof (s_buf) - 1);
          s_buf[sizeof (s_buf) - 1] = 0;
          setting = s_buf;
        }

      errno = 0;
      p = crypt (key, setting);
      errnm = errno;
#if ENABLE_FAILURE_TOKENS
      match = strcmp (p, hash);
#else
      match = (ok ? strcmp (p, hash) : p != 0);
#endif
      if ((!ok && !errno) || match)
        {
          printf ("FAIL: %d/crypt.1: key=%s setting=%s: xhash=%s xerr=%d, "
                  "p=%s match=%d err=%s\n",
                  i, key, setting, hash, !ok, p, match==0, strerror (errnm));
          status = 1;
          continue;
        }

      if (ok)
        {
          p = crypt (key, hash);
          if (strcmp (p, hash))
            {
              printf ("FAIL: %d/crypt.2: key=%s hash=%s p=%s\n",
                      i, key, hash, p);
              status = 1;
              continue;
            }
        }

      strcpy (o_buf, "abc");
      const char *x = "*0";
      if (setting[0] == '*' && setting[1] == '0')
        x = "*1";
      errno = 0;
      p = crypt_rn (key, setting, o_buf, sizeof o_buf);
      errnm = errno;
      if (ok)
        match = p && !strcmp (p, hash);
      else
        match = !p && errnm && !strcmp (o_buf, x);

      if (!match)
        {
          printf ("FAIL: %d/crypt_rn: key=%s setting=%s: "
                  "xhash=%s xmagic=%s xerr=%d, p=%s obuf=%s err=%s\n",
                  i, key, setting, hash, x, !ok, p, o_buf,
                  strerror (errnm));
          status = 1;
          continue;
        }

      errno = 0;
      p = crypt_ra (key, setting, &data, &size);
      errnm = errno;

      if (ok)
        match = p && !strcmp (p, hash);
      else
        match = !p && errnm && !strcmp (data, hash);

      if (!match)
        {
          printf ("FAIL: %d/crypt_ra: key=%s setting=%s: xhash=%s xerr=%d, "
                  "p=%s data=%s err=%s\n",
                  i, key, setting, hash, !ok, p,
                  (char *)data, strerror (errnm));
          status = 1;
          continue;
        }
    }

  free (data);
  return status;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif

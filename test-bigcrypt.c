#include <string.h>
#include <stdio.h>

#include "crypt.h"
#include "crypt-obsolete.h"

compat_symbol_ref (bigcrypt, bigcrypt);

int
main (void)
{
  char *newpassword = bigcrypt ("1234567890123", "GA");

  if (strlen (newpassword) != 24)
    {
      fprintf (stderr, "bigcrypt result was wrong length\n");
      return 1;
    }

  if (strcmp (newpassword, crypt ("1234567890123", newpassword)) != 0)
    {
      fprintf (stderr, "crypt cannot encrypt bigcrypt passwords\n");
      return 1;
    }

  return 0;
}

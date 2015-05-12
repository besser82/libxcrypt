
#include <string.h>
#include "xcrypt.h"
#include "xcrypt-plugin.h"


int
main (void)
{
  struct crypt_data output;
  const char salt[] = "$1$saltstring";
  char *cp;
  int result = 0;

  cp = __crypt_r ("Hello world!", salt, (char *)&output, sizeof (output));
  if (cp == NULL)
    return 1;

  result |= strcmp ("$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1", cp);

  return result;
}

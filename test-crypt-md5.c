#include "crypt-port.h"
#include "crypt-base.h"

int
main (void)
{
  struct crypt_data output;
  const char salt[] = "$1$saltstring";
  char *cp;
  int result = 0;

  cp = crypt_r ("Hello world!", salt, &output);
  if (cp == 0)
    return 1;

  result |= strcmp ("$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1", cp);

  return result;
}

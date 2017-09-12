#ifndef _LIBC_SYMBOLS_H
#define _LIBC_SYMBOLS_H 1

#include "config.h"

#define weak_alias(name, aliasname) _weak_alias (name, aliasname)
#define _weak_alias(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((weak, alias (#name)));

#define __set_errno(val) errno = (val)

#endif

#ifndef _LIBC_SYMBOLS_H
#define _LIBC_SYMBOLS_H 1

#include "config.h"

/* Suppression of unused-argument warnings.  */
#if defined __cplusplus
# define ARG_UNUSED(x) /*nothing*/
#elif defined __GNUC__ && __GNUC__ >= 3
# define ARG_UNUSED(x) x __attribute__ ((__unused__))
#else
# define ARG_UNUSED(x) x
#endif

#endif

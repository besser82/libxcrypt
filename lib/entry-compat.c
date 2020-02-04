#include "crypt-port.h"
#include "crypt-symver.h"

#if INCLUDE_crypt || (INCLUDE_fcrypt && !ENABLE_OBSOLETE_API_ENOSYS)
#endif

#if INCLUDE_crypt
SYMVER_crypt;
#endif

#if INCLUDE_fcrypt && !ENABLE_OBSOLETE_API_ENOSYS
strong_alias (crypt, fcrypt);
SYMVER_fcrypt;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt && INCLUDE_xcrypt
strong_alias (crypt, xcrypt);
SYMVER_xcrypt;
#endif

SYMVER_crypt_ra;
#endif

SYMVER_crypt_r;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt_r && INCLUDE_xcrypt_r
strong_alias (crypt_r, xcrypt_r);
SYMVER_xcrypt_r;
#endif

SYMVER_crypt_rn;

#endif

SYMVER_crypt_gensalt;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt_gensalt && INCLUDE_xcrypt_gensalt
strong_alias (crypt_gensalt, xcrypt_gensalt);
SYMVER_xcrypt_gensalt;
#endif

SYMVER_crypt_gensalt_ra;
#endif

#endif

#if INCLUDE_crypt_gensalt_rn
SYMVER_crypt_gensalt_rn;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt_gensalt_rn && INCLUDE_crypt_gensalt_r
strong_alias (crypt_gensalt_internal, crypt_gensalt_r);
SYMVER_crypt_gensalt_r;
#endif

/* For code compatibility with older versions (v3.1.1 and earlier).  */
#if INCLUDE_crypt_gensalt_rn && INCLUDE_xcrypt_gensalt_r
strong_alias (crypt_gensalt_internal, xcrypt_gensalt_r);
SYMVER_xcrypt_gensalt_r;
#endif

SYMVER_crypt_preferred_method;
#endif

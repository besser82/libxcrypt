#include <stdio.h>
#include <string.h>

#include "crypt-port.h"

const char defined_hash_methods[] =
#if INCLUDE_bcrypt
  "bcrypt:$2b$;"
#endif
#if INCLUDE_bcrypt_a
  "bcrypt_a:$2a$;"
#endif
#if INCLUDE_bcrypt_x
  "bcrypt_x:$2x$;"
#endif
#if INCLUDE_bcrypt_y
  "bcrypt_y:$2y$;"
#endif
#if INCLUDE_bigcrypt
  "bigcrypt:;"
#endif
#if INCLUDE_bsdicrypt
  "bsdicrypt:_;"
#endif
#if INCLUDE_descrypt
  "descrypt:;"
#endif
#if INCLUDE_gost_yescrypt
  "gost_yescrypt:$gy$;"
#endif
#if INCLUDE_md5crypt
  "md5crypt:$1$;"
#endif
#if INCLUDE_nt
  "nt:$3$;"
#endif
#if INCLUDE_scrypt
  "scrypt:$7$;"
#endif
#if INCLUDE_sha1crypt
  "sha1crypt:$sha1;"
#endif
#if INCLUDE_sha256crypt
  "sha256crypt:$5$;"
#endif
#if INCLUDE_sha512crypt
  "sha512crypt:$6$;"
#endif
#if INCLUDE_sm3_yescrypt
  "sm3_yescrypt:$sm3y$;"
#endif
#if INCLUDE_sm3crypt
  "sm3crypt:$sm3$;"
#endif
#if INCLUDE_sunmd5
  "sunmd5:$md5;"
#endif
#if INCLUDE_yescrypt
  "yescrypt:$y$;"
#endif
"";

int main(void)
{
    const char *expected = defined_hash_methods;
    const char *reported = crypt_get_supported_hash_methods();
    size_t len1 = strlen(expected) - 1, len2 = strlen(reported);
    int res = (len1 != len2 || strncmp(expected, reported, len2));

    // Assume there is ";" in the end of defined_hash_methods
    fprintf(stderr, "Compiled and reported by"
            " crypt_get_supported_hash_methods() lists of supported"
            " hash methods are %sequal:\n\"%s\" %s=\n\"%s;\"\n",
            (res ? "NOT " : ""), expected, (res ? "!" : "="), reported);
    return res;
}

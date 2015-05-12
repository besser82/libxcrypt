
#ifndef _XCRYPT_PRIVATE_H
#define _XCRYPT_PRIVATE_H       1

#define xcrypt __xcrypt
#define xcrypt_r __xcrypt_r
#define xcrypt_gensalt __xcrypt_gensalt
#define xcrypt_gensalt_r __xcrypt_gensalt_r
#define bigcrypt __bigcrypt

#include "xcrypt.h"

#undef xcrypt
#undef xcrypt_r
#undef xcrypt_gensalt
#undef xcrypt_gensalt_r
#undef crypt
#undef crypt_r
#undef crypt_gensalt
#undef crypt_gensalt_r
#undef bigcrypt

extern unsigned char _xcrypt_itoa64[];
extern char *_xcrypt_gensalt_traditional_rn (unsigned long count,
					     __const char *input, int size,
					     char *output, int output_size);
extern char *_xcrypt_gensalt_extended_rn (unsigned long count,
					  __const char *input, int size,
					  char *output, int output_size);
extern char *_xcrypt_gensalt_md5_rn (unsigned long count, __const char *input,
				     int size, char *output, int output_size);
extern char *_xcrypt_gensalt_sha256_rn (unsigned long count,
					__const char *input,
					int size, char *output,
					int output_size);
extern char *_xcrypt_gensalt_sha512_rn (unsigned long count,
					__const char *input,
					int size, char *output,
					int output_size);

extern struct crypt_data _ufc_foobar;

extern char *__des_crypt_r (__const char *__key, __const char *__salt,
                            struct crypt_data * __restrict __data);
extern char *__bigcrypt_r (__const char *key, __const char *salt,
                           struct crypt_data * __restrict __data);

#endif

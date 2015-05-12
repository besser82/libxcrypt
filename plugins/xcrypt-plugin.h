
#ifndef _XCRYPT_PLUGIN_H
#define _XCRYPT_PLUGIN_H       1

extern char *__crypt_r (__const char *key, __const char *salt,
			char *output, int size);
extern char *__crypt_gensalt_r (unsigned long count,
				__const char *input, int size,
				char *output, int output_size);

#endif

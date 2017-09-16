#ifndef _CRYPT_SYMBOLS_H
#define _CRYPT_SYMBOLS_H 1

#include "config.h"

/* Suppression of unused-argument warnings.  */
#if defined __cplusplus
# define ARG_UNUSED(x) /*nothing*/
#elif defined __GNUC__ && __GNUC__ >= 3
# define ARG_UNUSED(x) x __attribute__ ((__unused__))
#else
# define ARG_UNUSED(x) x
#endif

/* Define ALIASNAME as a strong alias for NAME.  Currently we only
   know how to do this using GCC extensions.  */
#if defined __GNUC__ && __GNUC__ >= 3
#define strong_alias(name, aliasname) _strong_alias(name, aliasname)
#define _strong_alias(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((alias (#name)))

#else
#error "Don't know how to generate symbol aliases with this compiler"
#endif

/* Rename all of the internal-but-global symbols with a _crypt_ prefix
   so that they do not interfere with other people's code when linking
   statically.  This is validated by test-symbols.sh.  */

#define comp_maskl               _crypt_comp_maskl
#define comp_maskr               _crypt_comp_maskr
#define crypt_bcrypt_rn          _crypt_crypt_bcrypt_rn
#define crypt_des_big_rn         _crypt_crypt_des_big_rn
#define crypt_des_trd_or_big_rn  _crypt_crypt_des_trd_or_big_rn
#define crypt_des_xbsd_rn        _crypt_crypt_des_xbsd_rn
#define crypt_md5_rn             _crypt_crypt_md5_rn
#define crypt_sha256_rn          _crypt_crypt_sha256_rn
#define crypt_sha512_rn          _crypt_crypt_sha512_rn
#define des_crypt_block          _crypt_des_crypt_block
#define des_set_key              _crypt_des_set_key
#define des_set_salt             _crypt_des_set_salt
#define fp_maskl                 _crypt_fp_maskl
#define fp_maskr                 _crypt_fp_maskr
#define gensalt_bcrypt_a_rn      _crypt_gensalt_bcrypt_a_rn
#define gensalt_bcrypt_b_rn      _crypt_gensalt_bcrypt_b_rn
#define gensalt_bcrypt_x_rn      _crypt_gensalt_bcrypt_x_rn
#define gensalt_bcrypt_y_rn      _crypt_gensalt_bcrypt_y_rn
#define gensalt_des_trd_rn       _crypt_gensalt_des_trd_rn
#define gensalt_des_xbsd_rn      _crypt_gensalt_des_xbsd_rn
#define gensalt_md5_rn           _crypt_gensalt_md5_rn
#define gensalt_sha256_rn        _crypt_gensalt_sha256_rn
#define gensalt_sha512_rn        _crypt_gensalt_sha512_rn
#define ip_maskl                 _crypt_ip_maskl
#define ip_maskr                 _crypt_ip_maskr
#define key_perm_maskl           _crypt_key_perm_maskl
#define key_perm_maskr           _crypt_key_perm_maskr
#define md5_finish_ctx           _crypt_md5_finish_ctx
#define md5_init_ctx             _crypt_md5_init_ctx
#define md5_process_bytes        _crypt_md5_process_bytes
#define m_sbox                   _crypt_m_sbox
#define psbox                    _crypt_psbox
#define sha256_finish_ctx        _crypt_sha256_finish_ctx
#define sha256_init_ctx          _crypt_sha256_init_ctx
#define sha256_process_bytes     _crypt_sha256_process_bytes
#define sha512_finish_ctx        _crypt_sha512_finish_ctx
#define sha512_init_ctx          _crypt_sha512_init_ctx
#define sha512_process_bytes     _crypt_sha512_process_bytes

#endif /* crypt-symbols.h */

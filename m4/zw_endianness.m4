dnl Written by Zack Weinberg <zackw at panix.com> in 2018.
dnl To the extent possible under law, Zack Weinberg has waived all
dnl copyright and related or neighboring rights to this work.
dnl
dnl See https://creativecommons.org/publicdomain/zero/1.0/ for further
dnl details.
dnl
dnl This macro is like AC_C_BIGENDIAN, but it doesn't try to determine
dnl a final value at configure time.  Instead, it probes for a set of
dnl headers and compile-time macros that may or may not be available,
dnl and uses them to guide preprocessor logic that makes the final
dnl determination.  This works better with MacOS "universal binaries",
dnl which may involve compiling the program twice under opposite
dnl endiannesses; no fixed byte-order macro is correct in that case,
dnl but the compiler's built-ins will be.  This approach is also
dnl friendlier to cross-compilation.
dnl
dnl This is the preprocessor logic that should be put in an appropriate
dnl location, after including config.h:
dnl
dnl #include <limits.h>
dnl #ifdef HAVE_ENDIAN_H
dnl #include <endian.h>
dnl #endif
dnl #ifdef HAVE_SYS_ENDIAN_H
dnl #include <sys/endian.h>
dnl #endif
dnl #ifdef HAVE_SYS_PARAM_H
dnl #include <sys/param.h>
dnl #endif
dnl
dnl #if ENDIANNESS_IS_BIG
dnl # define ENDIAN_BIG
dnl #elif ENDIANNESS_IS_LITTLE
dnl # define ENDIAN_LITTLE
dnl #elif ENDIANNESS_IS_PDP
dnl # define ENDIAN_PDP
dnl #else
dnl # error "Unable to determine byte order"
dnl #endif
dnl ------------------------------------------------

dnl There's no good way to implement this macro as a _shell_ loop, but we
dnl can reasonably implement it as an _m4_ loop that expands to a sequence
dnl of conditionals.  Actually two sequences of conditionals, one inside
dnl AC_CACHE_CHECK and one outside.

m4_define([zw_C_ENDIANNESS_options], [
[ [BYTE_ORDER and xxx_ENDIAN],
  [defined BYTE_ORDER && defined BIG_ENDIAN && defined LITTLE_ENDIAN && BIG_ENDIAN != LITTLE_ENDIAN],
  [BYTE_ORDER == BIG_ENDIAN],
  [BYTE_ORDER == LITTLE_ENDIAN],
  [BYTE_ORDER == PDP_ENDIAN],
],
[ [__BYTE_ORDER and __xxx_ENDIAN],
  [defined __BYTE_ORDER && defined __BIG_ENDIAN && defined __LITTLE_ENDIAN && __BIG_ENDIAN != __LITTLE_ENDIAN],
  [__BYTE_ORDER == __BIG_ENDIAN],
  [__BYTE_ORDER == __LITTLE_ENDIAN],
  [__BYTE_ORDER == __PDP_ENDIAN],
],
[ [__BYTE_ORDER__ and __xxx_ENDIAN__],
  [defined __BYTE_ORDER__ && defined __BIG_ENDIAN__ && defined __LITTLE_ENDIAN__ && __BIG_ENDIAN__ != __LITTLE_ENDIAN__],
  [__BYTE_ORDER__ == __BIG_ENDIAN__],
  [__BYTE_ORDER__ == __LITTLE_ENDIAN__],
  [__BYTE_ORDER__ == __PDP_ENDIAN__],
],
[ [__BYTE_ORDER__ and __ORDER_xxx_ENDIAN__],
  [defined __BYTE_ORDER__ && defined __ORDER_BIG_ENDIAN__ && defined __ORDER_LITTLE_ENDIAN__ && __ORDER_BIG_ENDIAN__ != __ORDER_LITTLE_ENDIAN__],
  [__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__],
  [__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__],
  [__BYTE_ORDER__ == __ORDER_PDP_ENDIAN__],
],
[ [_BIG_ENDIAN and _LITTLE_ENDIAN],
  [(defined _BIG_ENDIAN) != (defined _LITTLE_ENDIAN)],
  [defined _BIG_ENDIAN], [defined _LITTLE_ENDIAN], [0],
],
[ [__BIG_ENDIAN__ and __LITTLE_ENDIAN__],
  [(defined __BIG_ENDIAN__) != (defined __LITTLE_ENDIAN__)],
  [defined __BIG_ENDIAN__], [defined __LITTLE_ENDIAN__], [0],
],
[ [__ARMEB__ and __ARMEL__],
  [(defined __ARMEB__) != (defined __ARMEL__)],
  [defined __ARMEB__], [defined __ARMEL__], [0],
],
[ [__THUMBEB__ and __THUMBEL__],
  [(defined __THUMBEB__) != (defined __THUMBEL__)],
  [defined __THUMBEB__], [defined __THUMBEL__], [0],
],
[ [__AARCH64EB__ and __AARCH64EL__],
  [(defined __AARCH64EB__) != (defined __AARCH64EL__)],
  [defined __AARCH64EB__], [defined __AARCH64EL__], [0],
],
[ [__MIPSEB__ and __MIPSEL__],
  [(defined __MIPSEB__) != (defined __MIPSEL__)],
  [defined __MIPSEB__], [defined __MIPSEL__], [0],
],
[ [__MIPSEB and __MIPSEL],
  [(defined __MIPSEB) != (defined __MIPSEL)],
  [defined __MIPSEB], [defined __MIPSEL], [0],
],
[ [_MIPSEB and _MIPSEL],
  [(defined _MIPSEB) != (defined _MIPSEL)],
  [defined _MIPSEB], [defined _MIPSEL], [0],
]
])

m4_define([zw_C_ENDIANNESS_test_one], [
if test "$[]ac_cv_c_byte_order_macros" = unknown; then
  AC_PREPROC_IFELSE([AC_LANG_PROGRAM([[
#include <limits.h>
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if !($2)
#error fail
#endif
]])],
  [ac_cv_c_byte_order_macros="$1"])
fi])

m4_define([zw_C_ENDIANNESS_case_one],
  [["$1"], [
  zw_C_ENDIANNESS_IS_BIG="($3)"
  zw_C_ENDIANNESS_IS_LIT="($4)"
  zw_C_ENDIANNESS_IS_PDP="($5)"]])

AC_DEFUN([zw_C_ENDIANNESS], [
AC_REQUIRE([AC_PROG_CC])
AC_REQUIRE([AC_USE_SYSTEM_EXTENSIONS])
AC_CHECK_HEADERS_ONCE([endian.h sys/endian.h sys/param.h])
AC_CACHE_CHECK([for byte order macros],
  [ac_cv_c_byte_order_macros], [
  ac_cv_c_byte_order_macros=unknown
  m4_map([zw_C_ENDIANNESS_test_one], [zw_C_ENDIANNESS_options])])

AS_CASE([$ac_cv_c_byte_order_macros],
        m4_map_sep([zw_C_ENDIANNESS_case_one], [,], [zw_C_ENDIANNESS_options]),
        [AC_MSG_ERROR([unable to determine byte order at compile time])])

AC_DEFINE_UNQUOTED([ENDIANNESS_IS_BIG], [$zw_C_ENDIANNESS_IS_BIG],
  [Define as an @%:@if expression that is true when compiling for a big-endian CPU.])
AC_DEFINE_UNQUOTED([ENDIANNESS_IS_LITTLE], [$zw_C_ENDIANNESS_IS_LIT],
  [Define as an @%:@if expression that is true when compiling for a little-endian CPU.])
AC_DEFINE_UNQUOTED([ENDIANNESS_IS_PDP], [$zw_C_ENDIANNESS_IS_PDP],
  [Define as an @%:@if expression that is true when compiling for a PDP-endian CPU.])
])

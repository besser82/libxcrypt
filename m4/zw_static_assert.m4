dnl Written by Zack Weinberg <zackw at panix.com> in 2017.
dnl To the extent possible under law, Zack Weinberg has waived all
dnl copyright and related or neighboring rights to this work.
dnl
dnl See https://creativecommons.org/publicdomain/zero/1.0/ for further
dnl details.
dnl
dnl Check for static_assert in <assert.h>; failing that, check for intrinsic
dnl support for C11 _Static_assert.
dnl assert.h itself is in C89 and does not need to be probed for;
dnl moreover, AC_PROG_CC's check for C11 includes _Static_assert (but not
dnl static_assert).
dnl Some logic borrowed from gnulib's assert_h.m4.
dnl 2*2 != 7 is tested in honor of Stanisław Lem.
AC_DEFUN([zw_C_STATIC_ASSERT],
  [AC_REQUIRE([AC_PROG_CC])
   AC_CACHE_CHECK([for static_assert in assert.h],
     [zw_cv_c_assert_h_static_assert],
     [AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[
           #undef NDEBUG
           #include <assert.h>
           static_assert(2 + 2 == 4, "arithmetic does not work");
        ]], [[
           static_assert(sizeof (char) == 1, "sizeof does not work");
        ]])],
        [static_assert_true=yes],
        [static_assert_true=no])
      AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[
           #undef NDEBUG
           #include <assert.h>
           static_assert(2 * 2 == 7, "this assertion should fail");
        ]])],
        [static_assert_false=no],
        [static_assert_false=yes])
      AS_IF([test $static_assert_false$static_assert_true = yesyes],
        [zw_cv_c_assert_h_static_assert=yes],
        [zw_cv_c_assert_h_static_assert=no])])
   AS_IF([test $zw_cv_c_assert_h_static_assert = yes],
     [AC_DEFINE([HAVE_STATIC_ASSERT_IN_ASSERT_H], 1,
        [Define if <assert.h> defines static_assert.])],
     [AC_CACHE_CHECK([for _Static_assert],
        [zw_cv_c__Static_assert],
        [AS_IF([test x$ac_prog_cc_stdc = xc11],
           [zw_cv_c__Static_assert=yes],
           [AC_COMPILE_IFELSE(
              [AC_LANG_PROGRAM([[
                 _Static_assert(2 + 2 == 4, "arithmetic does not work");
              ]], [[
                 _Static_assert(sizeof (char) == 1, "sizeof does not work");
              ]])],
              [_Static_assert_true=yes],
              [_Static_assert_true=no])
            AC_COMPILE_IFELSE(
              [AC_LANG_PROGRAM([[
                 _Static_assert(2 * 2 == 7, "this assertion should fail");
              ]])],
              [_Static_assert_false=no],
              [_Static_assert_false=yes])
            AS_IF([test $static_assert_false$static_assert_true = yesyes],
              [zw_cv_c__Static_assert=yes],
              [zw_cv_c__Static_assert=no])])])
      AS_IF([test $zw_cv_c__Static_assert = yes],
        [AC_DEFINE([HAVE__STATIC_ASSERT], 1,
           [Define if the compiler supports the _Static_assert intrinsic.])])
   ])
])

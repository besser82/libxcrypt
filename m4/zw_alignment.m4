dnl Written by Zack Weinberg <zackw at panix.com> in 2017.
dnl To the extent possible under law, Zack Weinberg has waived all
dnl copyright and related or neighboring rights to this work.
dnl
dnl See https://creativecommons.org/publicdomain/zero/1.0/ for further
dnl details.
dnl
dnl Find out how to query and set data alignment.
dnl Currently knows about C11's _Alignas and _Alignof,
dnl and GCC's __attribute__ ((aligned)) and __alignof.
dnl
dnl Note: AC_PROG_CC_C11 includes a test for _Alignas and _Alignof,
dnl but not for <stdalign.h>, which we don't bother using anyway.
dnl
dnl Compatibility note: alignas (TYPE) does not work when alignas() is
dnl defined using __attribute__ ((aligned)).  Use alignas (alignof (TYPE))
dnl instead.
AC_DEFUN([zw_C_ALIGNAS],
  [AC_REQUIRE([AC_PROG_CC])
   AC_CACHE_CHECK([how to control data alignment], [zw_cv_c_alignas],
     [AS_IF([test x$ac_prog_cc_stdc = xc11],
        [zw_cv_c_alignas=_Alignas],
        [AC_COMPILE_IFELSE(
           [AC_LANG_PROGRAM([[
                int __attribute__((__aligned__(8))) global;
                struct __attribute__((__aligned__(8))) aggregate { int x, y; };
              ]], [[
                int __attribute__((__aligned__(8))) local;
              ]])],
           [zw_cv_c_alignas=__attribute__],
           [zw_cv_c_alignas=unknown])
        ])
     ])
   AS_IF([test x$zw_cv_c_alignas = x_Alignas],
            [zw_c_alignas_expr="_Alignas(n)"],
         [test x$zw_cv_c_alignas = x__attribute__],
            [zw_c_alignas_expr="__attribute__((__aligned__(n)))"],
         [AC_MSG_FAILURE([could not find a way to control data alignment])])
   AC_DEFINE_UNQUOTED([alignas(n)], [$zw_c_alignas_expr],
   [Define as a type specifier which sets the alignment of a variable or type
    to N bytes.  C11 alignas(TYPE) does not need to be supported.])
])

AC_DEFUN([zw_C_ALIGNOF],
  [AC_REQUIRE([AC_PROG_CC])
   AC_CACHE_CHECK([how to query data alignment], [zw_cv_c_alignof],
     [AS_IF([test x$ac_prog_cc_stdc = xc11],
        [zw_cv_c_alignof=_Alignof],
        [AC_COMPILE_IFELSE(
           [AC_LANG_PROGRAM([[
                struct agg { int x, y; };
                extern const char align_int[__alignof__(int)];
                extern const char align_agg[__alignof__(struct agg)];
              ]], [[
                double d;
                char align_var[__alignof__(d)];
              ]])],
           [zw_cv_c_alignof=__alignof__],
           [zw_cv_c_alignof=unknown])
        ])
     ])
   AS_IF([test x$zw_cv_c_alignof = x_Alignof],
            [zw_c_alignof_expr="_Alignof(thing)"],
         [test x$zw_cv_c_alignof = x__alignof__],
            [zw_c_alignof_expr="__alignof__(thing)"],
         [AC_MSG_FAILURE([could not find a way to query data alignment])])
   AC_DEFINE_UNQUOTED([alignof(thing)], [$zw_c_alignof_expr],
   [Define as an expression which evaluates to the alignment of THING.
    Must be computed at compile time (an "integer constant expression").])
])

AC_DEFUN([zw_C_MAX_ALIGN_T],
  [AC_REQUIRE([AC_PROG_CC])
   AC_REQUIRE([zw_C_ALIGNOF])
   AC_CACHE_CHECK([for max_align_t in stddef.h], [zw_cv_c_max_align_t],
     [AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[
            #include <stddef.h>
          ]], [[
            max_align_t var;
            return alignof(var);
          ]])],
        [zw_cv_c_max_align_t=yes],
        [zw_cv_c_max_align_t=no])
     ])
   AS_IF([test x$zw_cv_c_max_align_t = xyes],
     [AC_DEFINE([HAVE_MAX_ALIGN_T], 1,
        [Define if stddef.h provides max_align_t.])
   ])
])

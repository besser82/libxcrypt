dnl Written by Zack Weinberg <zackw at panix.com> in 2018.
dnl To the extent possible under law, Zack Weinberg has waived all
dnl copyright and related or neighboring rights to this work.
dnl
dnl See https://creativecommons.org/publicdomain/zero/1.0/ for further
dnl details.
dnl
dnl Find out whether ld --wrap is supported.
AC_DEFUN([zw_PROG_LD_WRAP],
  [AC_REQUIRE([AC_PROG_CC])
   AC_CACHE_CHECK([for ld --wrap], [zw_cv_prog_ld_wrap],
     [save_LDFLAGS="$LDFLAGS"
      save_LIBS="$LIBS"
      LDFLAGS=""
      LIBS=""
      AC_COMPILE_IFELSE(
        [AC_LANG_SOURCE([[
            extern void bar(void);
            void foo(void) { bar(); }
        ]])],
        [mv conftest.$OBJEXT conftest2.$OBJEXT
         LDFLAGS="-Wl,--wrap,bar"
         LIBS="conftest2.$OBJEXT"
         AC_LINK_IFELSE(
           [AC_LANG_PROGRAM([[
               extern void foo(void);
               void __wrap_bar(void) {}
            ]], [[
               foo();
            ]])],
           [zw_cv_prog_ld_wrap=yes],
           [zw_cv_prog_ld_wrap=no])
         rm -f conftest2.$OBJEXT
        ],
        [zw_cv_prog_ld_wrap=no])
      LDFLAGS="$save_LDFLAGS"
      LIBS="$save_LIBS"])
   if test x$zw_cv_prog_ld_wrap = xyes; then
      have_ld_wrap=yes
      AC_DEFINE([HAVE_LD_WRAP], 1,
                [Define to 1 if -Wl,--wrap,SYMBOL can be used to intercept
                 calls to SYMBOL at link time.])
   else
      have_ld_wrap=no
   fi
   AM_CONDITIONAL([HAVE_LD_WRAP], [test $have_ld_wrap = yes])
])

dnl Written by Zack Weinberg <zackw at panix.com> in 2021.
dnl To the extent possible under law, Zack Weinberg has waived all
dnl copyright and related or neighboring rights to this work.
dnl
dnl See https://creativecommons.org/publicdomain/zero/1.0/ for further
dnl details.
dnl
dnl Detect whether the active compiler compiles programs with ASan
dnl instrumentation.  If so, execute ACTIONS-IF-TRUE, otherwise
dnl ACTIONS-IF-FALSE.
dnl
dnl Implementation note: with clang one can use __has_feature(address_sanitizer)
dnl to detect ASan, but gcc does not support that.  Instead we look
dnl for ASan symbols in the linked executable.  This requires a helper
dnl macro shipped with libtool.
dnl
dnl zw_ASAN_IFELSE(actions-if-true[, actions-if-false])
AC_DEFUN([zw_ASAN_IFELSE],
  [AC_REQUIRE([AC_PROG_EGREP])]dnl
  [AC_REQUIRE([LT_PATH_NM])]dnl
  [AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
    [AS_IF([$NM conftest$EXEEXT | $EGREP _asan_ > /dev/null 2>&1],
           [$1], [$2])],
    [AC_MSG_ERROR([cannot link a trivial test program])])])

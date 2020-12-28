# zw_prog_perl.m4  -*- autoconf -*-
# serial 1
#
# inspired by, but shares no code with, ax_prog_perl_version.m4 by
# Franceso Salvestrini
#
# SYNOPSIS
#
#   zw_PROG_PERL([VERSION], [ACTION-IF-TRUE],
#                [ACTION-IF-FALSE = (error out)])
#
# DESCRIPTION
#
#   Locate a Perl interpreter, and then verify that its version number
#   is greater than or equal to VERSION.  If it is, set output variable
#   PERL to the absolute path of that interpreter, and execute
#   ACTION-IF-TRUE, if present.  Otherwise, execute ACTION-IF-FALSE.
#   If ACTION-IF-FALSE is not present it defaults to issuing an error
#   and stopping the configuration process.
#
# LICENSE
#
#   Copyright (c) 2020 Zack Weinberg <zackw@panix.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 13

AC_DEFUN([zw_PROG_PERL],
[AC_PATH_PROG([PERL], [perl])
AC_MSG_CHECKING([whether $PERL is version $1 or later])
_AS_ECHO_LOG([$PERL -e 'use v$1;'])
AS_IF(["$PERL" -e 'use v$1;' >&AS_MESSAGE_LOG_FD 2>&1],
  [AC_MSG_RESULT([yes])m4_ifnblank([$2], [
  $2])],
  [AC_MSG_RESULT([no])
m4_default([$3], [AC_MSG_ERROR([Perl version $1 or later is required])])])])

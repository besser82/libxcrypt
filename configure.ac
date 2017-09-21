# Process this file with autoconf to produce a configure script.
m4_include([m4/zw_automodern.m4])
AC_INIT([xcrypt],
        [3.2.0],
        [https://github.com/besser82/libxcrypt/issues],
        [libxcrypt],
        [https://github.com/besser82/libxcrypt])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_SRCDIR([crypt.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AM_INIT_AUTOMAKE

AH_TOP(
[#ifndef _CRYPT_CONFIG_H
#define _CRYPT_CONFIG_H 1])
AH_BOTTOM(
[#endif /* config.h */])

# Checks for programs.
AC_CANONICAL_HOST
AC_PROG_CC

# C99 language and library features are used unconditionally.
# Don't even try to build with an older compiler.
case "$ac_prog_cc_stdc" in
     c89 | no) AC_MSG_ERROR([a C99- or C11-compliant compiler is required]) ;;
esac

AC_PROG_CPP
AC_PROG_AWK
AC_PROG_MAKE_SET
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
zw_SIMPLE_ENABLE_WARNINGS
LT_INIT

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
zw_C_ALIGNAS
zw_C_ALIGNOF

# Checks for library functions.

# Configure options.

AC_ARG_ENABLE([obsolete-api],
    AS_HELP_STRING(
        [--disable-obsolete-api],
        [do not include compatibility definitions of obsolete APIs
         (fcrypt, encrypt, setkey) in the shared library.
         Breaks binary compatibility with glibc's libcrypt.
         Only affects existing binaries; new programs cannot be
         linked against these functions in any case.]
    ),
    [case "${enableval}" in
        yes) enable_obsolete_api=1 ;;
         no) enable_obsolete_api=0 ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-obsolete-api]) ;;
     esac],
     [enable_obsolete_api=1]
)

AC_ARG_ENABLE([weak-hashes],
    AS_HELP_STRING(
        [--disable-weak-hashes],
        [do not include any support for weak hashes (DES, MD5).
         Implies --disable-obsolete-api, and breaks binary compatibility
         with glibc's libcrypt.]
    ),
    [case "${enableval}" in
        yes) enable_weak_hashes=1 ;;
         no) enable_weak_hashes=0 ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-weak-hashes]) ;;
     esac],
     [enable_weak_hashes=1]
)

# If weak hashes are disabled, then the obsolete APIs won't work anyway
# (they're all DES-specific).
if test $enable_weak_hashes = 0; then enable_obsolete_api=0; fi

# The obsolete APIs are unconditionally excluded from the static library,
# so if we are not building the shared library, we are effectively not
# building obsolete APIs, and we shouldn't try to test them.
if test x$enable_shared != xyes; then enable_obsolete_api=0; fi

# Determine whether there's even a GNU libc on this system that we
# need to be binary backward compatible with.
SYMVER_FLOOR=none
if test $enable_obsolete_api = 1; then
  AC_MSG_CHECKING([minimum symbol version to use for compatibility symbols])
  case $host_os in
    *linux*)
      while read pattern version cond; do
        if test -z "$pattern" || test "x$pattern" = 'x#'; then
          continue
        fi
        if expr "$pattern" : "$host_cpu" > /dev/null; then
          if test -z "$cond"; then
            cond_matched=yes
          else
            AC_PREPROC_IFELSE([AC_LANG_SOURCE([[
#include <limits.h>
#if $cond
#error yes
#endif
            ]])],
            [cond_matched=no], [cond_matched=yes])
          fi
          if test $cond_matched = yes; then
            SYMVER_FLOOR="$version"
            break
          fi
        fi
      done < ${srcdir}/libcrypt.minver
    ;;

    *gnu*)
        # glibc exists for GNU Hurd, but it is unclear to me whether
        # it has a stable ABI yet.  For now, we are assuming not.
    ;;

    *)
        # Other host OSes do not use glibc, so there is no reason to
        # attempt to be binary compatible with it.
    ;;
  esac
  AC_MSG_RESULT([$SYMVER_FLOOR])
fi
if test x"$SYMVER_FLOOR" = xnone; then
  SYMVER_FLOOR=XCRYPT_2.0
  SYMVER_MIN=XCRYPT_2.0
  enable_obsolete_api=0
else
  SYMVER_MIN=GLIBC_2.0
fi
AC_SUBST([SYMVER_FLOOR])
AC_SUBST([SYMVER_MIN])

AC_DEFINE_UNQUOTED([SYMVER_FLOOR], [$SYMVER_FLOOR],
  [Define as the lowest compatibility symbol version that is actually
   included in libcrypt.so.])

AC_DEFINE_UNQUOTED([ENABLE_OBSOLETE_API], [$enable_obsolete_api],
 [Define as 1 if the obsolete APIs (fcrypt, encrypt, setkey)
  should be included, 0 otherwise.])
AM_CONDITIONAL([ENABLE_OBSOLETE_API], [test $enable_obsolete_api = 1])

AC_DEFINE_UNQUOTED([ENABLE_WEAK_HASHES], [$enable_weak_hashes],
 [Define as 1 if weak hashes (DES, MD5) should be included, 0 otherwise.
  If this is 0, ENABLE_OBSOLETE_API must also be 0.])
AM_CONDITIONAL([ENABLE_WEAK_HASHES], [test $enable_weak_hashes = 1])

# The Makefile needs to know if we are building the static library.
AM_CONDITIONAL([ENABLE_STATIC], [test $enable_static = yes])

AC_OUTPUT

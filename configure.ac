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
AC_PROG_CC

# C99 language and library features are used unconditionally.
# Don't even try to build with an older compiler.
case "$ac_prog_cc_stdc" in
     c89 | no) AC_MSG_ERROR([a C99- or C11-compliant compiler is required]) ;;
esac

AC_PROG_CPP
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
        [do not include obsolete APIs (bigcrypt, fcrypt, encrypt, setkey).
         Breaks binary compatibility.]
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
        [do not include support for weak hashes (DES, MD5).
         Implies --disable-obsolete-api and breaks binary compatibility.]
    ),
    [case "${enableval}" in
        yes) enable_weak_hashes=1 ;;
         no) enable_weak_hashes=0 ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-weak-hashes]) ;;
     esac],
     [enable_weak_hashes=1]
)

if test $enable_weak_hashes = 0; then enable_obsolete_api=0; fi

AC_DEFINE_UNQUOTED([ENABLE_OBSOLETE_API], [$enable_obsolete_api],
 [Define as 1 if the obsolete APIs (bigcrypt, fcrypt, encrypt, setkey)
  should be included, 0 otherwise.])
AM_CONDITIONAL([ENABLE_OBSOLETE_API], [test $enable_obsolete_api = 1])

AC_DEFINE_UNQUOTED([ENABLE_WEAK_HASHES], [$enable_weak_hashes],
 [Define as 1 if weak hashes (DES, MD5) should be included, 0 otherwise.
  If this is 0, ENABLE_OBSOLETE_API must also be 0.])
AM_CONDITIONAL([ENABLE_WEAK_HASHES],  [test $enable_weak_hashes = 1])

AC_OUTPUT

# Process this file with autoconf to produce a configure script.
m4_include([m4/zw_automodern.m4])
AC_INIT([xcrypt],
        [4.0.0],
        [https://github.com/besser82/libxcrypt/issues],
        [libxcrypt],
        [https://github.com/besser82/libxcrypt])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_SRCDIR([crypt.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  libxcrypt.pc
])
AM_INIT_AUTOMAKE

AH_TOP(
[#ifndef _CRYPT_CONFIG_H
#define _CRYPT_CONFIG_H 1])
AH_BOTTOM(
[#endif /* config.h */])

# Checks for programs.
AC_CANONICAL_HOST
AC_PROG_CC
AX_PROG_CC_FOR_BUILD

# Dependencies
PKG_PROG_PKG_CONFIG
PKG_INSTALLDIR

# C99 language and library features are used unconditionally.
# Don't even try to build with an older compiler.
case "$ac_prog_cc_stdc" in
     c89 | no) AC_MSG_ERROR([a C99- or C11-compliant compiler is required]) ;;
esac

AC_PROG_CPP
AC_PROG_AWK
AC_PROG_MAKE_SET
AC_PROG_LN_S
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
zw_SIMPLE_ENABLE_WARNINGS
LT_INIT

# Check for system's endianness
AC_C_BIGENDIAN(
   AC_DEFINE([IS_BIGENDIAN], 1,
    [Define to 1 if system's architecture is big-endian.]),
   AC_DEFINE([IS_BIGENDIAN], 0,
    [Define to 0 if system's architecture is little-endian.])
)

# One of the test scripts needs to use -dD.
AC_CACHE_CHECK([whether the preprocessor ($CPP) supports -dD],
  [ac_cv_prog_cc_dD],
  [printf '#include <errno.h>' |
    $CPP -dD -xc - > conftest.i 2>&AS_MESSAGE_LOG_FD
  if test $? -ne 0; then
    ac_cv_prog_cc_dD=no
  elif grep -q '#define EDOM' conftest.i; then
    ac_cv_prog_cc_dD=yes
  else
    ac_cv_prog_cc_dD=no
  fi
  rm -f conftest.i
])
AM_CONDITIONAL([HAVE_CPP_dD], [test $ac_cv_prog_cc_dD = yes])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS_ONCE(
  [fcntl.h stdbool.h sys/cdefs.h sys/random.h sys/syscall.h ucontext.h])

# stdint.h and inttypes.h were checked for by AC_INCLUDES_DEFAULT,
# invoked implicitly by the above.
if test $ac_cv_header_stdbool_h != yes ||
   test $ac_cv_header_stdint_h != yes ||
   test $ac_cv_header_inttypes_h != yes; then
   AC_MSG_ERROR([a C99- or C11-compliant runtime library is required])
fi

# Checks for the specific things that we need from sys/cdefs.h, which
# might or might not be there (there's no standard for this header).
AS_IF([test $ac_cv_header_sys_cdefs_h = yes],
  [AC_CACHE_CHECK([whether sys/cdefs.h defines __BEGIN_DECLS and __END_DECLS],
                 [ac_cv_header_sys_cdefs_begin_end_decls], [
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <sys/cdefs.h>
__BEGIN_DECLS
extern int foo(void);
__END_DECLS
    ]])],
    [ac_cv_header_sys_cdefs_begin_end_decls=yes],
    [ac_cv_header_sys_cdefs_begin_end_decls=no])
  ])
  AC_CACHE_CHECK([whether sys/cdefs.h defines __nonnull],
                 [ac_cv_header_sys_cdefs_nonnull], [
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <sys/cdefs.h>
extern char *foo(char *, char *) __nonnull ((1, 2));
    ]])],
    [ac_cv_header_sys_cdefs_nonnull=yes],
    [ac_cv_header_sys_cdefs_nonnull=no])
  ])
  AC_CACHE_CHECK([whether sys/cdefs.h defines __THROW],
                 [ac_cv_header_sys_cdefs_THROW], [
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <sys/cdefs.h>
extern void foo(void) __THROW;
    ]])],
    [ac_cv_header_sys_cdefs_THROW=yes],
    [ac_cv_header_sys_cdefs_THROW=no])
  ])],
dnl AS_IF else
 [ac_cv_header_sys_cdefs_begin_end_decls=no
  ac_cv_header_sys_cdefs_nonnull=no
  ac_cv_header_sys_cdefs_THROW=no])

if test $ac_cv_header_sys_cdefs_begin_end_decls = yes; then
  AC_DEFINE([HAVE_SYS_CDEFS_BEGIN_END_DECLS], 1,
    [Define if <sys/cdefs.h> defines __BEGIN_DECLS and __END_DECLS.])
fi
if test $ac_cv_header_sys_cdefs_nonnull = yes; then
  AC_DEFINE([HAVE_SYS_CDEFS_NONNULL], 1,
    [Define if <sys/cdefs.h> defines __nonnull.])
fi
if test $ac_cv_header_sys_cdefs_THROW = yes; then
  AC_DEFINE([HAVE_SYS_CDEFS_THROW], 1,
    [Define if <sys/cdefs.h> defines __THROW.])
fi

# Checks for typedefs, structures, and compiler characteristics.
zw_C_ALIGNAS
zw_C_ALIGNOF
zw_C_MAX_ALIGN_T
zw_C_STATIC_ASSERT

# Checks for library functions.
AC_CHECK_FUNCS_ONCE([
  arc4random_buf
  explicit_bzero
  explicit_memset
  getentropy
  getrandom
  memset_s
  syscall
])

# The ucontext.h functions that we use were withdrawn from
# POSIX.1-2008, so the existence of the header does not prove
# we can use the functions.
AS_IF([test $ac_cv_header_ucontext_h = yes],
  [AC_CACHE_CHECK([whether all ucontext.h functions are available],
     [ac_cv_header_ucontext_h_fns_available],
     [AC_LINK_IFELSE([AC_LANG_PROGRAM([[
// This code isn't intended to make sense; it just validates the
// type signature of all four context functions, and avoids tripping
// any of the many warnings we may have active.
#include <ucontext.h>
static int x;
static void fn1(void) {}
static void fn2(int a, int b) { x = a - b; }
]], [[
  ucontext_t uc1, uc2;
  if (getcontext(&uc1)) return 1;
  if (setcontext(&uc1)) return 1;
  makecontext(&uc1, fn1, 0);
  makecontext(&uc2, fn2, 2, 1, 1);
  if (swapcontext(&uc1, &uc2)) return 1;
  return x;
]])],
        [ac_cv_header_ucontext_h_fns_available=yes],
        [ac_cv_header_ucontext_h_fns_available=no])])],
  [ac_cv_header_ucontext_h_fns_available=no])

if test $ac_cv_header_ucontext_h_fns_available = yes; then
  AC_DEFINE([USE_SWAPCONTEXT], 1,
    [Define to 1 if getcontext, setcontext, makecontext, and swapcontext are
     available from ucontext.h without deprecation warnings.])
fi

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
        if expr "$host_cpu" : "$pattern" > /dev/null; then
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

# The Makefile needs to know which versions of the library we are building.
AM_CONDITIONAL([ENABLE_STATIC], [test $enable_static = yes])
AM_CONDITIONAL([ENABLE_SHARED], [test $enable_shared = yes])

# The Makefile needs to know if we are cross-compiling.
AM_CONDITIONAL([CROSS_COMPILING], [test $cross_compiling = yes])

AC_OUTPUT

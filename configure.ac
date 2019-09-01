# Process this file with autoconf to produce a configure script.
m4_include([m4/zw_automodern.m4])
AC_INIT([xcrypt],
        [4.4.8],
        [https://github.com/besser82/libxcrypt/issues],
        [libxcrypt],
        [https://github.com/besser82/libxcrypt])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_SRCDIR([lib/crypt.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  crypt.h.in:lib/crypt.h.in.in
  libxcrypt.pc:lib/libxcrypt.pc.in
])
AM_INIT_AUTOMAKE([tar-v7])

AH_TOP(
[#ifndef _CRYPT_CONFIG_H
#define _CRYPT_CONFIG_H 1])
AH_BOTTOM(
[#endif /* config.h */])

# PKG_INSTALLDIR may not be defined, but we have a
# compatibility replacement.
m4_pattern_allow([PKG_INSTALLDIR])

# Checks for programs.
AC_CANONICAL_HOST
AC_PROG_CC

# Dependencies
PKG_PROG_PKG_CONFIG
if $PKG_CONFIG --atleast-pkgconfig-version 0.27; then
  PKG_INSTALLDIR
else
  PKG_INSTALLDIR_COMPAT
fi

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
AX_PTHREAD
# Automake+Libtool don't support PTHREAD_CC being used for some but
# not all programs.
if test x"$PTHREAD_CC" != x"$CC"; then
  AC_MSG_ERROR([PTHREAD_CC different from CC is not supported, due to Automake limitations])
fi

# Checks for header files.
AC_CHECK_HEADERS_ONCE(
  [fcntl.h stdbool.h sys/cdefs.h sys/random.h sys/syscall.h])

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
  ac_cv_header_sys_cdefs_THROW=no])

if test $ac_cv_header_sys_cdefs_begin_end_decls = yes; then
  AC_DEFINE([HAVE_SYS_CDEFS_BEGIN_END_DECLS], 1,
    [Define if <sys/cdefs.h> defines __BEGIN_DECLS and __END_DECLS.])
fi
if test $ac_cv_header_sys_cdefs_THROW = yes; then
  AC_DEFINE([HAVE_SYS_CDEFS_THROW], 1,
    [Define if <sys/cdefs.h> defines __THROW.])
fi

# Checks for typedefs, structures, and compiler characteristics.
zw_C_ALIGNAS
zw_C_ALIGNOF
zw_C_MAX_ALIGN_T
zw_C_ENDIANNESS
zw_C_STATIC_ASSERT
zw_PROG_LD_WRAP
AX_CHECK_VSCRIPT

# FIXME: This only checks whether the linker accepts either
# -Wl,-z,defs or -Wl,--no-undefined.  It doesn't check that the switch
# actually does what we want it to do.
AC_CACHE_CHECK([how to make linking fail when undefined symbols remain],
  [ac_cv_ld_no_undefined], [
  ac_cv_ld_no_undefined=unknown
  SAVED_LDFLAGS="$LDFLAGS"
  LDFLAGS="$SAVED_LDFLAGS -Wl,-z,defs"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([], [int i = 1;])],
    [ac_cv_ld_no_undefined=-Wl,-z,defs])
  if test "x$ac_cv_ld_no_undefined" = xunknown; then
    LDFLAGS="$SAVED_LDFLAGS -Wl,--no-undefined"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([], [int i = 1;])],
      [ac_cv_ld_no_undefined=-Wl,--no-undefined])
  fi
  LDFLAGS="$SAVED_LDFLAGS"])

UNDEF_FLAG=
if test "x$ac_cv_ld_no_undefined" != xunknown; then
  UNDEF_FLAG="$ac_cv_ld_no_undefined"
fi
AC_SUBST([UNDEF_FLAG])

# FIXME: This only checks whether the linker accepts -Wl,-z,text.
# It doesn't check that the switch actually does what we want it to do.
AC_CACHE_CHECK([how to make linking fail when there are text relocations],
  [ac_cv_ld_no_textrel], [
  ac_cv_ld_no_textrel=unknown
  SAVED_LDFLAGS="$LDFLAGS"
  LDFLAGS="$SAVED_LDFLAGS -Wl,-z,text"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([], [int i = 1;])],
    [ac_cv_ld_no_textrel=-Wl,-z,text])
  LDFLAGS="$SAVED_LDFLAGS"])

TEXT_RELOC_FLAG=
if test "x$ac_cv_ld_no_textrel" != xunknown; then
  TEXT_RELOC_FLAG="$ac_cv_ld_no_textrel"
fi
AC_SUBST([TEXT_RELOC_FLAG])

# FIXME: This only checks whether the linker accepts -Wl,-z,relro.
# It doesn't check that the switch actually does what we want it to do.
AC_CACHE_CHECK([how to link with read-only relocations],
  [ac_cv_ld_relro], [
  ac_cv_ld_relro=unknown
  SAVED_LDFLAGS="$LDFLAGS"
  LDFLAGS="$SAVED_LDFLAGS -Wl,-z,relro"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([], [int i = 1;])],
    [ac_cv_ld_relro=-Wl,-z,relro])
  LDFLAGS="$SAVED_LDFLAGS"])

RELRO_FLAG=
if test "x$ac_cv_ld_relro" != xunknown; then
  RELRO_FLAG="$ac_cv_ld_relro"
fi
AC_SUBST([RELRO_FLAG])

# FIXME: This only checks whether the linker accepts -Wl,-z,now.
# It doesn't check that the switch actually does what we want it to do.
AC_CACHE_CHECK([how to link with immediate binding],
  [ac_cv_ld_now], [
  ac_cv_ld_now=unknown
  SAVED_LDFLAGS="$LDFLAGS"
  LDFLAGS="$SAVED_LDFLAGS -Wl,-z,now"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([], [int i = 1;])],
    [ac_cv_ld_now=-Wl,-z,now])
  LDFLAGS="$SAVED_LDFLAGS"])

BINDNOW_FLAG=
if test "x$ac_cv_ld_now" != xunknown; then
  BINDNOW_FLAG="$ac_cv_ld_now"
fi
AC_SUBST([BINDNOW_FLAG])

# FIXME: This only checks whether the compiler accepts -fno-plt.
# It doesn't check that the switch actually does what we want it to do.
AX_APPEND_COMPILE_FLAGS([-fno-plt], [OPTI_FLAGS])

# Export compiler flags for optimization.
AC_SUBST([OPTI_FLAGS])

# Checks for library functions.
AC_CHECK_FUNCS_ONCE([
  arc4random_buf
  explicit_bzero
  explicit_memset
  getentropy
  getrandom
  memset_s
  open64
  syscall
])

# Disable valgrind tools for checking multithreaded
# programs, as we don't use them in checks.
AX_VALGRIND_DFLT([drd], [off])
AX_VALGRIND_DFLT([helgrind], [off])

# Valgrind's sgcheck is b0rk3n upstream.
AX_VALGRIND_DFLT([sgcheck], [off])

# Add a target to run testsuite with valgrind.
AX_VALGRIND_CHECK()

# Requirements for running test-crypt-kat-gen.py.
ENABLE_CRYPT_KAT_GEN="no"

# Construct PYTHON_CANDIDATE_VERSIONS from most recent version to
# the minimum version required, ending up with a string containing:
#   "... python3.7 python3.6 python3 python".
# This way we just need one call to AC_PATH_PROGS to likely get a
# suitable version of Python.  The version check afterwards is for
# the case just a generic 'python3' or 'python' executable was found.
PYTHON_CANDIDATE_VERSIONS="python3 python"

for ver in `seq 6 1 10`; do
  PYTHON_CANDIDATE_VERSIONS="python3.$ver $PYTHON_CANDIDATE_VERSIONS"
done

AC_PATH_PROGS([PYTHON], [$PYTHON_CANDIDATE_VERSIONS], [])

if test x"$PYTHON" != "x"; then
  AX_PROG_PYTHON_VERSION([3.6], [ENABLE_CRYPT_KAT_GEN="yes"],
    [AC_MSG_WARN([Python >= 3.6 is required for optional Makefile targets.])
  ])

  if test x"$ENABLE_CRYPT_KAT_GEN" = "xyes"; then
    AX_PYTHON_MODULE([passlib], [], [$PYTHON])
    if test x"$HAVE_PYMOD_PASSLIB" = "xno"; then
      ENABLE_CRYPT_KAT_GEN="no"
    fi
  fi
fi

if test x"$ENABLE_CRYPT_KAT_GEN" = "xno"; then
  AC_MSG_WARN(
    [Disabling the "regen-test-crypt-kat" target, missing Python requirements.])
fi
AM_CONDITIONAL([ENABLE_CRYPT_KAT_GEN], [test x"$ENABLE_CRYPT_KAT_GEN" = "xyes"])

# Configure options.
AC_ARG_ENABLE([failure-tokens],
    AS_HELP_STRING(
        [--disable-failure-tokens],
        [Make crypt and crypt_r return NULL on failure, instead of a
         special "failure token" string that isn't the hash of any
         passphrase.  This matches the behavior of several other
         crypt implementations, but will break programs that assume these
         functions never return NULL.  crypt_rn and crypt_ra are not affected
         by this option, and will always return NULL on failure.]
    ),
    [case "$enableval" in
      yes) enable_failure_tokens=1;;
       no) enable_failure_tokens=0;;
        *) AC_MSG_ERROR([bad value ${enableval} for --enable-failure-tokens]);;
     esac],
    [enable_failure_tokens=1])
AC_DEFINE_UNQUOTED([ENABLE_FAILURE_TOKENS], [$enable_failure_tokens],
  [Define to 1 if crypt and crypt_r should return a "failure token" on
   failure, or 0 if they should return NULL.])

AC_ARG_ENABLE([xcrypt-compat-files],
    AS_HELP_STRING(
        [--disable-xcrypt-compat-files],
        [Disable the installation of the <xcrypt.h> header file and the
         libxcrypt.{a,so} compatibility symlinks.]
    ),
    [case "$enableval" in
      yes) enable_xcrypt_compat_files=1;;
       no) enable_xcrypt_compat_files=0;;
        *) AC_MSG_ERROR([bad value ${enableval} for --enable-xcrypt-compat-files]);;
     esac],
    [enable_xcrypt_compat_files=1])
AM_CONDITIONAL([ENABLE_XCRYPT_COMPAT_FILES], [test x"$enable_xcrypt_compat_files" = x1])

AC_ARG_ENABLE([obsolete-api],
    AS_HELP_STRING(
        [--enable-obsolete-api[=ARG]],
        [When set to "yes", include all compatibility interfaces.
         When set to "alt", include interfaces for compatibility with ALT.
         When set to "glibc", include interfaces for compatibility with glibc.
         When set to "owl", include interfaces for compatibility with Owl.
         When set to "suse", include interfaces for compatibility with SUSE.
         When set to "no", do not include any compatibility definitions at all,
         and change the soname of the installed library to libcrypt.so.2.
         This setting only affects existing binaries; new programs cannot
         be linked against the obsolete APIs (bigcrypt, fcrypt, encrypt, setkey)
         in any case. [default=yes]]
    ),
    [enableval="`AS_ECHO("$enableval") |
       $SED -e 'y!ABCDEFGHIJKLMNOPQRSTUVWXYZ-!abcdefghijklmnopqrstuvwxyz_!'`"
     case "${enableval}" in
        alt|glibc|owl)
            enable_obsolete_api=1
            enable_compat_suse=0
            COMPAT_ABI=${enableval} ;;
        yes|suse)
            enable_obsolete_api=1
            enable_compat_suse=1
            COMPAT_ABI=${enableval} ;;
         no)
            enable_obsolete_api=0
            enable_compat_suse=0
            COMPAT_ABI=${enableval} ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-obsolete-api]) ;;
     esac],
     [enable_obsolete_api=1
      enable_compat_suse=1
      COMPAT_ABI=yes]
)
AC_SUBST(COMPAT_ABI)

AC_ARG_ENABLE([obsolete-api-enosys],
    AS_HELP_STRING(
        [--enable-obsolete-api-enosys[=ARG]],
        [If set to "yes", this option replaces the obsolete APIs
         (fcrypt, encrypt{,_r}, and setkey{,_r}) with stubs that
         set errno to ENOSYS and return without performing any real
         operations.  This allows one to disable descrypt support
         while preserving POSIX compliance.  For security reasons,
         the encrypt{,r} functions will also overwrite their data-block
         argument with random bits.  The fcrypt function will always
         produce a failure token (*0 or *1), unless the library was
         also configured with --disable-failure-tokens, in which case
         it will always return NULL. [default=no]]
    ),
    [case "$enableval" in
      yes) enable_obsolete_api_enosys=1;;
       no) enable_obsolete_api_enosys=0;;
        *) AC_MSG_ERROR([bad value ${enableval} for --enable-obsolete-api-enosys]);;
     esac],
    [enable_obsolete_api_enosys=0])

AC_ARG_ENABLE([hashes],
    AS_HELP_STRING(
        [--enable-hashes=HASHES],
        [Select hash methods to support.  Acceptable values are
         'all' or a comma-separated list of names from the file
         'hashes.lst' and/or the keywords 'strong', 'alt',
         'fedora', 'freebsd', 'glibc', 'netbsd', 'openbsd',
         'osx', 'owl', 'solaris', and 'suse' which select groups
         of methods as described in that file.
         The default is 'all'.
         Note: if binary compatibility with any historic libcrypt is
         desired (i.e. any --enable-obsolete-api setting other than
         'no'), the 'descrypt' hash must be enabled.]),
    [hashes_selected="`AS_ECHO("$enableval") |
      $SED -e 'y!ABCDEFGHIJKLMNOPQRSTUVWXYZ-!abcdefghijklmnopqrstuvwxyz_!'`"],
    [hashes_selected=all]
)
# This code must run after AC_PROG_AWK.
hashes_enabled=$(
    $AWK -f ${srcdir}/lib/sel-hashes.awk \
         -v SELECTED_HASHES="$hashes_selected" \
            ${srcdir}/lib/hashes.lst
)
if test x"$hashes_enabled" = x || test x"$hashes_enabled" = x,; then
    AC_MSG_ERROR([bad value '${hashes_selected}' for --enable-hashes])
fi
AC_SUBST([hashes_enabled])


# If the traditional DES hash is disabled, then the obsolete APIs are
# implicitly disabled, except when stubs are requested.
case "$hashes_enabled" in
    *,descrypt,*) ;;
    *)
       if test x"$COMPAT_ABI" != xno && \
          test x"$enable_obsolete_api_enosys" != x1; then
         AC_MSG_WARN(
           [--enable-hashes=${hashes_selected} forces --enable-obsolete-api=no])
         enable_obsolete_api=0
         enable_compat_suse=0
         COMPAT_ABI=no
       fi
       ;;
esac

# If the obsolete APIs are disabled, the stubs implicitly disabled as well.
if test x"$COMPAT_ABI" = xno && test x"$enable_obsolete_api_enosys" = x1; then
  AC_MSG_WARN(
    [--enable-obsolete-api=no implies --enable-obsolete-api-enosys=no.])
  enable_obsolete_api_enosys=0
fi

# Export the value for ENABLE_OBSOLETE_API_ENOSYS.
AC_DEFINE_UNQUOTED([ENABLE_OBSOLETE_API_ENOSYS], [$enable_obsolete_api_enosys],
  [Define to 1 if fcrypt, encrypt{,_r}, setkey{,_r} should set errno to ENOSYS,
   or 0 if they should perform real operations.])

# The obsolete APIs are unconditionally excluded from the static library,
# so if we are not building the shared library, we are effectively not
# building obsolete APIs, and we shouldn't try to test them.
if test x$enable_shared != xyes; then enable_obsolete_api=0; fi

# Determine whether there's even a GNU libc on this system that we
# need to be binary backward compatible with.
MINVER_OS=no
SYMVER_FLOOR=none
if test $enable_obsolete_api = 1; then
  AC_MSG_CHECKING([minimum symbol version to use for compatibility symbols])
  case $host_os in
    *gnu*)
      # GNU Systems use glibc
      case $host_os in
        *linux*)
          MINVER_OS=linux
          ;;
        kfreebsd-gnu*)
          MINVER_OS=kfreebsd
          ;;
        gnu*)
          MINVER_OS=hurd
          ;;
        *)
          ;;
      esac

      if test $MINVER_OS != no ; then
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
        done < ${srcdir}/lib/libcrypt.minver.$MINVER_OS
      fi
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
AC_SUBST([MINVER_OS])
AC_SUBST([SYMVER_FLOOR])
AC_SUBST([SYMVER_MIN])

AC_DEFINE_UNQUOTED([SYMVER_FLOOR], [$SYMVER_FLOOR],
  [Define as the lowest compatibility symbol version that is actually
   included in libcrypt.so.])

AC_DEFINE_UNQUOTED([ENABLE_OBSOLETE_API], [$enable_obsolete_api],
 [Define as 1 if the obsolete APIs (fcrypt, encrypt, setkey)
  should be included, 0 otherwise.])
AM_CONDITIONAL([ENABLE_OBSOLETE_API], [test $enable_obsolete_api = 1])
AM_CONDITIONAL([ENABLE_COMPAT_SUSE], [test $enable_compat_suse = 1])

# The Makefile needs to know which versions of the library we are building.
AM_CONDITIONAL([ENABLE_STATIC], [test $enable_static = yes])
AM_CONDITIONAL([ENABLE_SHARED], [test $enable_shared = yes])

# The Makefile needs to know if we are cross-compiling.
AM_CONDITIONAL([CROSS_COMPILING], [test $cross_compiling = yes])

XCRYPT_VERSION_MAJOR=$(
    echo $PACKAGE_VERSION | $AWK -F. '{ print $1 }'
)
AC_SUBST([XCRYPT_VERSION_MAJOR])
XCRYPT_VERSION_MINOR=$(
    echo $PACKAGE_VERSION | $AWK -F. '{ print $2 }'
)
AC_SUBST([XCRYPT_VERSION_MINOR])

AC_OUTPUT

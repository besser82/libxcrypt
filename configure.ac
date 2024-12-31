# Process this file with autoconf to produce a configure script.
m4_include([build-aux/m4/zw_automodern.m4])
AC_INIT([xcrypt],
        [4.4.38],
        [https://github.com/besser82/libxcrypt/issues],
        [libxcrypt],
        [https://github.com/besser82/libxcrypt])
AC_CONFIG_MACRO_DIR([build-aux/m4])
AC_CONFIG_AUX_DIR([build-aux/m4-autogen])
AC_CONFIG_SRCDIR([lib/crypt.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
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
PKG_PROG_PKG_CONFIG_COMPAT([0.27], [PKG_CONFIG=false])
AS_IF([test x"$PKG_CONFIG" != xfalse],
  [PKG_INSTALLDIR],
  [PKG_INSTALLDIR_COMPAT])

# Checks for programs.
AC_CANONICAL_HOST
AC_PROG_CC

# C99 language and library features are used unconditionally.
# Don't even try to build with an older compiler.
case "$ac_prog_cc_stdc" in
     c89 | no) AC_MSG_ERROR([a C99- or C11-compliant compiler is required]) ;;
esac

AC_PROG_CPP
AC_PROG_MAKE_SET
AC_PROG_LN_S
zw_PROG_PERL([5.14.0])
AC_PATH_PROG([GPG2], [gpg2], [false])
AC_PATH_PROG([SHA256SUM], [sha256sum], [false])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
zw_SIMPLE_ENABLE_WARNINGS
LT_INIT

# The test scripts need to know whether C global symbols have a
# leading underscore.
LT_SYS_SYMBOL_USCORE
if test x$sys_symbol_underscore = xno; then
  SYMBOL_PREFIX=
else
  SYMBOL_PREFIX=_
fi
AC_SUBST([SYMBOL_PREFIX])

# One of the test scripts needs to use -dD.
AC_CACHE_CHECK([whether the preprocessor ($CPP) supports -dD],
  [ac_cv_prog_cpp_dD],
  [printf '#include <errno.h>' |
    $CPP -dD -xc - > conftest.i 2>&AS_MESSAGE_LOG_FD
  if test $? -ne 0; then
    ac_cv_prog_cpp_dD=no
  elif grep '#define EDOM' conftest.i > /dev/null 2>&1; then
    ac_cv_prog_cpp_dD=yes
  else
    ac_cv_prog_cpp_dD=no
  fi
  rm -f conftest.i
])
AC_SUBST([HAVE_CPP_dD], [$ac_cv_prog_cpp_dD])

# Some of the tests need to be conditionally compiled depending on
# whether ASan is active.
AC_CACHE_CHECK([whether we are compiling with ASan],
  [ac_cv_c_address_sanitizer],
  [zw_ASAN_IFELSE(
    [ac_cv_c_address_sanitizer=yes],
    [ac_cv_c_address_sanitizer=no])])
if test x$ac_cv_c_address_sanitizer = xyes; then
  AC_DEFINE([XCRYPT_USE_ASAN], [1],
    [Define when compiling with ASan.  Only affects tests.])
fi

# Checks for libraries: currently none needed.

# Checks for header files.
AC_CHECK_HEADERS_ONCE([
  fcntl.h
  stdbool.h
  ucontext.h
  sys/cdefs.h
  sys/random.h
  sys/syscall.h
  valgrind/valgrind.h
])

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
AX_GCC_FUNC_ATTRIBUTE(symver)

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

# Requirements for running test/ka-table-gen.py.
AC_CACHE_CHECK([for Python 3.>=6 with Passlib],
  [ac_cv_path_python3_passlib],
  [AC_PATH_PROGS_FEATURE_CHECK([python3_passlib],
     [python3 m4_for([minor], 11, 6, -1, [[python3.]minor ]) python],
     [_AS_ECHO_LOG([trying $ac_path_python3_passlib...])
AS_IF([$ac_path_python3_passlib -c '
import sys
if sys.version_info < (3,6,0):
    sys.stderr.write("too old: " + sys.version + "\n")
    sys.exit(1)
import passlib
' >&AS_MESSAGE_LOG_FD 2>&1],
        [ac_cv_path_python3_passlib=$ac_path_python3_passlib
         ac_path_python3_passlib_found=:])],
     [ac_cv_path_python3_passlib="not found"])])
if test x"$ac_cv_path_python3_passlib" = x"not found"; then
  PYTHON=false
  AC_MSG_NOTICE(
    [Disabling the "regen-ka-table" target, missing Python requirements.])
else
  PYTHON="$ac_cv_path_python3_passlib"
fi
AC_SUBST([PYTHON])
AM_CONDITIONAL([ENABLE_KA_TABLE_GEN], [test x"$PYTHON" != "xfalse"])

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
]], [[
  ucontext_t uc1, uc2;
  if (getcontext(&uc1)) return 1;
  if (setcontext(&uc1)) return 1;
  makecontext(&uc1, fn1, 0);
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
         'hashes.conf' and/or the keywords 'strong', 'alt',
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
# This code must run after $PERL is set.
hashes_enabled=$(
    $PERL "$srcdir"/build-aux/scripts/expand-selected-hashes \
          "$srcdir"/lib/hashes.conf \
          "$hashes_selected"
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
if test $enable_obsolete_api = 1; then
  AC_MSG_CHECKING([minimum symbol version to use for compatibility symbols])
  SYMVER_FLOOR=$(
    export CC
    $PERL "$srcdir"/build-aux/scripts/compute-symver-floor \
      "$srcdir"/lib/libcrypt.minver $host_os $host_cpu \
    2>&AS_MESSAGE_LOG_FD
  )
  AC_MSG_RESULT([$SYMVER_FLOOR])
  case "$SYMVER_FLOOR" in
    '')
      AC_MSG_ERROR([compute-symver-floor failed, see config.log for details])
    ;;
    ERROR)
      AC_MSG_ERROR([libxcrypt port to $host is incomplete])
    ;;
    XCRYPT_2.0)
      SYMVER_MIN=XCRYPT_2.0
      enable_obsolete_api=0
      enable_obsolete_api_enosys=0
      enable_compat_suse=0
      COMPAT_API=no
    ;;
    *)
      SYMVER_MIN=GLIBC_2.0
    ;;
  esac
else
  SYMVER_FLOOR=XCRYPT_2.0
  SYMVER_MIN=XCRYPT_2.0
fi
AC_SUBST([SYMVER_FLOOR])
AC_SUBST([SYMVER_MIN])

# If symbol versioning is disabled for any reason, we should not rely on
# versioned symbols in the testsuite.
have_symver=0
if test x$ax_check_vscript_flag != x; then have_symver=1; fi

AC_DEFINE_UNQUOTED([HAVE_SYMVER], [$have_symver],
  [Define as 1 if symbol versioning is enabled and applied.])

# If we are not building the obsolete APIs then we shouldn't install
# xcrypt.h or the compatibility symlinks either.
if test $enable_obsolete_api = 0; then enable_xcrypt_compat_files=0; fi

AC_DEFINE_UNQUOTED([SYMVER_FLOOR], [$SYMVER_FLOOR],
  [Define as the lowest compatibility symbol version that is actually
   included in libcrypt.so.])

AC_DEFINE_UNQUOTED([ENABLE_OBSOLETE_API], [$enable_obsolete_api],
 [Define as 1 if the obsolete APIs (fcrypt, encrypt, setkey)
  should be included, 0 otherwise.])

AM_CONDITIONAL([ENABLE_OBSOLETE_API], [test $enable_obsolete_api = 1])
AM_CONDITIONAL([ENABLE_COMPAT_SUSE], [test $enable_compat_suse = 1])
AM_CONDITIONAL([ENABLE_XCRYPT_COMPAT_FILES],
               [test $enable_xcrypt_compat_files = 1])

# The Makefile needs to know which versions of the library we are building.
AM_CONDITIONAL([ENABLE_STATIC], [test $enable_static = yes])
AM_CONDITIONAL([ENABLE_SHARED], [test $enable_shared = yes])

# The Makefile needs to know if we are cross-compiling.
AM_CONDITIONAL([CROSS_COMPILING], [test $cross_compiling = yes])

XCRYPT_VERSION_MAJOR=`echo $PACKAGE_VERSION | cut -d. -f1`
AC_SUBST([XCRYPT_VERSION_MAJOR])

XCRYPT_VERSION_MINOR=`echo $PACKAGE_VERSION | cut -d. -f2`
AC_SUBST([XCRYPT_VERSION_MINOR])

AC_OUTPUT

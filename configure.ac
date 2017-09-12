# Process this file with autoconf to produce a configure script.
m4_include([m4/zw_automodern.m4])
AC_INIT([xcrypt],
        [3.2.0],
        [https://github.com/besser82/libxcrypt/issues],
        [libxcrypt],
        [https://github.com/besser82/libxcrypt])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_SRCDIR([src/crypt.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
LT_INIT

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_ALLOCA

# Configure options.
zw_SIMPLE_ENABLE_WARNINGS

AC_OUTPUT

# Process this file with autoconf to produce a configure script.
AC_INIT([xcrypt],
        [3.1.0],
        [https://github.com/besser82/libxcrypt/issues],
        [libxcrypt],
        [https://github.com/besser82/libxcrypt])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/xcrypt.h])
AC_CONFIG_HEADERS([config.h])
AC_PREFIX_DEFAULT(/usr)

test "${prefix}" = "NONE" && prefix="/usr"
if test ${prefix} = '/usr'
then
        if test ${libdir} = '${exec_prefix}/lib'
        then
                case "`uname -m`" in
                    x86_64|ppc64|s390x|sparc64)
                        libdir="/lib64" ;;
                    *)
                        libdir="/lib" ;;
                esac
        fi
fi

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AS
AC_PROG_MAKE_SET
LT_INIT
AC_SYS_LARGEFILE

EXTRA_CFLAGS=""
if eval "test x$GCC = xyes"; then
    EXTRA_CFLAGS="-W -Wall -Wextra -Wbad-function-cast -Wcast-align -Wcast-qual -Winline -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wshadow -Wstrict-prototypes -Wundef -Wpointer-arith -Werror"
fi
AC_SUBST(EXTRA_CFLAGS)

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([limits.h stdint.h stdlib.h string.h sys/param.h sys/time.h])
AC_CHECK_HEADERS([bits/libc-lock.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([memchr memset strcspn strdup])

# Configure options.
AC_ARG_ENABLE(
    [bootstrap],
    AS_HELP_STRING(
        [--enable-bootstrap], [skip some tests on initial build]
    ),
    [case "${enableval}" in
        yes) nobootstrap=false ;;
         no) nobootstrap=true ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-bootstrap]) ;;
     esac],
    [nobootstrap=true]
)

AM_CONDITIONAL([NOBOOTSTRAP], [test x$nobootstrap = xtrue])

AC_CONFIG_FILES([Makefile src/Makefile plugins/Makefile plugins/blowfish/Makefile
	plugins/md5/Makefile plugins/sha256/Makefile plugins/sha512/Makefile])
AC_OUTPUT

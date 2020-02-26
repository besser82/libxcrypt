# zw_shlib_flags.m4 - Determine how to build shared libraries. -*- Autoconf -*-
#
# Copyright 2020 Zack Weinberg <zackw@panix.com>
# Portions of this file were taken from libtool.m4:
# Copyright 1996-2001, 2003-2015 Free Software Foundation, Inc.
# Written by Gordon Matzigkeit.
#
# This file is free software; the copyright holders give unlimited
# permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.

# This Autoconf macro provides an extremely simplified version of the
# logic Libtool uses to decide how to build shared and static
# libraries, suitable for use together with plain old Makefile rules.
# It sets the following substitution variables:
#
#   @ENABLE_SHARED@ - "yes" if shared libraries are to be built and installed,
#                     "no" if not.  Controllable by configure switches
#                     (--(enable|disable)-shared) as well as by the
#                     system's capabilities.
#
#   @ENABLE_STATIC@ - "yes" if static libraries are to be built and installed,
#                     "no" if not.  Controllable by configure switches
#                     (--(enable|disable)-static) as well as by the
#                     system's capabilities.  At least one of these two
#                     will be "yes" once this macro completes.
#
#   @SOEXT@    - The file extension for shared libraries on this
#                platform, with leading dot.  May be empty.
#
#   @SOVER_AFTER_EXT@ - "yes" if shared library file names have a
#                       version number after @SOEXT@, "no" if it
#                       goes before @SOEXT@.
#
#   @HAVE_SONAME@ - "yes" if shared libraries have an embedded name that
#                   needs to be specified at link time, "no" if they don't.
#
#   @PICFLAGS@ - Switches to make the compiler generate code suitable for
#                inclusion in a shared library (e.g. -fPIC with gcc).
#                Note that this will *not* include -DPIC.  Add that to
#                (AM_)CPPFLAGS yourself if you want it.
#
#   @SO_LDFLAGS@ - Switches to make the compiler link object files into
#                  a shared library.  These should appear before any object
#                  files in the compiler invocation.
#
#   @SO_LIBS@    - Any switches that might need to go at the *end*
#                  of the compiler invocation; e.g. -lsomething.
#                  Put any -l switches specific to your library
#                  *before* this variable.
#
#   @SONAME@     - Switch to tell the linker the embedded name of the
#                  shared library.  In the link command, write this as
#                  a single argument with the actual name, e.g.
#                  $(CC) $(SO_LDFLAGS) $(SONAME)libfoo.$(SOEXT).1 ...
#
#   @WHOLE_A@    - Switch to tell the compiler to include the entire
#                  contents of subsequent .a libraries in the link.
#
#   @END_WHOLE_A@ - Switch to tell the compiler to stop including
#                   the entire contents of .a libraries in the link.
#                   Usage: $(WHOLE_A) libfoo-pic.a $(END_WHOLE_A) -lbar
#
#   @LIST_EXPORTS_CMD@ - Command using either nm or objconv to list all
#                        exported symbols in a static library.  Uses $<
#                        and $@ internally.
#
#   @RENAME_INTERNALS_CMD@ - Command using either objcopy or objconv to
#                            rename all internal symbols in a static library.
#                            Uses $^ and $@ internally; $^ must be the list
#                            of symbols to rename and the input static
#                            library, _in that order_.
#
#   @RENAMES_FORMAT@ - If @RENAME_CMD@ uses objconv, this will be the string
#                      "--objconv", otherwise it will be empty.  Use this to
#                      tell the program that generates the list of symbols to
#                      rename what format to produce.
#
#                      When @RENAMES_FORMAT@ is empty, the expected format is
#                      the format of the file read by objcopy --redefine-syms:
#                      one entry per line, "oldname newname".
#
#                      When @RENAMES_FORMAT@ is "objconv", the expected format
#                      is an objconv "response file": one entry per line,
#                      "-nr:oldname:newname"
#
# Note that in some cases it does not work to put more than one library
# between $(WHOLE_A) and $(END_WHOLE_A).
#
# If AM_INIT_AUTOMAKE has been called, then ENABLE_SHARED,
# ENABLE_STATIC, SOVER_AFTER_EXT, and HAVE_SONAME will also be made
# available as AM_CONDITIONALs.
#
# If the appropriate value for *any* of the above variables is
# unknown, or if appropriate use of the above variables is not enough
# to build a shared library successfully, then @ENABLE_SHARED@,
# @SOVER_AFTER_EXT@ and @HAVE_SONAME@ will be set to "no", @PICFLAGS@
# will be set to "unknown", and all the other variables will be empty.
#
# Similarly, if we are unable to determine how to rename internal
# symbols in a static library, then @ENABLE_STATIC@ will be set to
# "no", @RENAME_CMD@ will be set to a command that always fails, and
# @FOR_OBJCONV@ will be empty.
#
# If we cannot determine how to build *either* a static or a shared
# library, or if --enable-shared or --enable-static was given on the
# command line and we cannot build that type of library, the configure
# script will fail.
#
# We assume that it is enough to test the C compiler and that all other
# compilers will accept the same switches.
AC_DEFUN([zw_CHECK_LIBRARY_BUILD_FLAGS], [
  AC_REQUIRE([AC_CANONICAL_HOST])
  AC_REQUIRE([AC_PROG_CC])
  AC_REQUIRE([AM_PROG_AR])
  AC_REQUIRE([AC_PROG_RANLIB])
  AC_CHECK_TOOL([NM], [nm], [false])
  AC_CHECK_TOOL([OBJCOPY], [objcopy], [false])
  AC_CHECK_TOOL([OBJCONV], [objconv], [false])

  AC_LANG_ASSERT([C])

  # User configuration.
  AC_ARG_ENABLE([shared],
    [AS_HELP_STRING([--enable-shared],
        [build shared libraries @<:@default=if possible@:>@])],
    [case $enableval in
        (yes|no) ;;
        (*) AC_MSG_ERROR([invalid argument $enableval for --enable-shared]) ;;
     esac],
    [enable_shared=default])

  AC_ARG_ENABLE([static],
    [AS_HELP_STRING([--enable-static],
        [build static libraries @<:@default=if possible@:>@])],
    [case $enableval in
        (yes|no) ;;
        (*) AC_MSG_ERROR([invalid argument $enableval for --enable-static]) ;;
     esac],
    [enable_static=default])

  if test "$enable_shared,$enable_static" = no,no; then
   # If both the shared and the static library are disabled, we have
   # nothing left to build, which is not a useful configuration.
   AC_MSG_ERROR(
     [--disable-shared and --disable-static cannot be used together])
 fi

  # Sensible fallback settings for all substitution variables.
  AC_SUBST([ENABLE_STATIC],        [$enable_static])
  AC_SUBST([ENABLE_SHARED],        [$enable_shared])
  AC_SUBST([SOEXT],                [""])
  AC_SUBST([SOVER_AFTER_EXT],      [no])
  AC_SUBST([HAVE_SONAME],          [no])
  AC_SUBST([PICFLAGS],             [unknown])
  AC_SUBST([SO_LDFLAGS],           [""])
  AC_SUBST([SO_LIBS],              [""])
  AC_SUBST([SONAME],               [""])
  AC_SUBST([WHOLE_A],              [""])
  AC_SUBST([END_WHOLE_A],          [""])
  AC_SUBST([LIST_EXPORTS_CMD],     [false])
  AC_SUBST([RENAME_INTERNALS_CMD], [false])
  AC_SUBST([RENAMES_FORMAT],       [""])

  if test $enable_shared != no; then
    zw__SHARED_LIBS_TESTS
  fi

  if test x"$PICFLAGS" = xunknown; then
    # Either --enable-shared=yes or --enable-symvers=yes indicates the user
    # does not want us to silently fail to produce shared libraries.
    # At this point $enable_symvers might not have been set.
    if test x$enable_shared = xyes || test x$enable_symvers = xyes; then
      AC_MSG_ERROR(
        [shared libraries not supported with this OS and/or compiler])
    fi
    enable_shared=no
    # AX_CHECK_VSCRIPT must be invoked unconditionally because it calls
    # AM_CONDITIONAL.  However, we can skip the tests by setting
    # enable_symvers=no when enable_shared=no.
    enable_symvers=no
  else
    enable_shared=yes
  fi

  AX_CHECK_VSCRIPT

  if test $enable_static != no; then
    zw__STATIC_LIBS_TESTS
  fi

  if test x"$RENAME_INTERNALS_CMD" = xfalse; then
    # --enable-static=yes indicates the user does not want us to
    # silently fail to produce static libraries.
    if test x$enable_static = xyes; then
      AC_MSG_ERROR(
        [static libraries not supported with this OS and/or compiler])
    fi
    enable_static=no
  else
    enable_static=yes
  fi

  # The above tests might have wound up turning both shared and static
  # libraries off.
  if test "$enable_shared,$enable_static" = no,no; then
    AC_MSG_ERROR(
      [neither the shared nor the static library can be built])
  fi

  # AM_CONDITIONAL must be executed unconditionally, after computation
  # of the value it tests.
  AM_CONDITIONAL([ENABLE_STATIC], [test x$enable_static = xyes])
  AM_CONDITIONAL([ENABLE_SHARED], [test x$enable_shared = xyes])
  AM_CONDITIONAL([SOVER_AFTER_EXT], [test $SOVER_AFTER_EXT = yes])
  AM_CONDITIONAL([HAVE_SONAME], [test $HAVE_SONAME = yes])
])

AC_DEFUN([zw__SHARED_LIBS_TESTS], [
  AC_CACHE_CHECK([object file format], [zw_cv_object_format], [
    AC_LINK_IFELSE([AC_LANG_PROGRAM()], [
      zw_cv_object_format=$(
        $PYTHON $srcdir/scripts/detect-object-format conftest$EXEEXT \
            2>&AS_MESSAGE_LOG_FD || echo unknown
      )
    ],
    [zw_cv_object_format=unknown])
  ])

  if test x$GCC = xyes; then
    case $zw_cv_object_format in
      (ELF)
        # ELF and GCC(-alike) is the easiest case.
        # -fPIC is on by default in some cases but specifying it
        # explicitly does no harm.
        PICFLAGS="-fPIC"
        SOEXT=".so"
        SOVER_AFTER_EXT="yes"
        HAVE_SONAME="yes"
        SO_LDFLAGS="-shared"
        SO_LIBS=""
        SONAME="-Wl,-soname,"
        WHOLE_A="-Wl,--whole-archive"
        END_WHOLE_A="-Wl,--no-whole-archive"
      ;;

      (Mach-O)
        # We understand how to do this for Darwin only.  Other OSes
        # using this file format had completely different quirks.
        case $host_os in
          (darwin*)
            # PIC is default, but common symbols are not allowed in shared libs
            PICFLAGS="-fno-common"
            SOEXT=.dylib
            SOVER_AFTER_EXT="no"
            HAVE_SONAME="no" # needs further investigation,
                             # libtool is doing _something_...
            SO_LDFLAGS="-dynamiclib "
            SO_LIBS=""
            SONAME=""
            WHOLE_A="-Wl,-force_load"
            END_WHOLE_A=""
          ;;
        esac
        ;;

      (PE)
        # Windows - to be implemented.
        ;;

      (MZ)
        # libtool.m4: "Just because we use GCC doesn't mean we suddenly
        # get shared libraries on systems that don't support them."
        ;;

      (a.out)
        # Implementable in principle at least for Linux and the first
        # generation of open-source BSDs, but is it worth it?
        ;;

      (unknown)
        ;;

      (*)
        AC_MSG_ERROR(
          ["missing object file format case: GCC/$zw_cv_object_format"])
        ;;
      esac

  else # not GCC
    : # to be implemented: icc, at least
  fi

  # Report results.
  AC_MSG_CHECKING([how to build shared libraries])
  if test x"$PICFLAGS" = xunknown; then
    AC_MSG_RESULT([unknown])
  else
    AC_MSG_RESULT([success])
    AC_MSG_CHECKING([for shared library extension])
    AC_MSG_RESULT([${SOEXT-(empty)}])
    AC_MSG_CHECKING([whether shared library version goes after the extension])
    AC_MSG_RESULT([$SOVER_AFTER_EXT])
    AC_MSG_CHECKING([whether shared libraries have embedded names])
    AC_MSG_RESULT([$HAVE_SONAME])
    AC_MSG_CHECKING([for shared library compile flags])
    AC_MSG_RESULT([${PICFLAGS-not needed}])
    AC_MSG_CHECKING([for shared library link flags])
    AC_MSG_RESULT([${SO_LDFLAGS}])
    AC_MSG_CHECKING([for shared library extra libraries])
    AC_MSG_RESULT([${SO_LIBS-not needed}])
    if test $HAVE_SONAME = yes; then
      AC_MSG_CHECKING([how to embed a name in a shared library])
      AC_MSG_RESULT([$SONAME])
    fi
    AC_MSG_CHECKING([how to start including static libraries whole])
    AC_MSG_RESULT([$WHOLE_A])
    AC_MSG_CHECKING([how to stop including static libraries whole])
    AC_MSG_RESULT([$END_WHOLE_A])
  fi
])

AC_DEFUN([zw__STATIC_LIBS_TESTS], [
  # As of binutils 2.33.50, GNU nm and objcopy are known not to work
  # on x86-based Darwin.  The problem *may* only affect "fat binaries"
  # (embedding more than one architecture's machine code in a single
  # object file) but it's not practical to know at this point whether
  # we're doing that.  Don't do this for powerpc- or arm-based Darwin,
  # even though they probably have the same problem, because objconv
  # only supports x86 and fat binaries aren't as common in either
  # context.
  case "$host" in
    ( i?86-*-darwin* | x86_64-*-darwin* )
      NM=false
      OBJCOPY=false
    ;;
  esac

  # We must have either 'nm' and 'objcopy', or 'objconv'.
  # The former works on more different OSes and CPUs, so it's preferred.
  # FIXME Verify that nm has all of the options we use.
  if test x"$NM" != xfalse && test x"$OBJCOPY" != xfalse; then
    LIST_EXPORTS_CMD='$(NM) --format=bsd --extern-only --defined-only --no-sort'
    LIST_EXPORTS_CMD="$LIST_EXPORTS_CMD "'$< > $[]@.T'

    RENAME_INTERNALS_CMD='$(OBJCOPY) --redefine-syms $^ $[]@'
    RENAMES_FORMAT=

  elif test x"$OBJCONV" != xfalse; then
    LIST_EXPORTS_CMD='$(OBJCONV) -v0 -ds $< > $[]@.T'
    RENAME_INTERNALS_CMD='$(OBJCONV) -v0 @$^ $[]@'
    RENAMES_FORMAT=--objconv
  fi

  if test x"$LIST_EXPORTS_CMD" != xfalse; then
    LIST_EXPORTS_CMD="$LIST_EXPORTS_CMD "'; mv -f $[]@.T $[]@'
  fi
])

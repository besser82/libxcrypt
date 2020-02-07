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
# logic Libtool uses to decide how to build a shared library, suitable
# for use together with plain old Makefile rules.  It sets the following
# substitution variables:
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
# Note that in some cases it does not work to put more than one library
# between $(WHOLE_A) and $(END_WHOLE_A).
#
# If AM_INIT_AUTOMAKE has been called, then SOVER_AFTER_EXT and
# HAVE_SONAME will also be made available as AM_CONDITIONALs.
#
# If the appropriate value for *any* of the above variables is
# unknown, or if appropriate use of the above variables is not enough
# to build a shared library successfully, then @PICFLAGS@ will be set
# to "unknown", @SOVER_AFTER_EXT@ and @HAVE_SONAME@ to "no", and all
# the other variables will be empty.  Caller is responsible for
# noticing that this has happened and going into --disable-shared
# mode.  (Caller is also responsible for AC_ARG_ENABLE([shared]) in
# the first place.)
#
# We assume that it is enough to test the C compiler and that all other
# compilers will accept the same switches.
AC_DEFUN([zw_CHECK_SHLIB_FLAGS], [
  # Defaults.
  AC_SUBST([SOEXT],           [""])
  AC_SUBST([SOVER_AFTER_EXT], [no])
  AC_SUBST([HAVE_SONAME],     [no])
  AC_SUBST([PICFLAGS],        [unknown])
  AC_SUBST([SO_LDFLAGS],      [""])
  AC_SUBST([SO_LIBS],         [""])
  AC_SUBST([SONAME],          [""])
  AC_SUBST([WHOLE_A],         [""])
  AC_SUBST([END_WHOLE_A],     [""])

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
        [build static libraries @<:@default=yes@:>@])],
    [case $enableval in
        (yes|no) ;;
        (*) AC_MSG_ERROR([invalid argument $enableval for --enable-static]) ;;
     esac],
    [enable_static=yes])

  if test "$enable_shared,$enable_static" = no,no; then
   # If both the shared and the static library are disabled, we have
   # nothing left to build, which is not a useful configuration.
   AC_MSG_ERROR(
     [--disable-shared and --disable-static cannot be used together])
 fi

  if test $enable_shared != no; then
    zw__CHECK_SHLIB_FLAGS_TESTS
  fi

  # Report results.
  AC_MSG_CHECKING([how to build shared libraries])
  if test x"$PICFLAGS" = xunknown; then
    AC_MSG_RESULT([unknown])
    SOEXT=""
    SOVER_AFTER_EXT=no
    HAVE_SONAME=no
    SO_LDFLAGS=
    SO_LIBS=
    SONAME=
    WHOLE_A=
    END_WHOLE_A=
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

  AM_CONDITIONAL([SOVER_AFTER_EXT], [test $SOVER_AFTER_EXT = yes])
  AM_CONDITIONAL([HAVE_SONAME], [test $HAVE_SONAME = yes])

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
])

AC_DEFUN([zw__CHECK_SHLIB_FLAGS_TESTS], [
  AC_REQUIRE([AC_CANONICAL_HOST])
  AC_REQUIRE([AC_PROG_CC])
  AC_LANG_ASSERT([C])

  AC_CACHE_CHECK([object file format], [zw_cv_object_format], [
    AC_LINK_IFELSE([AC_LANG_PROGRAM()], [
      # get the first sixteen bytes of the compiled executable, in octal
      magic=$(od -b conftest$EXEEXT | sed -e 's/^@<:@0-7@:>@* *//; y/ /./; q')
      AS_ECHO("conftest$EXEEXT magic: $magic") >&AS_MESSAGE_LOG_FD

      case $magic in
         # ELF: \x7F E L F
         (177.105.114.106.*)
             zw_cv_object_format=ELF
             ;;

         # Mach-O:
         # FE ED FA CE / CF FA ED FE (big/little endian)
         # CA FE BA BE / BE BA FE CA (ditto)
         # Java jars also use CA FE BA BE but we don't expect to see
         # that as the output of a C compiler
         (376.355.372.317.* | 317.372.355.376.* | \
          312.376.272.276.* | 276.272.376.312.* ) zw_cv_object_format=Mach-O ;;

         # DOS and Windows: M Z
         # rather than groveling deep into the file for actual PE
         # headers, check whether $EXEEXT is ".exe" (arbitrary case)
         # and then look at $host_os.  unfortunately, the first few bytes
         # of the "stub" vary too much to key off of.
         (115.132.*)
             if test x"$(AS_ECHO(["$EXEEXT"]) |
                         tr "$as_cr_LETTERS" "$as_cr_letters")" = x.exe; then
                 case $host_os in
                   (cygwin*|mingw*|msys*|interix*|uwin*)
                     zw_cv_object_format=PE ;;
                   (msdos*)
                     zw_cv_object_format=MZ ;;
                   (*)
                     zw_cv_object_format=unknown;;
                  esac
              fi
          ;;

          # Bare COFF/ECOFF/XCOFF executables are rare nowadays and
          # difficult to identify from the first 16 bytes alone.  (The
          # first two bytes of the file identify the CPU, not the file
          # format as such; there's a long list and not enough effort
          # seems to have been put into avoiding collisions with other
          # file types.)  We're not bothering with them for now.
          # Revisit if and when someone wants this to work on AIX.

          # a.out: OMAGIC, NMAGIC, ZMAGIC, QMAGIC (from linux/a.out.h)
          # This format is also rare nowadays, but at least the set of
          # patterns to look for is reasonably short and unlikely to
          # be mistaken for anything else.  The only complication is
          # that on big-endian machines the magic number is bytes 3
          # and 4.  (And I wish people had realized back in the day
          # that two bytes of magic number is not enough.)
          (007.001.* | \
           010.001.* | \
           013.001.* | \
           314.000.* | \
     @<:@!.@:>@@<:@!.@:>@@<:@!.@:>@.@<:@!.@:>@@<:@!.@:>@@<:@!.@:>@.001.007.* | \
     @<:@!.@:>@@<:@!.@:>@@<:@!.@:>@.@<:@!.@:>@@<:@!.@:>@@<:@!.@:>@.001.010.* | \
     @<:@!.@:>@@<:@!.@:>@@<:@!.@:>@.@<:@!.@:>@@<:@!.@:>@@<:@!.@:>@.001.013.* | \
     @<:@!.@:>@@<:@!.@:>@@<:@!.@:>@.@<:@!.@:>@@<:@!.@:>@@<:@!.@:>@.000.314.* )
              zw_cv_object_format=a.out
          ;;

         (*)
             zw_cv_object_format=unknown
         ;;
      esac
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
])

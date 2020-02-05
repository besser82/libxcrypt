# serial 1
dnl Copyright 2017 Zack Weinberg <zackw at panix.com>.
dnl Partially based on Autoconf, copyright 1992-2017 Free Software Foundation.
dnl
dnl This program is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU General Public License as
dnl published by the Free Software Foundation, either version 3 of the
dnl License, or (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl Under Section 7 of GPL version 3, you are granted additional
dnl permissions described in the Autoconf Configure Script Exception,
dnl version 3.0, as published by the Free Software Foundation.
dnl
dnl Because only two files in this source tree are released
dnl under GPLv3 with exceptions, neither the GPLv3 nor the exception are
dnl distributed with this source tree.  Copies can be retrieved from
dnl https://www.gnu.org/licenses/
dnl
dnl Autoconf core has no good way of enabling compiler warnings.
dnl This is a cut-down version of the elaborate thing in the extras
dnl archive, which we do not need nearly all of.
dnl
dnl Partly based on:
dnl https://www.gnu.org/software/autoconf-archive/ax_compiler_flags_cflags.html

AC_PREREQ(2.64)dnl for _AC_LANG_PREFIX and AS_VAR_IF

AC_DEFUN([zw_SIMPLE_ENABLE_WARNINGS],
[
AC_ARG_ENABLE(
   [werror],
   AS_HELP_STRING(
        [--disable-werror],
        [do not treat all warnings as errors]
    ),
    [case "${enableval}" in
        yes) warnings_are_errors=true ;;
         no) warnings_are_errors=false ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-werror]) ;;
     esac],
     [warnings_are_errors=true]
)

    # Always pass -Werror=unknown-warning-option to get Clang to fail
    # on bad flags, otherwise they are always appended to the
    # warn_cflags variable, and Clang warns on them for every
    # compilation unit.  If this is passed to GCC, it will explode, so
    # the flag must be enabled conditionally.
    AX_CHECK_COMPILE_FLAG([-Werror=unknown-warning-option],[
        ax_compiler_flags_test="-Werror=unknown-warning-option"
    ],[
        ax_compiler_flags_test=""
    ])

    # Don't enable -pedantic if we don't have C11, or we may get junk
    # warnings about static_assert.
    ax_candidate_warnings="dnl
        -Wall dnl
        -Wextra dnl
        -Walloc-zero dnl
        -Walloca dnl
        -Wbad-function-cast dnl
        -Wcast-align dnl
        -Wcast-qual dnl
        -Wconversion dnl
        -Wformat=2 dnl
        -Wformat-overflow=2 dnl
        -Wformat-signedness dnl
        -Wformat-truncation=1 dnl
        -Wlogical-op dnl
        -Wmissing-declarations dnl
        -Wmissing-prototypes dnl
        -Wnested-externs dnl
        -Wnull-dereference dnl
        -Wold-style-definition dnl
        -Wpointer-arith dnl
        -Wrestrict dnl
        -Wshadow dnl
        -Wstrict-overflow=2 dnl
        -Wstrict-prototypes dnl
        -Wundef dnl
        -Wvla dnl
        -Wwrite-strings dnl
    "
    if test x$ac_prog_cc_stdc = xc11; then
        ax_candidate_warnings="$ax_candidate_warnings -Wpedantic"
    fi
    if test x$warnings_are_errors = xtrue; then
        ax_candidate_warnings="$ax_candidate_warnings -Werror"
    fi

    # If we are building for OSX, turn -Wdeprecated-declarations off.
    # Apple is a little too trigger-happy with deprecations.
    case "$host_os" in
      (*darwin*)
        ax_candidate_warnings="$ax_candidate_warnings -Wno-deprecated-declarations"
      ;;
    esac

    AX_APPEND_COMPILE_FLAGS(
        [$ax_candidate_warnings], [WARN_CFLAGS],
        [$ax_compiler_flags_test])

    AC_SUBST(WARN_CFLAGS)

   if test $cross_compiling = yes; then
       # Repeat the above logic for the build compiler.

       save_cross_compiling=$cross_compiling
       save_ac_tool_prefix=$ac_tool_prefix
       save_CC="$CC"
       save_CFLAGS="$CFLAGS"
       save_CPPFLAGS="$CPPFLAGS"
       save_LDFLAGS="$LDFLAGS"

       cross_compiling=no
       ac_tool_prefix=
       CC="$CC_FOR_BUILD"
       CFLAGS="$CFLAGS_FOR_BUILD"
       CPPFLAGS="$CPPFLAGS_FOR_BUILD"
       LDFLAGS="$LDFLAGS_FOR_BUILD"

       pushdef([_AC_LANG_ABBREV],[build_c])

       AX_CHECK_COMPILE_FLAG([-Werror=unknown-warning-option],[
           ax_compiler_flags_test="-Werror=unknown-warning-option"
       ],[
           ax_compiler_flags_test=""
       ])
       AX_APPEND_COMPILE_FLAGS(
           [$ax_candidate_warnings], [WARN_CFLAGS_FOR_BUILD],
           [$ax_compiler_flags_test])

       popdef([_AC_LANG_ABBREV])

       AC_SUBST(WARN_CFLAGS_FOR_BUILD)

       cross_compiling=$save_cross_compiling
       ac_tool_prefix=$save_ac_tool_prefix
       CC="$save_CC"
       CFLAGS="$save_CFLAGS"
       CPPFLAGS="$save_CPPFLAGS"
       LDFLAGS="$save_LDFLAGS"
    fi # cross_compiling
])

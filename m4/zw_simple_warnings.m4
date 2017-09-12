# serial 1
dnl Autoconf core has no good way of enabling compiler warnings.
dnl This is a cut-down version of the elaborate thing in the extras
dnl archive, which we do not need nearly all of.
dnl Partly based on:
dnl http://www.gnu.org/software/autoconf-archive/ax_append_flag.html
dnl http://www.gnu.org/software/autoconf-archive/ax_check_compile_flag.html
dnl http://www.gnu.org/software/autoconf-archive/ax_append_compile_flags.html
dnl http://www.gnu.org/software/autoconf-archive/ax_compiler_flags_cflags.html
AC_PREREQ(2.64)dnl for _AC_LANG_PREFIX and AS_VAR_IF

AC_DEFUN([AX_CHECK_COMPILE_FLAG],
[AS_VAR_PUSHDEF([CACHEVAR],[ax_cv_check_[]_AC_LANG_ABBREV[]flags_$4_$1])dnl
AC_CACHE_CHECK([whether _AC_LANG compiler accepts $1], CACHEVAR, [
  ax_check_save_flags=$[]_AC_LANG_PREFIX[]FLAGS
  _AC_LANG_PREFIX[]FLAGS="$[]_AC_LANG_PREFIX[]FLAGS $4 $1"
  AC_COMPILE_IFELSE([m4_default([$5],[AC_LANG_PROGRAM()])],
    [AS_VAR_SET(CACHEVAR,[yes])],
    [AS_VAR_SET(CACHEVAR,[no])])
  _AC_LANG_PREFIX[]FLAGS=$ax_check_save_flags])
AS_VAR_IF(CACHEVAR,yes,
  [m4_default([$2], :)],
  [m4_default([$3], :)])
AS_VAR_POPDEF([CACHEVAR])])

AC_DEFUN([AX_APPEND_FLAG],
[AS_VAR_PUSHDEF([FLAGS], [m4_default($2,_AC_LANG_PREFIX[FLAGS])])
AS_VAR_SET_IF(FLAGS,[
  AS_CASE([" AS_VAR_GET(FLAGS) "],
    [*" $1 "*], [AC_RUN_LOG([: FLAGS already contains $1])],
    [
     AS_VAR_APPEND(FLAGS,[" $1"])
     AC_RUN_LOG([: FLAGS="$FLAGS"])
    ])
  ],
  [
  AS_VAR_SET(FLAGS,[$1])
  AC_RUN_LOG([: FLAGS="$FLAGS"])
  ])
AS_VAR_POPDEF([FLAGS])dnl
])dnl AX_APPEND_FLAG

AC_DEFUN([AX_APPEND_COMPILE_FLAGS],
[for flag in $1; do
  AX_CHECK_COMPILE_FLAG([$flag],
    [AX_APPEND_FLAG([$flag], [$2])], [], [$3], [$4])
done
])

AC_DEFUN([zw_SIMPLE_ENABLE_WARNINGS],
[
AC_ARG_ENABLE(
    [warn-cast-align],
    AS_HELP_STRING(
        [--disable-warn-cast-align],
        [do not warn about casts increasing required alignment of target type]
    ),
    [case "${enableval}" in
        yes) cast_align=true ;;
         no) cast_align=false ;;
          *)
       AC_MSG_ERROR([bad value ${enableval} for --enable-warn-cast-align]) ;;
     esac],
     [cast_align=true]
)
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
        -Wbad-function-cast dnl
        -Wcast-qual dnl
        -Wformat=2 dnl
        -Winline dnl
        -Wmissing-declarations dnl
        -Wmissing-prototypes dnl
        -Wnested-externs
        -Wpointer-arith
        -Wshadow
        -Wstrict-prototypes dnl
        -Wundef dnl
        -Wwrite-strings dnl
    "
    if test x$ac_prog_cc_stdc = xc11; then
        ax_candidate_warnings="$ax_candidate_warnings -Wpedantic"
    fi
    if test x$cast_align = xtrue; then
        ax_candidate_warnings="$ax_candidate_warnings -Wcast-align"
    fi
    if test x$warnings_are_errors = xtrue; then
        ax_candidate_warnings="$ax_candidate_warnings -Werror"
    fi

    AX_APPEND_COMPILE_FLAGS(
        [$ax_candidate_warnings], [WARN_CFLAGS],
        [$ax_compiler_flags_test])

    AC_SUBST(WARN_CFLAGS)
])

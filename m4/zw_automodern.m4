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
dnl As of this writing (September 2017), Autoconf 2.70 is not yet released.
dnl Backport some improvements:
dnl  - switch AC_CHECK_HEADER to compile-only
dnl  - eliminate unnecessary tests in AC_INCLUDES_DEFAULT
dnl  - Darwin (OSX) support in AC_USE_SYSTEM_EXTENSIONS
dnl  - C11 mode by default in AC_PROG_CC, falling back to C99
AC_PREREQ([2.62])dnl earliest version with working m4_version_prereq
m4_version_prereq([2.70], [], [

  m4_define([AC_CHECK_HEADER], [_AC_CHECK_HEADER_COMPILE($@)])

  AC_DEFUN_ONCE([_AC_INCLUDES_DEFAULT_REQUIREMENTS],
[m4_divert_text([DEFAULTS],
[# Factoring default headers for most tests.
ac_includes_default="\
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif"
])]dnl
[AC_CHECK_HEADERS(
  [sys/types.h sys/stat.h strings.h inttypes.h stdint.h unistd.h],,,[/**/])]dnl
dnl For backward compatibility, provide unconditional AC_DEFINEs of
dnl HAVE_STDLIB_H, HAVE_STRING_H, and STDC_HEADERS.
[AC_DEFINE([HAVE_STDLIB_H], [1],
  [Always define to 1, for backward compatibility.
   You can assume <stdlib.h> exists.])]dnl
[AC_DEFINE([HAVE_STRING_H], [1],
  [Always define to 1, for backward compatibility.
   You can assume <string.h> exists.])]dnl
[AC_DEFINE([STDC_HEADERS], [1],
  [Always define to 1, for backward compatibility.
   You can assume the C90 standard headers exist.])])

  m4_define([AC_USE_SYSTEM_EXTENSIONS],
    m4_defn([AC_USE_SYSTEM_EXTENSIONS])[
    AH_VERBATIM([USE_SYSTEM_EXTENSIONS_270],
[/* Enable general extensions on OSX. */
#ifndef _DARWIN_C_SOURCE
# undef _DARWIN_C_SOURCE
#endif
])
    AC_DEFINE([_DARWIN_C_SOURCE])
  ])

dnl Prior to 2.70, AC_PROG_CC ends with an unconditional call to
dnl _AC_PROG_CC_C89.  Use this as an extension hook, replacing it with
dnl the logic that will be used in 2.70.
m4_define([_AC_PROG_CC_C89_original], m4_defn([_AC_PROG_CC_C89]))
m4_define([_AC_PROG_CC_C89], [dnl
dnl Set ac_prog_cc_stdc to the supported C version.
dnl Also set the documented variable ac_cv_prog_cc_stdc;
dnl its name was chosen when it was cached, but it is no longer cached.
_AC_PROG_CC_C11([ac_prog_cc_stdc=c11
                 ac_cv_prog_cc_stdc=$ac_cv_prog_cc_c11],
  [_AC_PROG_CC_C99([ac_prog_cc_stdc=c99
                    ac_cv_prog_cc_stdc=$ac_cv_prog_cc_c99],
     [_AC_PROG_CC_C89_original([ac_prog_cc_stdc=c89
                       ac_cv_prog_cc_stdc=$ac_cv_prog_cc_c89],
                      [ac_prog_cc_stdc=no
                       ac_cv_prog_cc_stdc=no])])])
])
dnl Must also supply the definition of _AC_PROG_CC_C11.
dnl This is also taken verbatim from Autoconf trunk.
dnl I regret the bulk.
AC_DEFUN([_AC_PROG_CC_C11],
[_AC_C_STD_TRY([c11],
[[#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdio.h>

// Check varargs macros.  These examples are taken from C99 6.10.3.5.
#define debug(...) fprintf (stderr, __VA_ARGS__)
#define showlist(...) puts (#__VA_ARGS__)
#define report(test,...) ((test) ? puts (#test) : printf (__VA_ARGS__))
static void
test_varargs_macros (void)
{
  int x = 1234;
  int y = 5678;
  debug ("Flag");
  debug ("X = %d\n", x);
  showlist (The first, second, and third items.);
  report (x>y, "x is %d but y is %d", x, y);
}

// Check long long types.
#define BIG64 18446744073709551615ull
#define BIG32 4294967295ul
#define BIG_OK (BIG64 / BIG32 == 4294967297ull && BIG64 % BIG32 == 0)
#if !BIG_OK
  your preprocessor is broken;
#endif
#if BIG_OK
#else
  your preprocessor is broken;
#endif
static long long int bignum = -9223372036854775807LL;
static unsigned long long int ubignum = BIG64;

struct incomplete_array
{
  int datasize;
  double data[];
};

struct named_init {
  int number;
  const wchar_t *name;
  double average;
};

typedef const char *ccp;

static inline int
test_restrict (ccp restrict text)
{
  // See if C++-style comments work.
  // Iterate through items via the restricted pointer.
  // Also check for declarations in for loops.
  for (unsigned int i = 0; *(text+i) != '\0'; ++i)
    continue;
  return 0;
}

// Check varargs and va_copy.
static bool
test_varargs (const char *format, ...)
{
  va_list args;
  va_start (args, format);
  va_list args_copy;
  va_copy (args_copy, args);

  const char *str = "";
  int number = 0;
  float fnumber = 0;

  while (*format)
    {
      switch (*format++)
        {
        case 's': // string
          str = va_arg (args_copy, const char *);
          break;
        case 'd': // int
          number = va_arg (args_copy, int);
          break;
        case 'f': // float
          fnumber = va_arg (args_copy, double);
          break;
        default:
          break;
        }
    }
  va_end (args_copy);
  va_end (args);

  return *str && number && fnumber;
}

// Check _Alignas.
char _Alignas (double) aligned_as_double;
char _Alignas (0) no_special_alignment;
extern char aligned_as_int;
char _Alignas (0) _Alignas (int) aligned_as_int;

// Check _Alignof.
enum
{
  int_alignment = _Alignof (int),
  int_array_alignment = _Alignof (int[100]),
  char_alignment = _Alignof (char)
};
_Static_assert (0 < -_Alignof (int), "_Alignof is signed");

// Check _Noreturn.
int _Noreturn does_not_return (void) { for (;;) continue; }

// Check _Static_assert.
struct test_static_assert
{
  int x;
  _Static_assert (sizeof (int) <= sizeof (long int),
                  "_Static_assert does not work in struct");
  long int y;
};

// Check UTF-8 literals.
#define u8 syntax error!
char const utf8_literal[] = u8"happens to be ASCII" "another string";

// Check duplicate typedefs.
typedef long *long_ptr;
typedef long int *long_ptr;
typedef long_ptr long_ptr;

// Anonymous structures and unions -- taken from C11 6.7.2.1 Example 1.
struct anonymous
{
  union {
    struct { int i; int j; };
    struct { int k; long int l; } w;
  };
  int m;
} v1;
]],
[[
  // Check bool.
  _Bool success = false;

  // Check restrict.
  if (test_restrict ("String literal") == 0)
    success = true;
  char *restrict newvar = "Another string";

  // Check varargs.
  success &= test_varargs ("s, d' f .", "string", 65, 34.234);
  test_varargs_macros ();

  // Check flexible array members.
  struct incomplete_array *ia =
    malloc (sizeof (struct incomplete_array) + (sizeof (double) * 10));
  ia->datasize = 10;
  for (int i = 0; i < ia->datasize; ++i)
    ia->data[i] = i * 1.234;

  // Check named initializers.
  struct named_init ni = {
    .number = 34,
    .name = L"Test wide string",
    .average = 543.34343,
  };

  ni.number = 58;

  int dynamic_array[ni.number];
  dynamic_array[ni.number - 1] = 543;

  // work around unused variable warnings
  return (!success || bignum == 0LL || ubignum == 0uLL || newvar[0] == 'x'
          || dynamic_array[ni.number - 1] != 543);

  v1.i = 2;
  v1.w.k = 5;
  _Static_assert ((offsetof (struct anonymous, i)
                   == offsetof (struct anonymous, w.k)),
                  "Anonymous union alignment botch");
]],
dnl Try
dnl GCC         -std=gnu11 (unused restrictive mode: -std=c11)
dnl with extended modes being tried first.
dnl
dnl Do not try -qlanglvl=extc1x, because IBM XL C V12.1 (the latest version as
dnl of September 2012) does not pass the C11 test.  For now, try extc1x when
dnl compiling the C99 test instead, since it enables _Static_assert and
dnl _Noreturn, which is a win.  If -qlanglvl=extc11 or -qlanglvl=extc1x passes
dnl the C11 test in some future version of IBM XL C, we'll add it here,
dnl preferably extc11.
[[-std=gnu11]], [$1], [$2])[]dnl
])# _AC_PROG_CC_C11


])dnl m4_version_prereq([2.70], ...)

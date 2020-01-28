# Meson configuration logic for libcrypt.
# See meson_options.txt for build options.
#
#  Copyright 2007-2017 Thorsten Kukuk and Zack Weinberg
#  Copyright 2018-2019 Björn Esser and Zack Weinberg
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation; either version 2.1 of
#  the License, or (at your option) any later version.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with this library; if not, see
#  <https://www.gnu.org/licenses/>.

project('libxcrypt', 'c',
        version: '4.5.0',
        default_options: [
          'buildtype=debugoptimized',
          'default_library=both',
          # Use C11 if possible.  Don't use GCC's strict conformance
          # mode (-std=cXX); it has a nasty tendency to break the
          # system headers, and we don't want to have to worry about
          # trigraphs.
          'c_std=gnu11',
          # More warnings will be enabled by hand below.
          # See below for why we don't use warning_level=3.
          'warning_level=2',
        ]
)

#
# We need to run Python subprograms as part of both the configuration
# process and the build process.  3.6 or later is required.
#

pymod = import('python')
python = pymod.find_installation('python3')

pv = run_command(python, '--version')
if pv.returncode() != 0
  error(pv.stderr() + '\n' +
        python.path() + ' --version: exit ' + pv.returncode().to_string())
endif
pv = pv.stdout().strip().split(' ')[1]
if pv.version_compare('<3.6.0')
  error('Python ' + pv + ' is too old for build scripts')
endif
message('Using Python ' + pv + ' for build scripts')

# Find out if we have the optional library required to run test/ka-table-gen
pv = run_command(python, '-c', 'import passlib')
if pv.returncode() == 0
  message('Passlib is available, regen-ka-table target enabled')
  ENABLE_KA_TABLE_GEN = true
else
  message('Passlib not available, regen-ka-table target disabled')
  ENABLE_KA_TABLE_GEN = false
endif

cc = meson.get_compiler('c')

# Load file objects for the scripts.
subdir('scripts')

#
# Configuration.
#

# Everything in here will be made available via crypt-config.h.
cdata = configuration_data()

# Compiler switches to be used when compiling probe programs.
# Caution: putting something in this array does NOT arrange for it to
# be used during the build.
cflags_for_probe = []

#
# Process build options.  We do this as early as possible so we can
# fail fast on invalid choices.
#

COMPAT_API = get_option('obsolete-api')
if COMPAT_API in ['alt', 'glibc', 'owl']
  ENABLE_OBSOLETE_API = true
  ENABLE_COMPAT_SUSE = false

elif COMPAT_API in ['true', 'suse']
  ENABLE_OBSOLETE_API = true
  ENABLE_COMPAT_SUSE = true

elif COMPAT_API == 'false'
  ENABLE_OBSOLETE_API = false
  ENABLE_COMPAT_SUSE = false

else
  # we can only get here if the cases above are out of sync with the
  # choices list in meson_options.txt
  error('internal error: -Dobsolete-api=' + COMPAT_API + ' not recognized')
endif

ENABLE_OBSOLETE_API_ENOSYS = get_option('obsolete-api-enosys')

# If the obsolete APIs are disabled, that supersedes the option to
# have them unconditionally fail.
if ENABLE_OBSOLETE_API_ENOSYS and not ENABLE_OBSOLETE_API
  warning('-Dobsolete-api=false supersedes -Dobsolete-api-enosys=true')
  ENABLE_OBSOLETE_API_ENOSYS = false
endif

# The obsolete APIs are unconditionally excluded from the static library,
# so if we are not building the shared library, we are effectively not
# building obsolete APIs.  Do not warn about this.
if get_option('default_library') == 'static'
  ENABLE_OBSOLETE_API = false
  ENABLE_OBSOLETE_API_ENOSYS = false
  ENABLE_COMPAT_SUSE = false
  COMPAT_API = 'false'
endif

# Determine whether the host operating system even has a libcrypt.so.1
# to be binary backward compatible with.

svf = run_command(python, S_compute_symver_floor,
                  files('lib/libcrypt.minver'),
                  host_machine.system(), host_machine.cpu_family(),
                  host_machine.endian(), cc.cmd_array())
if svf.returncode() == 0
  SYMVER_FLOOR = svf.stdout().strip()

else
  error(svf.stderr() + '\n'
        + 'scripts/compute-symver-floor: exit ' + svf.returncode().to_string())
endif

if SYMVER_FLOOR == 'ERROR'
  error('libxcrypt port to ' + host_machine.system() + '/'
        + host_machine.cpu_family() + '/' + host_machine.endian()
        + ' is incomplete.')

elif SYMVER_FLOOR == 'XCRYPT_2.0'
  SYMVER_MIN   = 'XCRYPT_2.0'
  ENABLE_OBSOLETE_API = false
  ENABLE_OBSOLETE_API_ENOSYS = false
  ENABLE_COMPAT_SUSE = false
  COMPAT_API = 'false'

else
  SYMVER_MIN = 'GLIBC_2.0'
endif

# Validate and expand the value of the 'hashes' configuration option.
SELECTED_HASHES = get_option('hashes')
he = run_command(python, S_expand_selected_hashes,
                 files('lib/hashes.conf'), SELECTED_HASHES)
if he.returncode() == 0
  ENABLED_HASHES = he.stdout().strip()

else
  error(he.stderr() + '\n'
        + 'scripts/expand_selected-hashes: exit ' + he.returncode().to_string())
endif
message('Hashes to be enabled: ' + ENABLED_HASHES)

# If the traditional DES hash is disabled, then the obsolete APIs are
# implicitly disabled, except when stubs are requested.
if (ENABLE_OBSOLETE_API
    and not ENABLE_OBSOLETE_API_ENOSYS
    and not ENABLED_HASHES.contains('descrypt'))
  warning('-Dhashes='+SELECTED_HASHES
          + ', without -Dobsolete-api-enosys=true'
          + ', implies -Dobsolete-api=false')

  COMPAT_API = 'false'
  ENABLE_OBSOLETE_API = false
  ENABLE_COMPAT_SUSE  = false
endif

cdata.set('SYMVER_FLOOR', SYMVER_FLOOR)
cdata.set('ENABLE_OBSOLETE_API', ENABLE_OBSOLETE_API ? 1 : 0)
cdata.set('ENABLE_OBSOLETE_API_ENOSYS', ENABLE_OBSOLETE_API_ENOSYS ? 1 : 0)
cdata.set('ENABLE_FAILURE_TOKENS', get_option('failure-tokens') ? 1 : 0)

# The value of the 'default_library' option is one of 'static', 'shared', or
# 'both'.  We want to install shared libraries if it's 'shared' or 'both',
# and static libraries if it's 'static' or 'both'.  We can't just rely on
# meson's library() builtin to take care of this for us because libcrypt.a
# and libcrypt.so have slightly different contents; see lib/meson.build.
INSTALL_SHARED_LIB = (get_option('default_library') != 'static')
INSTALL_STATIC_LIB = (get_option('default_library') != 'shared')

#
# Compiler properties.
#

# We asked for C11 in the project default options.
# Find out if we actually got a C11-capable compiler.
HAVE_C11 = cc.compiles('''
#if !defined __STDC_VERSION__ || __STDC_VERSION__ < 201112L
#error not C11
#endif
int dummy;
''', name: 'Test whether C compiler supports C2011')

# If we didn't, check for a C89-only, or even a K&R, compiler
# and bomb out now.
if not HAVE_C11
  if not cc.compiles('''
#if !defined __STDC__ || __STDC__ == 0
#error not ANSI C
#endif
#if !defined __STDC_VERSION__ || __STDC_VERSION__ < 199901L
#error not C1999
#endif
int dummy;
''', name: 'Test whether C compiler supports C1999')
    error('A C compiler supporting at least C1999 is required.')
  endif
endif

# Also bomb out now if C99 header files are missing.
foreach h : ['stdbool.h', 'stdint.h', 'inttypes.h']
  if not cc.check_header(h)
    error('A C library supporting at least C1999 is required.')
  endif
endforeach

# We need to set up a bunch of #defines on the command line.
cc_syntax = cc.get_argument_syntax()
if cc_syntax == 'gcc'
  _D = '-D'
elif cc_syntax == 'msvc'
  _D = '/D'
else
  error('Don\'t know how to define macros on the command line')
endif

# Additional compiler options.
# Right now we only do this for GCC-style compilers.
if cc_syntax == 'gcc'

  # Warnings.
  # To test for warnings options, we must make Clang issue a hard error for
  # unknown warnings options.  Otherwise, it will just warn about them, and
  # then we'll try to use them anyway, and we'll get junk warnings about them
  # for every file in the build.  But GCC rejects the option that makes Clang
  # do this, so we have to test for *it* first.
  need_werror_unknown_option = cc.has_argument('-Werror=unknown-warning-option')

  candidate_warnings = [
    '-Walloc-zero',
    '-Walloca',
    '-Wbad-function-cast',
    '-Wcast-align',
    '-Wcast-qual',
    '-Wconversion',
    '-Wdate-time',
    '-Wformat=2',
    '-Wformat-overflow=2',
    '-Wformat-signedness',
    '-Wformat-truncation=1',
    '-Wlogical-op',
    '-Wmissing-declarations',
    '-Wmissing-prototypes',
    '-Wnested-externs',
    '-Wnull-dereference',
    '-Wold-style-definition',
    '-Wpointer-arith',
    '-Wrestrict',
    '-Wshadow',
    '-Wstrict-overflow=2',
    '-Wstrict-prototypes',
    '-Wundef',
    '-Wvla',
    '-Wwrite-strings',
  ]
  # Only enable -Wpedantic if we have C11, or we may get junk
  # warnings about static_assert.  This is also why we cannot
  # use warning_level=3 in project options.
  # With gcc 4.7.x or earlier, this option is only recognized as
  # -pedantic without the leading W, but it's not worth the extra
  # logic for such an old compiler.
  if HAVE_C11
    candidate_warnings += '-Wpedantic'
  endif
  # -Werror is handled via meson's built-in --werror option.
  # get_supported_arguments doesn't accept the 'args' parameter
  # so we can't use it, sigh.
  foreach w : candidate_warnings
    if need_werror_unknown_option
      ok = cc.has_multi_arguments('-Werror=unknown-warning-option', w)
    else
      ok = cc.has_argument(w)
    endif
    if ok
      add_project_arguments(w, language: 'c')
    endif
  endforeach

  #
  # Linker-level hardening.
  # Meson already takes care of passing -z defs / --no-undefined
  # when possible.
  # FIXME: We're only checking that the linker *accepts*
  # the options, not that they do what we want them to do.
  candidate_fflags = [
    '-fno-plt'
  ]
  candidate_ldflags = [
    '-Wl,-z,text',
    '-Wl,-z,relro',
    '-Wl,-z,now',
  ]

  foreach f : candidate_fflags
    if cc.has_argument(f)
      add_project_arguments(f, language: 'c')
    endif
  endforeach

  foreach f: candidate_ldflags
    if cc.has_link_argument(f)
      add_project_link_arguments(f, language: 'c')
    endif
  endforeach

  # Testing for ld --wrap requires that we create _two_ object files
  # and link them together, which Meson's built in tests cannot do.
  # So we use an external script.
  r = run_command(python, S_check_ld_wrap, cc.cmd_array())
  if r.returncode() == 0
    message('Checking if linker supports --wrap: YES')
    HAVE_LD_WRAP = true
    cdata.set('HAVE_LD_WRAP', 1)
  elif r.returncode() == 1
    message('Checking if linker supports --wrap: NO')
    HAVE_LD_WRAP = false
  else
    warning('Checking if linker supports --wrap: ERROR')
    message('See meson-logs/meson-log.txt for details')
    HAVE_LD_WRAP = false
  endif

  # Similarly, testing for ld --version-script / -M requires a more
  # complicated sequence of link invocations than the built-in tests
  # can handle.  The logic in S_check_ld_vscript is borrowed from
  # ax_check_vscript.m4 but does not bother with HAVE_VSCRIPT_COMPLEX.
  if get_option('symvers') == 'false'
    HAVE_VSCRIPT = false
    VSCRIPT_LDFLAGS = ''
  else
    r = run_command(python, S_check_ld_vscript, cc.cmd_array())
    if r.returncode() == 0
      message('Checking if linker supports version scripts: YES')
      HAVE_VSCRIPT = true
      VSCRIPT_LDFLAGS = r.stdout().strip()
    elif r.returncode() == 1
      message('Checking if linker supports version scripts: NO')
      HAVE_VSCRIPT = false
      VSCRIPT_LDFLAGS = ''
    else
      warning('Checking if linker supports version scripts: ERROR')
      message('See meson-logs/meson-log.txt for details')
      HAVE_VSCRIPT = false
      VSCRIPT_LDFLAGS = ''
    endif
    if get_option('symvers') == 'true' and not HAVE_VSCRIPT
      error('-Dsymvers=true set, but linker does not support version scripts')
    endif
  endif

else
  HAVE_LD_WRAP = false
endif

# Feature selection macros.
# This is the moral equivalent of AC_USE_SYSTEM_EXTENSIONS plus the
# bits of AC_SYS_LARGEFILE that Meson doesn't bother with.
# These definitions need to be visible both to the project (via
# crypt-config.h) and to the tests below (via cflags_for_probe).
# Like Autoconf, we don't worry about conflicts among these macros
# unless we actually know of a problem (e.g. with __EXTENSIONS__ and
# _MINIX).
feature_selection_macros = [
  '_POSIX_SOURCE=1',
  '_POSIX_1_SOURCE=2',
  '_POSIX_C_SOURCE=200809L',
  '_XOPEN_SOURCE=700',
  '_ALL_SOURCE=1',
  '_DARWIN_C_SOURCE=1',
  '_DARWIN_USE_64_BIT_INODE=1',
  '_GNU_SOURCE=1',
  '_LARGE_FILES=1',
  '_POSIX_PTHREAD_SEMANTICS=1',
  '_TANDEM_SOURCE=1'
]
if cc.check_header('minix/config.h')
  feature_selection_macros += '_MINIX=1'
endif
if cc.compiles('''
#define __EXTENSIONS__ 1
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
''', name: 'Test of defining __EXTENSIONS__')
  feature_selection_macros += '__EXTENSIONS__=1'
endif
foreach m : feature_selection_macros
  cflags_for_probe += (_D + m)
  m = m.split('=')
  cdata.set(m[0], m[1])
endforeach

# Probe for C library headers.  Project policy is that headers may be
# used unconditionally if and only if they are required to be present
# in a C99 hosted environment.  For instance, no probe is required for
# <stdbool.h>, but a probe is required for <unistd.h>.
# Some probes below need to know header availability.
needed_headers = [
  'endian.h',
  'fcntl.h',
  'sys/cdefs.h',
  'sys/endian.h',
  'sys/param.h',
  'sys/random.h',
  'sys/stat.h',
  'sys/syscall.h',
  'sys/types.h',
  'unistd.h',
]
foreach h : needed_headers
  if cc.check_header(h, args: cflags_for_probe)
    m = 'HAVE_' + h.underscorify().to_upper()
    cdata.set(m, 1)
    cflags_for_probe += (_D + m + '=1')
  endif
endforeach

# Probe for C library functions.  Project policy is that functions may
# only be used unconditionally if they are required to be present in a
# C99 hosted environment.  Furthermore, if the existence of a non-C99
# header implies the presence of a non-C99 function, only the header
# needs to be checked for.  For instance, no probe is required for
# snprintf; open may be assumed to exist if fcntl.h and sys/stat.h
# exist; open64 needs to be checked for individually.
# Each array entry is a 2-tuple giving the name of the function and
# the name of the header that is expected to declare it.
needed_functions = [
  ['arc4random_buf',  'stdlib.h'],
  ['explicit_bzero',  'string.h'],
  ['explicit_memset', 'string.h'],
  ['getentropy',      'unistd.h'],
  ['getrandom',       'sys/random.h'],
  ['memset_s',        'string.h'],
  ['open64',          'fcntl.h'],
  ['syscall',         'unistd.h'],
]
foreach f : needed_functions
  fn = f[0]
  h = f[1]
  if (h == 'stdlib.h'
      or h == 'string.h'
      or cdata.has('HAVE_' + h.underscorify().to_upper()))
    if cc.has_function(fn, prefix: '#include <' + h + '>',
                       args: cflags_for_probe)
      cdata.set('HAVE_' + fn.underscorify().to_upper(), 1)
    endif
  endif
endforeach

# If we have none of these functions, compile a fallback.
INCLUDE_SECURE_ERASE = not (
     cdata.has('HAVE_MEMSET_S')
  or cdata.has('HAVE_EXPLICIT_BZERO')
  or cdata.has('HAVE_EXPLICIT_MEMSET')
)

# Atypical checks for features of the C compiler and library.

# Function annotation to suppress inlining (we only know how to do
# this GCC-style at the moment).
if cc.has_function_attribute('noinline')
  cdata.set('attribute_noinline', '__attribute__((noinline))')
else
  cdata.set('attribute_noinline', '')
endif


# static_assert (C11)
# Testing that 2 * 2 != 7 is in honor of Stanisław Lem.
if cc.compiles('''
_Static_assert(2 + 2 == 4, "arithmetic does not work");
_Static_assert(sizeof(char) == 1, "sizeof does not work");
''', name: 'Test 1 for _Static_assert (should succeed)', args: cflags_for_probe

) and not cc.compiles('''
_Static_assert(2 * 2 == 7, "this assertion should fail");
''',
    name: 'Test 2 for _Static_assert (should fail)',
    args: cflags_for_probe
)
  cdata.set('HAVE__STATIC_ASSERT', 1)
endif

if cc.compiles('''
#undef _NDEBUG
#include <assert.h>
static_assert(2 + 2 == 4, "arithmetic does not work");
static_assert(sizeof(char) == 1, "sizeof does not work");
''', name: 'Test 1 for static_assert in assert.h (should succeed)',
     args: cflags_for_probe
) and not cc.compiles('''
#undef _NDEBUG
#include <assert.h>
static_assert(2 * 2 == 7, "this assertion should fail");
''', name: 'Test 2 for static_assert in assert.h (should fail)',
     args: cflags_for_probe
)
  cdata.set('HAVE_STATIC_ASSERT_IN_ASSERT_H', 1)
endif

# convenience macros from <sys/cdefs.h>
if cdata.has('HAVE_SYS_CDEFS_H')
  if cc.compiles('''
#include <sys/cdefs.h>
__BEGIN_DECLS
extern int foo(void);
__END_DECLS
  ''', name: 'Test for __BEGIN_DECLS in sys/cdefs.h', args: cflags_for_probe)
    cdata.set('HAVE_SYS_CDEFS_BEGIN_END_DECLS', 1)
  endif

  if cc.compiles('''
#include <sys/cdefs.h>
extern void foo(void) __THROW;
  ''', name: 'Test for __THROW in sys/cdefs.h', args: cflags_for_probe)
    cdata.set('HAVE_SYS_CDEFS_THROW', 1)
  endif
endif

# Endianness.
#   The logic below is like AC_C_BIGENDIAN, but it doesn't try to determine
#   a final value at configure time.  Instead, it probes for a variety of
#   headers and compile-time macros that may or may not be available,
#   and uses them to guide preprocessor logic that makes the final
#   determination.  This works better with MacOS "universal binaries",
#   which may involve compiling the program twice under opposite
#   endiannesses; no fixed byte-order macro is correct in that case,
#   but the compiler's built-ins will be.  This approach is also
#   friendlier to cross-compilation.
#
#   This is the preprocessor logic that should be put in an appropriate
#   location, after including config.h:
#
#   #include <limits.h>
#   #ifdef HAVE_ENDIAN_H
#   #include <endian.h>
#   #endif
#   #ifdef HAVE_SYS_ENDIAN_H
#   #include <sys/endian.h>
#   #endif
#   #ifdef HAVE_SYS_PARAM_H
#   #include <sys/param.h>
#   #endif
#
#   #if ENDIANNESS_IS_BIG
#   # define ENDIAN_BIG
#   #elif ENDIANNESS_IS_LITTLE
#   # define ENDIAN_LITTLE
#   #else
#   # error "Unable to determine byte order"
#   #endif
#
#   We don't bother supporting what glibc's endian.h calls
#   "PDP_ENDIAN" (byte order within a 4-byte word of 3412,
#   where 1 is the least significant byte and 4 is the most).

endianness_options = [
  [ 'BYTE_ORDER and xxx_ENDIAN',
    'defined BYTE_ORDER && defined BIG_ENDIAN && defined LITTLE_ENDIAN && BIG_ENDIAN != LITTLE_ENDIAN',
    'BYTE_ORDER == BIG_ENDIAN',
    'BYTE_ORDER == LITTLE_ENDIAN',
  ],
  [ '__BYTE_ORDER and __xxx_ENDIAN',
    'defined __BYTE_ORDER && defined __BIG_ENDIAN && defined __LITTLE_ENDIAN && __BIG_ENDIAN != __LITTLE_ENDIAN',
    '__BYTE_ORDER == __BIG_ENDIAN',
    '__BYTE_ORDER == __LITTLE_ENDIAN',
  ],
  [ '__BYTE_ORDER__ and __xxx_ENDIAN__',
    'defined __BYTE_ORDER__ && defined __BIG_ENDIAN__ && defined __LITTLE_ENDIAN__ && __BIG_ENDIAN__ != __LITTLE_ENDIAN__',
    '__BYTE_ORDER__ == __BIG_ENDIAN__',
    '__BYTE_ORDER__ == __LITTLE_ENDIAN__',
  ],
  [ '__BYTE_ORDER__ and __ORDER_xxx_ENDIAN__',
    'defined __BYTE_ORDER__ && defined __ORDER_BIG_ENDIAN__ && defined __ORDER_LITTLE_ENDIAN__ && __ORDER_BIG_ENDIAN__ != __ORDER_LITTLE_ENDIAN__',
    '__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__',
    '__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__',
  ],
  [ '_BIG_ENDIAN and _LITTLE_ENDIAN',
    '(defined _BIG_ENDIAN) != (defined _LITTLE_ENDIAN)',
    'defined _BIG_ENDIAN',
    'defined _LITTLE_ENDIAN',
  ],
  [ '__BIG_ENDIAN__ and __LITTLE_ENDIAN__',
    '(defined __BIG_ENDIAN__) != (defined __LITTLE_ENDIAN__)',
    'defined __BIG_ENDIAN__',
    'defined __LITTLE_ENDIAN__',
  ],
  [ '__ARMEB__ and __ARMEL__',
    '(defined __ARMEB__) != (defined __ARMEL__)',
    'defined __ARMEB__',
    'defined __ARMEL__',
  ],
  [ '__THUMBEB__ and __THUMBEL__',
    '(defined __THUMBEB__) != (defined __THUMBEL__)',
    'defined __THUMBEB__', 'defined __THUMBEL__',
  ],
  [ '__AARCH64EB__ and __AARCH64EL__',
    '(defined __AARCH64EB__) != (defined __AARCH64EL__)',
    'defined __AARCH64EB__',
    'defined __AARCH64EL__',
  ],
  [ '__MIPSEB__ and __MIPSEL__',
    '(defined __MIPSEB__) != (defined __MIPSEL__)',
    'defined __MIPSEB__',
    'defined __MIPSEL__',
  ],
  [ '__MIPSEB and __MIPSEL',
    '(defined __MIPSEB) != (defined __MIPSEL)',
    'defined __MIPSEB',
    'defined __MIPSEL',
  ],
  [ '_MIPSEB and _MIPSEL',
    '(defined _MIPSEB) != (defined _MIPSEL)',
    'defined _MIPSEB',
    'defined _MIPSEL',
  ]
]
foreach o : endianness_options
  test_program = '''
#include <limits.h>
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if !(@0@)
#error fail
#endif
'''.format(o[1])
  if cc.compiles(test_program,
                 name: 'Test for endianness macros: ' + o[0],
                 args: cflags_for_probe)
    cdata.set('ENDIANNESS_IS_BIG', '(' + o[2] + ')')
    cdata.set('ENDIANNESS_IS_LITTLE', '(' + o[3] + ')')
    break
  endif
endforeach
if not cdata.has('ENDIANNESS_IS_BIG')
  error('Unable to determine byte order at compile time')
endif

# Alignment overrides.
# We don't bother checking for stdalign.h.

# Options for a declaration-specifier (in the sense in which C11 uses
# that term) that controls the alignment of the object being declared.
# The macro parameter N will only ever be an integer constant expression,
# not a type name.  Only usage that is permitted for C11's _Alignas
# needs to work.
alignas_options = [
  '_Alignas(n)', # C11
  '__attribute__((aligned(n)))' # GNU
]
foreach o : alignas_options
  test_program = '''
#define alignas(n) @0@
int alignas(8) global;
struct aggregate { int alignas(8) x; int y; };
void test(void) { int alignas(8) local; }
'''.format(o)
  if cc.compiles(test_program,
                 name: 'Alignment control using ' + o,
                 args: cflags_for_probe)
    cdata.set('alignas(n)', o)
    break
  endif
endforeach
if not cdata.has('alignas(n)')
  error('Unable to find a way to control data alignment')
endif

# Options for an expression which evaluates to the alignment of the
# macro parameter THING.  The construct must qualify as an integer
# constant expression, in the sense in which the C standard uses that
# term (e.g. it must be acceptable as the size of an array with static
# storage duration).
alignof_options = [
  '_Alignof(thing)',    # C11
  '__alignof__(thing)', # GNU
]
foreach o : alignof_options
  test_program = '''
#define alignof(thing) @0@
struct agg { int x, y; };
extern const char align_int[alignof(int)];
extern const char align_agg[alignof(struct agg)];
void test(void)
{
  double d;
  char align_var[alignof(d)];
}
'''.format(o)
  if cc.compiles(test_program,
                 name: 'Alignment queries using ' + o,
                 args: cflags_for_probe)
    cdata.set('alignof(thing)', o)
    cflags_for_probe += (_D + 'alignof(thing)=' + o)
    break
  endif
endforeach
if not cdata.has('alignof(thing)')
  error('Unable to find a way to query data alignment')
endif

# Does stddef.h provide max_align_t?
# This test uses the alignof() macro defined above.
if cc.compiles('''
#include <stddef.h>
size_t test(void)
{
  max_align_t var;
  return alignof(var);
}
''', name: 'Test for max_align_t in stddef.h',
     args: cflags_for_probe
)
  cdata.set('HAVE_MAX_ALIGN_T', 1)
endif

# Generate config.h from the data gleaned above.
configure_file(output: 'crypt-config.h',
               configuration: cdata)
I_config_h = include_directories('.')

# Subdirectories containing code, documentation, and tests, respectively.
subdir('lib')
subdir('doc')
subdir('test')

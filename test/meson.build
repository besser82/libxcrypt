# Meson build logic for libcrypt: tests.
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

# The known-answer tests are all compiled from the same source code
# with a different TEST_* macro defined for each.  They optionally
# test an obsolete function, so they must be linked with the shared
# library if possible.  Some of them are very slow, so we bump up the
# timeout and we give them priorities according to how slow they are.
# The number on the right-hand side of the table below is the
# wall-clock time required for each test program on a reasonably beefy
# x86-64 box in early 2020, rounded to the nearest second, which
# translates directly to a Meson test priority.  The per-test timeout
# is chosen to be a little more than twice what the slowest test
# actually requires.
foreach hash, time : {
  'bcrypt'         : 3,
  'bcrypt-a'       : 3,
  'bcrypt-x'       : 3,
  'bcrypt-y'       : 3,
  'bigcrypt'       : 0,
  'bsdicrypt'      : 0,
  'descrypt'       : 0,
  'gost-yescrypt'  : 2,
  'md5crypt'       : 0,
  'nt'             : 0,
  'scrypt'         : 1,
  'sha1crypt'      : 1,
  'sha256crypt'    : 4,
  'sha512crypt'    : 3,
  'sunmd5'         : 50,
  'yescrypt'       : 3,
}
  test('ka-'+hash,
       executable(
         'ka-'+hash,
         sources: 'ka-tester.c',
         dependencies: [libcrypt_dep],
         c_args: [_D + 'TEST_' + hash.underscorify()]),
      timeout: 120,
      priority: time)
endforeach

# simple compiled-code tests
foreach t : [
  'alg-des',
  'alg-gost3411-2012',
  'alg-gost3411-2012-hmac',
  'alg-hmac-sha1',
  'alg-md4',
  'alg-md5',
  'alg-pbkdf-hmac-sha256',
  'alg-sha1',
  'alg-sha256',
  'alg-sha512',
  'alg-yescrypt',
  'badsalt',
  'badsetting',
  'byteorder',
  'checksalt',
  'compile-strong-alias',
  'crypt-badargs',
  'crypt-gost-yescrypt',
  'gensalt',
  'gensalt-extradata',
  'gensalt-nthash',
  'getrandom-interface',
  'preferred-method',
  'short-outbuf',
]
  test(t, executable(t,
                     sources: [t + '.c'],
                     dependencies: [libcrypt_a_dep]))
endforeach

# compiled-code tests requiring special options
# getrandom-fallbacks wants to wrap system calls to verify what happens
# when they fail
if HAVE_LD_WRAP
getrandom_fallbacks_LDFLAGS = [
  '-Wl,--wrap,close',
  '-Wl,--wrap,getentropy',
  '-Wl,--wrap,getrandom',
  '-Wl,--wrap,open',
  '-Wl,--wrap,open64',
  '-Wl,--wrap,read',
  '-Wl,--wrap,syscall',
]
else
getrandom_fallbacks_LDFLAGS = []
endif
test('getrandom-fallbacks',
     executable('getrandom-fallbacks',
                sources: ['getrandom-fallbacks.c'],
                dependencies: [libcrypt_a_dep],
                link_args: getrandom_fallbacks_LDFLAGS))

# tests of the obsolete functions in the shared library, must be linked
# against the shared library; they do not use any of the internal
# functions that are only available from the static library
if ENABLE_OBSOLETE_API
foreach t : [
  'des-obsolete',
  'des-obsolete_r',
  'fcrypt-enosys',
]
  test(t, executable(t,
                     sources: [t + '.c'],
                     dependencies: [libcrypt_so_dep]))
endforeach
endif

# symbol versioning tests

if get_option('default_library') != 'shared' # 'static' or 'both'
test('symbols-static', python,
     args: [S_test_symbols_static, libcrypt_a, libcrypt_map_in])

if HAVE_CPP_dD
test('symbols-renames', python,
     args: [S_test_symbols_renames, libcrypt_a] + cc.cmd_array() + [
             '-I' + meson.current_build_dir() / '..',
             '-I' + meson.current_build_dir() / '../lib',
             '-I' + meson.current_source_dir() / '..',
             '-I' + meson.current_source_dir() / '../lib'
           ])
endif
endif

if ENABLE_OBSOLETE_API
test('symbols-compat', python,
     args: [S_test_symbols_compat, libcrypt_so] + cc.cmd_array())
endif

# regeneration of crypt-kat.inc
# not run by default because it requires unusual software and is
# painfully slow
if ENABLE_KA_TABLE_GEN
run_target('regen-ka-table',
           command: [python, 'ka-table-gen'],
           depends: [libcrypt_so])
endif

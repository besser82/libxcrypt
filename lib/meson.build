# Meson build logic for libcrypt: core library.
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

# Generated internal headers, the version map, etc.
crypt_hashes_h = custom_target(
  'crypt-hashes.h',
  output: ['crypt-hashes.h'],
  input: ['hashes.conf'],
  command: [python, S_gen_crypt_hashes_h,
            '--hashes='+ENABLED_HASHES,
            '@OUTPUT@', '@INPUT@']
)

libcrypt_map_in = files('libcrypt.map.in')
crypt_symbol_vers_h = custom_target(
  'crypt-symbol-vers.h',
  output: ['crypt-symbol-vers.h'],
  input: [libcrypt_map_in],
  command: [python, S_gen_crypt_symbol_vers_h,
            '--symver-min=' + SYMVER_MIN,
            '--symver-floor=' + SYMVER_FLOOR,
            '--compat-api=' + COMPAT_API,
            '@OUTPUT@', '@INPUT@']
)

libcrypt_map = custom_target(
  'libcrypt.map',
  output: ['libcrypt.map'],
  input: ['libcrypt.map.in'],
  command: [python, S_gen_libcrypt_map,
            '--symver-min='+SYMVER_MIN,
            '--symver-floor='+SYMVER_FLOOR,
            '--compat-api='+COMPAT_API,
            '@OUTPUT@', '@INPUT@']
)
libcrypt_2_map = files('libcrypt.2.map')[0]

# Public headers.
# crypt.h and xcrypt.h have to be separate targets because xcrypt.h
# may or may not be installed, depending on configuration.
gen_crypt_h_cmd = [
  python, S_gen_crypt_h,
  '--xcrypt-version=' + meson.project_version(),
  '--cdefs-h=' + cdata.has('HAVE_SYS_CDEFS_H').to_string(),
  '--cdefs-throw=' + cdata.has('HAVE_SYS_CDEFS_THROW').to_string(),
  '--cdefs-decls=' + cdata.has('HAVE_SYS_CDEFS_BEGIN_END_DECLS').to_string(),
  '--hashes-h=' + crypt_hashes_h.full_path(),
  '@OUTPUT@', '@INPUT@'
]

crypt_h = custom_target(
  'crypt.h',
  output: ['crypt.h'],
  input: ['crypt.h.in'],
  depends: [crypt_hashes_h],
  command: gen_crypt_h_cmd,
  install: true,
  install_dir: get_option('includedir')
)
xcrypt_h = custom_target(
  'xcrypt.h',
  output: ['xcrypt.h'],
  input: ['xcrypt.h.in'],
  depends: [crypt_hashes_h],
  command: gen_crypt_h_cmd,
  install: get_option('xcrypt-compat-files'),
  install_dir: get_option('includedir')
)

# The main library.
# We cannot use library() or both_libraries(), because:
#  - the compatibility symbols go only in the shared library
#  - we need to compile the shared library with different preprocessor
#    defines so the symbol versioning will work right
#  - many of the tests refer to internal symbols, and the easiest way
#    to make that possible is to link them unconditionally with the
#    static library
#
# Therefore, the static library is always built, but is only installed
# when build options request it.

libcrypt_a_sources = files([
  'alg-des.c',
  'alg-des-tables.c',
  'alg-gost3411-2012-core.c',
  'alg-gost3411-2012-hmac.c',
  'alg-hmac-sha1.c',
  'alg-md4.c',
  'alg-md5.c',
  'alg-sha1.c',
  'alg-sha256.c',
  'alg-sha512.c',
  'alg-yescrypt-common.c',
  'alg-yescrypt-opt.c',
  'entry-checksalt.c',
  'entry-crypt.c',
  'entry-crypt-r.c',
  'entry-crypt-ra.c',
  'entry-crypt-rn.c',
  'entry-gensalt.c',
  'entry-gensalt-ra.c',
  'entry-gensalt-rn.c',
  'entry-preferred-method.c',
  'fn-ascii64.c',
  'fn-do-crypt.c',
  'fn-gensalt-sha.c',
  'fn-get-hashfn.c',
  'fn-make-failure-token.c',
  'fn-randombytes.c',
  'fn-secure-memset.c',
  'fn-strcpy-or-abort.c',
  'hm-bcrypt.c',
  'hm-des.c',
  'hm-gost-yescrypt.c',
  'hm-md5.c',
  'hm-nthash.c',
  'hm-pbkdf1-sha1.c',
  'hm-scrypt.c',
  'hm-sha256.c',
  'hm-sha512.c',
  'hm-sunmd5.c',
  'hm-yescrypt.c',
]) + [
  # these files may need any of the generated headers
  crypt_h, xcrypt_h, crypt_hashes_h, crypt_symbol_vers_h,
]

libcrypt_so_sources = libcrypt_a_sources
if ENABLE_OBSOLETE_API
  libcrypt_so_sources += files([
    'entry-encrypt-setkey.c',
    'entry-fcrypt.c',
  ])
endif

if HAVE_VSCRIPT
  libcrypt_so_extra_args = {
    'link_depends': [libcrypt_map],
    'link_args': ['-Wl,@0@,@1@'.format(
      VSCRIPT_LDFLAGS, libcrypt_map.full_path())]
  }
else
  libcrypt_so_extra_args = {}
endif

libcrypt_so = shared_library(
  'crypt',
  soversion: ENABLE_OBSOLETE_API ? '1' : '2',
  sources: libcrypt_so_sources,
  c_args: ['-DIN_LIBCRYPT', '-DPIC'],
  include_directories: I_config_h,
  install: INSTALL_SHARED_LIB,
  kwargs: libcrypt_so_extra_args
)

libcrypt_a_internal = static_library(
  'crypt-internal',
  sources: libcrypt_a_sources,
  c_args: ['-DIN_LIBCRYPT'],
  include_directories: I_config_h,
  install: false
)

libcrypt_a = custom_target(
  'libcrypt.a',
  output: 'libcrypt.a',
  input: libcrypt_a_internal,
  command: [python, S_rename_internal_symbols,
            '_crypt_', libcrypt_2_map, '@INPUT@', '@OUTPUT@'],
  install_dir: get_option('libdir'),
  install: INSTALL_STATIC_LIB,
)

# Needed by the tests.
I_lib = include_directories('.')
libcrypt_a_internal_dep = declare_dependency(
  sources: [crypt_h, xcrypt_h],
  link_with: [libcrypt_a_internal],
  include_directories: [I_config_h, I_lib],
)
libcrypt_a_dep = declare_dependency(
  sources: [crypt_h, xcrypt_h],
  # libcrypt_a is not a library object, but putting it in link_with seems
  # to work fine anyway.
  link_with: [libcrypt_a],
  include_directories: [I_config_h, I_lib],
)
libcrypt_so_dep = declare_dependency(
  sources: [crypt_h, xcrypt_h],
  link_with: [libcrypt_so],
  include_directories: [I_config_h, I_lib],
)

# For programs that should be linked against the shared library if it
# exists, the static library otherwise.
if get_option('default_library') == 'static'
libcrypt_dep = libcrypt_a_dep
else
libcrypt_dep = libcrypt_so_dep
endif

# Generate and install a .pc file.

# As of meson 0.52, when pkg.generate is passed a static library, the
# generated .pc file is (at least in this relatively simple case)
# correct for both that static library and for the matching shared
# library.  However, the reverse is not true: meson's handling of
# Libs.private, when pkg.generate is passed a shared library, produces
# a .pc file that is correct for that shared library but *not* for the
# matching static library.  So we give it the static library regardless
# of what we're actually going to install.
pkg = import('pkgconfig')
pkg.generate(libcrypt_a_internal,
  description: 'Extended crypt library for DES, MD5, Blowfish and others',
  filebase: 'libxcrypt',
  name: 'libxcrypt',
)

# Compatibility symlinks for libcrypt.a and libcrypt.so.
# FIXME all calls to add_install_script below should really look like
# add_install_script(python, S_install_symlink, ...) but that doesn't
# work, because of https://github.com/mesonbuild/meson/issues/6175
if get_option('xcrypt-compat-files')
  if INSTALL_SHARED_LIB
    meson.add_install_script('../scripts/install-symlink',
                             get_option('libdir'),
                             'libcrypt.so', 'libxcrypt.so')
  endif
  if INSTALL_STATIC_LIB
    meson.add_install_script('../scripts/install-symlink',
                             get_option('libdir'),
                             'libcrypt.a', 'libxcrypt.a')
  endif
endif

if ENABLE_COMPAT_SUSE
  # SUSE shipped an older version of libxcrypt under the name of libowcrypt
  # (presumably ow stands for Openwall).  Install compatiblity symlinks.
  # In this case we also need a symlink for libowcrypt.so.1.
  # Appropriate symbol versions (OW_CRYPT_1.0) are already included in
  # libcrypt.so.1.
  #
  # Caution: this hardwires the expected (so)names of the shared
  # libraries involved, libcrypt.so.1 and libowcrypt.so.1.  (We should
  # be able to get away with this because in any circumstance where the
  # soname of libcrypt isn't libcrypt.so.1, ENABLE_COMPAT_SUSE should
  # be automatically turned off, and as best I can tell, SUSE only ever
  # shipped libowcrypt.so.1.)
  if INSTALL_SHARED_LIB
    meson.add_install_script('../scripts/install-symlink',
                             get_option('libdir'),
                             'libcrypt.so', 'libowcrypt.so')
    meson.add_install_script('../scripts/install-symlink',
                             get_option('libdir'),
                             'libcrypt.so.1', 'libowcrypt.so.1')
  endif
  if INSTALL_STATIC_LIB
    meson.add_install_script('../scripts/install-symlink',
                             get_option('libdir'),
                             'libcrypt.a', 'libowcrypt.a')
  endif
endif

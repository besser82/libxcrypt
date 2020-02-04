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
            '@OUTPUT@', '@INPUT@'],
  build_by_default: false,
  install: false,
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
            '@OUTPUT@', '@INPUT@'],
  build_by_default: false,
  install: false,
)

libcrypt_map = custom_target(
  'libcrypt.map',
  output: ['libcrypt.map'],
  input: ['libcrypt.map.in'],
  command: [python, S_gen_libcrypt_map,
            '--symver-min='+SYMVER_MIN,
            '--symver-floor='+SYMVER_FLOOR,
            '--compat-api='+COMPAT_API,
            '@OUTPUT@', '@INPUT@'],
  build_by_default: false,
  install: false,
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
  build_by_default: true,
  install: true,
  install_dir: get_option('includedir'),
)
xcrypt_h = custom_target(
  'xcrypt.h',
  output: ['xcrypt.h'],
  input: ['xcrypt.h.in'],
  depends: [crypt_hashes_h],
  command: gen_crypt_h_cmd,
  build_by_default: get_option('xcrypt-compat-files'),
  install: get_option('xcrypt-compat-files'),
  install_dir: get_option('includedir'),
)

# The secure_erase() fallback, if needed, must be compiled separately
# from the rest of the library, with link-time optimization explicitly
# disabled.  Since meson doesn't currently support per-object-file
# compilation flags (https://github.com/mesonbuild/meson/issues/3345),
# the only way to do this is with a shim static library.
secure_erase_src = []
if INCLUDE_SECURE_ERASE
  secure_erase_src += 'fn-secure-erase.c'
endif
lib_secure_erase = static_library(
  'secure-erase',
  sources: secure_erase_src,
  include_directories: I_config_h,
  override_options: ['unity=off', 'b_lto=false', 'b_staticpic=true'],
  build_by_default: false,
  install: false,
)


# The main library: installed as libcrypt.a and libcrypt.so.2.
libcrypt_2_sources = files([
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
  # of the generated headers, these files only require crypt.h and
  # crypt_hashes.h
  crypt_h,
  crypt_hashes_h,
]

# if we use libcrypt_2_map in the format() call, it will incorrectly
# reference a nonexistent lib/libcrypt.2.map in the *build* tree
if HAVE_VSCRIPT
libcrypt_so_2_extra_args = {
    'link_depends': [libcrypt_2_map],
    'link_args': ['-Wl,@0@,@1@'.format(
      VSCRIPT_LDFLAGS, meson.current_source_dir() / 'libcrypt.2.map')]
  }
else
  libcrypt_so_2_extra_args = {}
endif

# We do not use library() or both_libraries() because we want to
# rename all the internal symbols in libcrypt.a, which is done with
# a postprocessing step.

# The static library we get by compiling all the source files normally.
# For internal use only.
libcrypt_internal = static_library(
  'crypt-internal',
  sources: libcrypt_2_sources,
  link_whole: lib_secure_erase,
  include_directories: I_config_h,
  build_by_default: false,
  install: false,
  override_options: ['b_staticpic=true'],
)

# The installed shared library.
libcrypt_so_2 = shared_library(
  'crypt',
  soversion: '2',
  link_whole: [libcrypt_internal, lib_secure_erase],
  include_directories: I_config_h,
  build_by_default: INSTALL_SHARED_LIB,
  install: INSTALL_SHARED_LIB,
  kwargs: libcrypt_so_2_extra_args,
)

# The installed static library is generated from the internal static
# library by renaming all the internal symbols using 'objcopy'.  This
# approximates the effect of hiding the internals of the shared
# library with a version script.

libcrypt_internal_exports = custom_target(
  'libcrypt-internal.a.exports',
  output: 'libcrypt-internal.a.exports',
  input: libcrypt_internal,
  command: [nm,
            '--print-file-name', '--format=bsd',
            '--extern-only', '--defined-only', '--no-sort',
            '@INPUT@'],
  capture: true,
  build_by_default: false,
  install: false,
)

libcrypt_a_renames = custom_target(
  'libcrypt.a.renames',
  output: 'libcrypt.a.renames',
  input: [libcrypt_internal_exports, libcrypt_2_map],
  command: [python, S_compute_symbol_renames,
            '-p', '_crypt_', '-o', '@OUTPUT@', '@INPUT@'],
  build_by_default: false,
  install: false,
)

libcrypt_a = custom_target(
  'libcrypt.a',
  output: 'libcrypt.a',
  input: [libcrypt_a_renames, libcrypt_internal],
  command: [objcopy, '--redefine-syms', '@INPUT0@', '@INPUT1@', '@OUTPUT@'],
  build_by_default: INSTALL_STATIC_LIB,
  install: INSTALL_STATIC_LIB,
  install_dir: get_option('libdir'),
)

# Link most tests against the shared library if it exists, the static
# library otherwise.  libcrypt_a is not a library object, but putting
# it in link_with seems to work fine anyway.
I_lib = include_directories('.')
if INSTALL_SHARED_LIB
libcrypt_dep = declare_dependency(
  sources: [crypt_h],
  link_with: [libcrypt_so_2],
  include_directories: [I_config_h, I_lib]
)
else
libcrypt_dep = declare_dependency(
  sources: [crypt_h],
  link_with: [libcrypt_a],
  include_directories: [I_config_h, I_lib],
)
endif

# Generate and install a .pc file.
# As of meson 0.52, when pkg.generate is passed a static library, the
# generated .pc file is (at least in this relatively simple case)
# correct for both that static library and for the matching shared
# library.  However, the reverse is not true: meson's handling of
# Libs.private, when pkg.generate is passed a shared library, produces
# a .pc file that is correct for that shared library but *not* for the
# matching static library.  So we give it the static library
# regardless of what we're actually going to install.  We give it the
# *internal* static library because that's always built, and the
# symbol rewriting on the installed static library doesn't affect the
# contents of the .pc file.
pkg = import('pkgconfig')
pkg.generate(libcrypt_internal,
  description: 'Extended crypt library for DES, MD5, Blowfish and others',
  filebase: 'libxcrypt',
  name: 'libxcrypt',
)

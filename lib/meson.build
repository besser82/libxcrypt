

crypt_hashes_h = custom_target('crypt-hashes.h',
    input: 'hashes.conf',
    output: 'crypt-hashes.h',
    command: [
        'env', 'LC_ALL=C',
        awk,
        '-v', 'ENABLED_HASHES=@0@'.format(','.join(hashes_enabled)),
        '-f', files('gen-hashes.awk'),
        '@INPUT@',
    ],
    capture: true,
)

xcrypt_h = custom_target('xcrypt.h',
    output: 'xcrypt.h',
    input: 'xcrypt.h.in',
    command: [
        'env', 'LC_ALL=C',
        awk, '-f', files('gen-crypt-h.awk'), config_h, '@INPUT@',
    ],
    capture: true,
)

crypt_symbol_vers_h = custom_target('crypt-symbol-vers.h',
    output: 'crypt-symbol-vers.h',
    input: 'libcrypt.map.in',
    command: [
        'env', 'LC_ALL=C',
        awk,
        '-v', 'SYMVER_MIN=@0@'.format(  symver_min),
        '-v', 'SYMVER_FLOOR=@0@'.format(symver_floor),
        '-v', 'COMPAT_ABI=@0@'.format(  obsolete_api),
        '-f', files('gen-vers.awk'),
        '@INPUT@'
    ],
    capture: true,
)

crypt_h_in = configure_file(
    input: 'crypt.h.in.in',
    output: 'crypt.h.in',
    configuration: config,
)
crypt_h_in2 = custom_target('crypt.h.in2',
    input:  [ config_h, crypt_h_in, ],
    output: 'crypt.h.in2',
    command: [
        'env', 'LC_ALL=C',
        awk, '-f', files('gen-crypt-h.awk'), '@INPUT@'
    ],
    capture: true,
)

custom_target('crypt.h',
    input: [ crypt_h_in2, crypt_hashes_h ],
    output: 'crypt.h',
    command: [ find_program('gen-crypt-h-bis.sh'), '@INPUT@', ],
    capture: true,
    install: true,
    install_dir: get_option('includedir'),
)


libcrypt_gen_headers = [ crypt_hashes_h, xcrypt_h, crypt_symbol_vers_h ]

libcrypt_sources = [
    'alg-des-tables.c',
    'alg-des.c',
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
    'crypt-bcrypt.c',
    'crypt-common.c',
    'crypt-des.c',
    'crypt-gensalt-static.c',
    'crypt-gensalt.c',
    'crypt-gost-yescrypt.c',
    'crypt-md5.c',
    'crypt-nthash.c',
    'crypt-pbkdf1-sha1.c',
    'crypt-scrypt.c',
    'crypt-sha256.c',
    'crypt-sha512.c',
    'crypt-static.c',
    'crypt-sunmd5.c',
    'crypt-yescrypt.c',
    'crypt.c',
    'randombytes.c',
    libcrypt_gen_headers,
]
if enable_obsolete_api
    libcrypt_sources += 'crypt-des-obsolete.c'
endif

###############################################################################
# Output variables

lib_include = include_directories('.')

libcrypt = library('crypt',
    libcrypt_sources,
    include_directories: root_include,
    c_args: '-DIN_LIBCRYPT',
    install: true,
)

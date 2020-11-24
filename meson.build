project('xcrypt',
    'c',

    default_options: [
        'c_std=gnu11',
    ],
    version: '4.4.18',

    meson_version: '>=0.51.0'
)


pythonmod = import('python')

cc = meson.get_compiler('c')


###############################################################################
# Project configuration

config = configuration_data()
config_data = configuration_data()


project_url = 'https://github.com/besser82/libxcrypt'

project_version = meson.project_version()
xcrypt_version_major = project_version.split('.')[0]
xcrypt_version_minor = project_version.split('.')[1]


###############################################################################
# Build tools

awk = find_program('awk')

# Check python installation
python = pythonmod.find_installation()

enable_ka_table_gen = false
if not python.language_version().version_compare('>=3.6')
    warning('Python was found but >=3.6 is required !')
elif not pythonmod.find_installation(required: false, modules: 'passlib').found()
    warning('Python was found but module "patlib" is required !')
else
    enable_ka_table_gen = true
endif

static_libs_enabled = [ 'static', 'both' ].contains(get_option('default_library'))

###############################################################################
# Check build environment

c_std = get_option('c_std')
if c_std == 'none' or c_std == 'c89' or c_std == 'gnu89'
    error('a C99- or C11-compliant compiler is required')
endif

check_arguments = [
    '-dD',
    '-fno-plt',
]
foreach arg : check_arguments
    if not cc.has_argument(arg)
        error('Compiler does not support argument ' + arg)
    endif
endforeach
check_link_arguments = [
    '-Wl,-no-undefined',
    '-Wl,-z,text',
    '-Wl,-z,relro',
    '-Wl,-z,now',
]
foreach arg : check_link_arguments
    if not cc.has_link_argument(arg)
        error('Linker does not support ' + arg)
    endif
endforeach
# TODO check in sys/cdefs.h



check_headers = [
    'fcntl.h',
    'stdbool.h',
    'sys/cdefs.h',
    'sys/random.h',
    'sys/syscall.h',
    'sys/types.h',
    'endian.h',
    'sys/endian.h',
    'sys/param.h',
    'sys/stat.h',
    'unistd.h',
]
check_functions = [
  'arc4random_buf',
  'explicit_bzero',
  'explicit_memset',
  'getentropy',
  'getrandom',
  'memset_s',
  'open64',
  'syscall',
]

foreach header : check_headers
    config.set('HAVE_' + header.underscorify().to_upper(), cc.has_header(header) ? 1 : false)
endforeach
foreach function : check_functions
    config.set('HAVE_' + function.underscorify().to_upper(), cc.has_function(function) ? 1 : false)
endforeach



config.set10('ENDIANNESS_IS_BIG',     host_machine.endian() == 'big')
config.set10('ENDIANNESS_IS_LITTLE',  host_machine.endian() == 'little')
config.set10('ENDIANNESS_IS_PDP',     host_machine.endian() == 'pdp')


config.set('HAVE_SYS_CDEFS_THROW', cc.has_header_symbol('sys/cdefs.h', '__THROW') ? 1 : false)
config.set('HAVE_STATIC_ASSERT_IN_ASSERT_H', cc.has_header_symbol('assert.h', 'static_assert') ? 1 : false)
config.set('HAVE_MAX_ALIGN_T', cc.has_header_symbol('stddef.h', 'max_align_t') ? 1 : false)


alignas_test_code = '''
#define n 8
int     @0@ global;
struct  @0@ aggregate { int x, y; };
int     @0@ local;
'''

alignas = '_Alignas(n)'
if not cc.compiles(alignas_test_code.format(alignas))
alignas = '__attribute__((__aligned__(n)))'
    if not cc.compiles(alignas_test_code.format(alignas))
        error('No method found for alignas !')
    endif
endif
message('Found alignas method: ' + alignas)
config.set('alignas(n)', alignas)

alignof_test_code = '''
struct agg { int x, y; };
extern const char align_int[@0@(int)];
extern const char align_agg[@0@(struct agg)];
int main() {
    double d;
    char align_var[@0@(d)];
}
'''

alignof = '__alignof__'
if not cc.compiles(alignof_test_code.format(alignof))
    alignof = '_Alignof'
    if not cc.compiles(alignof_test_code.format(alignof))
        error('No method found for alignof !')
    endif
endif
message('Found alignof method: ' + alignof)
config.set('alignof(thing)', alignof + '(thing)')

have_ld_wrap = cc.has_link_argument('-Wl,--wrap')
config.set('HAVE_LD_WRAP', have_ld_wrap)

###############################################################################
# Check options

config.set10('ENABLE_FAILURE_TOKENS', get_option('failure-tokens'))

obsolete_api = get_option('obsolete-api')
enable_obsolete_api = (obsolete_api != 'no')
enable_compat_suse = (obsolete_api == 'yes' or obsolete_api == 'suse')


hashes_selected = get_option('hashes')
hashes_enabled = run_command('awk',
    '-f', files('lib/sel-hashes.awk'),
    '-v', 'SELECTED_HASHES=@0@'.format(','.join(hashes_selected)),
    files('lib/hashes.conf'),
).stdout().split(',')


# If the traditional DES hash is disabled, then the obsolete APIs are
# implicitly disabled, except when stubs are requested.
if (not ('descrypt' in hashes_enabled)) and (enable_obsolete_api)
    warning('Disabling DES hash forces obsolete-api=no')
    enable_obsolete_api = false
    enable_compat_suse = false
endif

# If the obsolete APIs are disabled, the stubs implicitly disabled as well.
obsolete_api_enosys = get_option('obsolete-api-enosys')
if obsolete_api_enosys and (not enable_obsolete_api)
    warning('Disabling obsolete APIs implies disabling obsolete-api-enosys')
    obsolete_api_enosys = false
endif

install_xcrypt_compat_files = get_option('xcrypt-compat-files')
if install_xcrypt_compat_files and (not enable_obsolete_api)
    warning('Disabling obsolete APIs forbids installation of xcrypt compat files')
    install_xcrypt_compat_files = false
endif


###############################################################################
# Determine whether there's even a GNU libc on this system that we
# need to be binary backward compatible with.

os = host_machine.system()
minver_os = ''
if os == 'linux'
    minver_os = 'linux'
elif os == 'freebsd'
    minver_os = 'kfreebsd'
elif os == 'gnu'
    minver_os = 'hurd'
endif

# TODO match in lib/libcrypt.minver.@minver_os@
symver_floor = 'GLIBC_2.27'
symver_min = 'GLIBC_2.27'

config.set('SYMVER_FLOOR', symver_floor)
config.set10('ENABLE_OBSOLETE_API', enable_obsolete_api)
config.set10('ENABLE_OBSOLETE_API_ENOSYS', obsolete_api_enosys)

config.set('DEFAULT_PREFIX_ENABLED', '@DEFAULT_PREFIX_ENABLED@')

###############################################################################
config.set('PACKAGE_VERSION',       project_version)
config.set('XCRYPT_VERSION_MAJOR',  xcrypt_version_major)
config.set('XCRYPT_VERSION_MINOR',  xcrypt_version_minor)


config_data.set('PACKAGE',      meson.project_name())
config_data.set('VERSION',      project_version)
config_data.set('prefix' ,      get_option('prefix'))
config_data.set('includedir',   get_option('includedir'))
config_data.set('libdir',       get_option('libdir'))


config_h = configure_file(
    output: 'config.h',
    configuration: config,
)

configure_file(
    input: 'lib/libxcrypt.pc.in',
    output: 'libxcrypt.pc',
    configuration: config_data,
)

add_project_arguments('-DHAVE_CONFIG_H', language: 'c')

###############################################################################

root_include = include_directories('.')

subdir('doc')
subdir('lib')
subdir('test')

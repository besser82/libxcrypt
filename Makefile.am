#
# Copyright (c) 2002, 2007 SuSE Linux AG, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = \
	1.14 gnits dist-bzip2 dist-xz filename-length-max=99

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = $(WARN_CFLAGS) $(OPTI_FLAGS)

AM_LDFLAGS = $(RELRO_FLAG) $(BINDNOW_FLAG)

@VALGRIND_CHECK_RULES@

TEST_EXTENSIONS = .sh

EXTRA_DIST = \
	LICENSING THANKS \
	crypt.h.in.in xcrypt.h.in libcrypt.map.in \
	libcrypt.minver gen-map.awk gen-vers.awk \
	gen-crypt-h.awk gen-hashes.awk sel-hashes.awk \
	hashes.lst

notrans_dist_man3_MANS = \
	crypt.3 crypt_r.3 crypt_ra.3 crypt_rn.3 \
	crypt_checksalt.3 crypt_gensalt.3 crypt_gensalt_ra.3 \
	crypt_gensalt_rn.3 crypt_preferred_method.3
notrans_dist_man5_MANS = crypt.5

nodist_include_HEADERS = crypt.h
nodist_noinst_HEADERS = crypt-hashes.h crypt-symbol-vers.h
noinst_HEADERS = \
	alg-des.h alg-gost3411-2012-const.h alg-gost3411-2012-core.h \
	alg-gost3411-2012-hmac.h alg-gost3411-2012-precalc.h \
	alg-gost3411-2012-ref.h alg-hmac-sha1.h alg-md4.h alg-md5.h \
	alg-sha1.h alg-sha256.h alg-sha512.h alg-yescrypt.h \
	alg-yescrypt-sysendian.h byteorder.h crypt-common.h \
	crypt-obsolete.h crypt-port.h test-des-cases.h

if ENABLE_XCRYPT_COMPAT_FILES
nodist_include_HEADERS += xcrypt.h
else
nodist_noinst_HEADERS += xcrypt.h
endif


noinst_PROGRAMS = gen-des-tables

lib_LTLIBRARIES = libcrypt.la
libcrypt_la_SOURCES = \
	alg-des.c alg-des-tables.c alg-gost3411-2012-core.c \
	alg-gost3411-2012-hmac.c alg-hmac-sha1.c alg-md4.c alg-md5.c \
	alg-sha1.c alg-sha256.c alg-sha512.c alg-yescrypt-opt.c \
	alg-yescrypt-common.c crypt.c crypt-bcrypt.c crypt-des.c \
	crypt-gensalt-static.c crypt-gensalt.c crypt-gost-yescrypt.c \
	crypt-md5.c crypt-nthash.c crypt-pbkdf1-sha1.c crypt-scrypt.c \
	crypt-sha256.c crypt-sha512.c crypt-static.c crypt-sunmd5.c \
	crypt-yescrypt.c randombytes.c crypt-common.c

EXTRA_DIST += alg-yescrypt-platform.c

pkgconfig_DATA = libxcrypt.pc

# Install libcrypt.pc symlink to libxcrypt.pc file.
phony_targets = \
	install-data-hook-pkgconfig uninstall-hook-pkgconfig
install-data-hook: install-data-hook-pkgconfig
uninstall_hook_targets = \
	uninstall-hook-pkgconfig
install-data-hook-pkgconfig:
	cd $(DESTDIR)$(pkgconfigdir) && \
		$(LN_S) libxcrypt.pc libcrypt.pc
uninstall-hook-pkgconfig:
	-rm -f $(DESTDIR)$(pkgconfigdir)/libcrypt.pc

# Build libcrypt.so.2 if obsolete APIs are excluded, libcrypt.so.1 otherwise.
if ENABLE_OBSOLETE_API
libcrypt_la_VERSION = 2:0:1
else
libcrypt_la_VERSION = 2:0:0
endif

libcrypt_la_LDFLAGS = -version-info $(libcrypt_la_VERSION)

if HAVE_VSCRIPT
libcrypt_la_LDFLAGS += $(VSCRIPT_LDFLAGS),$(builddir)/libcrypt.map
endif

libcrypt_la_LDFLAGS += $(UNDEF_FLAG) $(TEXT_RELOC_FLAG) $(AM_LDFLAGS)

libcrypt_la_CPPFLAGS = $(AM_CPPFLAGS) -DIN_LIBCRYPT

CONFIG_STATUS_DEPENDENCIES = libcrypt.minver
EXTRA_libcrypt_la_DEPENDENCIES = libcrypt.map
CLEANFILES = Makefile.deps.T Makefile.deps \
	libcrypt.map libcrypt.map.T \
	crypt-symbol-vers.h crypt-symbol-vers.h.T \
	crypt-hashes.h crypt-hashes.h.T \
	crypt.h crypt.h.T xcrypt.h xcrypt.h.T \
	*.gcda *.gcno

DISTCLEANFILES = .deps/*.Plo

# Empty target to have needed headers pre-generated before any other target.
Makefile.deps: xcrypt.h libcrypt.map
	$(AM_V_GEN)LC_ALL=C echo "# Deps" > Makefile.deps.T
	$(AM_V_at)mv -f Makefile.deps.T Makefile.deps

libcrypt.map: libcrypt.map.in gen-map.awk Makefile
	$(AM_V_GEN)LC_ALL=C $(AWK) \
	  -v SYMVER_MIN=$(SYMVER_MIN) \
	  -v SYMVER_FLOOR=$(SYMVER_FLOOR) \
	  -v COMPAT_ABI=$(COMPAT_ABI) \
	  -f $(srcdir)/gen-map.awk $(srcdir)/libcrypt.map.in > libcrypt.map.T
	$(AM_V_at)mv -f libcrypt.map.T libcrypt.map

crypt-hashes.h: hashes.lst gen-hashes.awk Makefile
	$(AM_V_GEN)LC_ALL=C $(AWK) -f $(srcdir)/gen-hashes.awk \
	  -v ENABLED_HASHES=$(hashes_enabled) \
	  $(srcdir)/hashes.lst > crypt-hashes.h.T
	$(AM_V_at)mv -f crypt-hashes.h.T crypt-hashes.h

crypt-symbol-vers.h: libcrypt.map.in gen-vers.awk Makefile
	$(AM_V_GEN)LC_ALL=C $(AWK) \
	  -v SYMVER_MIN=$(SYMVER_MIN) \
	  -v SYMVER_FLOOR=$(SYMVER_FLOOR) \
	  -v COMPAT_ABI=$(COMPAT_ABI) \
	  -f $(srcdir)/gen-vers.awk \
	     $(srcdir)/libcrypt.map.in > crypt-symbol-vers.h.T
	$(AM_V_at)mv -f crypt-symbol-vers.h.T crypt-symbol-vers.h

crypt.h: crypt.h.in crypt-hashes.h gen-crypt-h.awk config.h Makefile
	$(AM_V_GEN)LC_ALL=C $(AWK) \
	  -f $(srcdir)/gen-crypt-h.awk config.h $(builddir)/crypt.h.in \
	  > crypt.h.T
	$(AM_V_GEN)LC_ALL=C \
	$(GREP) -q "#define HASH_ALGORITHM_DEFAULT" crypt-hashes.h && \
	$(SED) -i -e "s/@DEFAULT_PREFIX_ENABLED@/1/g" crypt.h.T || \
	$(SED) -i -e "s/@DEFAULT_PREFIX_ENABLED@/0/g" crypt.h.T
	$(AM_V_at)mv -f crypt.h.T crypt.h

xcrypt.h: crypt.h crypt-symbol-vers.h
	$(AM_V_GEN)LC_ALL=C $(AWK) \
	  -f $(srcdir)/gen-crypt-h.awk config.h $(srcdir)/xcrypt.h.in \
	  > xcrypt.h.T
	$(AM_V_at)mv -f xcrypt.h.T xcrypt.h

install_exec_hook_targets =

if ENABLE_XCRYPT_COMPAT_FILES
if ENABLE_STATIC
# Install libxcrypt.a symlink to libcrypt.a file.
phony_targets += \
	install-exec-hook-xcrypt-static uninstall-hook-xcrypt-static
install_exec_hook_targets += \
	install-exec-hook-xcrypt-static
uninstall_hook_targets += \
	uninstall-hook-xcrypt-static
install-exec-hook-xcrypt-static:
	cd $(DESTDIR)$(libdir) && \
		$(LN_S) libcrypt.a libxcrypt.a
uninstall-hook-xcrypt-static:
	-rm -f $(DESTDIR)$(libdir)/libxcrypt.a
endif

if ENABLE_SHARED
# Install libxcrypt.so symlink to libcrypt.so file.
phony_targets += \
	install-exec-hook-xcrypt-shared uninstall-hook-xcrypt-shared
install_exec_hook_targets += \
	install-exec-hook-xcrypt-shared
uninstall_hook_targets += \
	uninstall-hook-xcrypt-shared
install-exec-hook-xcrypt-shared:
	cd $(DESTDIR)$(libdir) && \
		$(LN_S) libcrypt.so libxcrypt.so
uninstall-hook-xcrypt-shared:
	-rm -f $(DESTDIR)$(libdir)/libxcrypt.so
endif
endif

if ENABLE_COMPAT_SUSE
# When we are being binary compatible, also install symbolic links to
# mimic SUSE's libowcrypt; any program that uses -lowcrypt in its
# build, or already has a NEEDED entry for libowcrypt.so.1, will be
# redirected to libcrypt.  The OW_CRYPT_1.0 symbol versions are already
# present in libcrypt.so.1.
#
# Caution: this hardwires the expected (so)names of the shared
# libraries involved, libcrypt.so.1 and libowcrypt.so.1.  (We should
# be able to get away with this because in any circumstance where the
# soname of libcrypt isn't libcrypt.so.1, ENABLE_OBSOLETE_API should
# be automatically turned off, and as best I can tell, SUSE only ever
# shipped libowcrypt.so.1.)
if ENABLE_OBSOLETE_API
if ENABLE_STATIC
phony_targets += \
	install-exec-hook-libstatic uninstall-hook-libstatic
install_exec_hook_targets += \
	install-exec-hook-libstatic
uninstall_hook_targets += \
	uninstall-hook-libstatic
install-exec-hook-libstatic:
	cd $(DESTDIR)$(libdir) && \
		$(LN_S) libcrypt.a libowcrypt.a
uninstall-hook-libstatic:
	-rm -f $(DESTDIR)$(libdir)/libowcrypt.a
endif
if ENABLE_SHARED
phony_targets += \
	install-exec-hook-libshared uninstall-hook-libshared
install_exec_hook_targets += \
	install-exec-hook-libshared
uninstall_hook_targets += \
	uninstall-hook-libshared
install-exec-hook-libshared:
	cd $(DESTDIR)$(libdir) && \
		$(LN_S) libcrypt.so libowcrypt.so && \
		$(LN_S) libcrypt.so.1 libowcrypt.so.1
uninstall-hook-libshared:
	-rm -f  $(DESTDIR)$(libdir)/libowcrypt.so \
		$(DESTDIR)$(libdir)/libowcrypt.so.1
endif
endif
endif

check_PROGRAMS = \
	test-alg-des test-alg-gost3411-2012 test-alg-gost3411-2012-hmac \
	test-alg-hmac-sha1 test-alg-md4 test-alg-md5 \
	test-alg-pbkdf-hmac-sha256 test-alg-sha1 test-alg-sha256 \
	test-alg-sha512 test-alg-yescrypt test-checksalt test-crypt-bcrypt \
	test-crypt-des test-crypt-gost-yescrypt test-crypt-md5 \
	test-crypt-nthash test-crypt-pbkdf1-sha1 test-crypt-scrypt \
	test-crypt-sha256 test-crypt-sha512 test-crypt-sunmd5 \
	test-crypt-yescrypt test-byteorder test-badsalt test-badsetting \
	test-gensalt test-gensalt-extradata test-gensalt-nthash \
	test-preferred-method test-crypt-badargs test-short-outbuf \
	test-compile-strong-alias test-getrandom-interface \
	test-getrandom-fallbacks

if ENABLE_OBSOLETE_API
libcrypt_la_SOURCES += crypt-des-obsolete.c
check_PROGRAMS += test-des-obsolete test-des-obsolete_r test-fcrypt-enosys
endif

TESTS = $(check_PROGRAMS)

if ENABLE_STATIC
TESTS += test-symbols-static.sh

if HAVE_CPP_dD
TESTS += test-symbols-renames.sh
endif
endif

if ENABLE_OBSOLETE_API
TESTS += test-symbols-compat.sh
endif

EXTRA_DIST += test-symbols-static.sh test-symbols-compat.sh test-symbols-renames.sh

AM_TESTS_ENVIRONMENT = \
    lib_la="./libcrypt.la"; lib_map="$(srcdir)/libcrypt.map.in"; \
    CC="$(CC)"; CPP="$(CPP)"; \
    CPPFLAGS="$(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES)"; \
    CPPFLAGS="$${CPPFLAGS} $(AM_CPPFLAGS) $(CPPFLAGS)"; \
    export lib_la lib_map CC CPP CPPFLAGS;

if CROSS_COMPILING
LOG_COMPILER = m4/skip-if-exec-format-error
endif

EXTRA_DIST += m4/skip-if-exec-format-error

# Refer to object files that are linked into libxcrypt with the
# qualified name, libcrypt_la-foobar.lo, to prevent them from
# being compiled a second time.
COMMON_TEST_OBJECTS = libcrypt_la-crypt-common.lo libcrypt.la

test_crypt_bcrypt_LDADD = $(COMMON_TEST_OBJECTS)
test_crypt_des_LDADD = $(COMMON_TEST_OBJECTS)
test_crypt_md5_LDADD = $(COMMON_TEST_OBJECTS)
test_crypt_nthash_LDADD = $(COMMON_TEST_OBJECTS)
test_crypt_pbkdf1_sha1_LDADD = $(COMMON_TEST_OBJECTS)
test_crypt_scrypt_LDADD = $(COMMON_TEST_OBJECTS)
test_crypt_sha256_LDADD = $(COMMON_TEST_OBJECTS)
test_crypt_sha512_LDADD = $(COMMON_TEST_OBJECTS)
test_crypt_sunmd5_LDADD = $(COMMON_TEST_OBJECTS)
test_crypt_yescrypt_LDADD = $(COMMON_TEST_OBJECTS)
test_badsalt_LDADD = $(COMMON_TEST_OBJECTS)
test_badsetting_LDADD = $(COMMON_TEST_OBJECTS)
test_gensalt_LDADD = $(COMMON_TEST_OBJECTS)
test_gensalt_nthash_LDADD = $(COMMON_TEST_OBJECTS)
test_gensalt_extradata_LDADD = $(COMMON_TEST_OBJECTS)
test_checksalt_LDADD = $(COMMON_TEST_OBJECTS)
test_des_obsolete_LDADD = $(COMMON_TEST_OBJECTS)
test_des_obsolete_r_LDADD = $(COMMON_TEST_OBJECTS)
test_fcrypt_enosys_LDADD = $(COMMON_TEST_OBJECTS)
test_crypt_badargs_LDADD = $(COMMON_TEST_OBJECTS)
test_short_outbuf_LDADD = $(COMMON_TEST_OBJECTS)
test_preferred_method_LDADD = $(COMMON_TEST_OBJECTS)

# These tests call internal APIs that may not be accessible from the
# fully linked shared library.
test_alg_des_LDADD = \
	libcrypt_la-alg-des.lo \
	libcrypt_la-alg-des-tables.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_gost3411_2012_LDADD = \
	libcrypt_la-alg-gost3411-2012-core.lo \
	libcrypt_la-alg-gost3411-2012-hmac.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_gost3411_2012_hmac_LDADD = \
	libcrypt_la-alg-gost3411-2012-core.lo \
	libcrypt_la-alg-gost3411-2012-hmac.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_hmac_sha1_LDADD = \
	libcrypt_la-alg-sha1.lo \
	libcrypt_la-alg-hmac-sha1.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_md4_LDADD = \
	libcrypt_la-alg-md4.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_md5_LDADD = \
	libcrypt_la-alg-md5.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_pbkdf_hmac_sha256_LDADD = \
	libcrypt_la-alg-sha256.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_sha1_LDADD = \
	libcrypt_la-alg-sha1.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_sha256_LDADD = \
	libcrypt_la-alg-sha256.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_sha512_LDADD = \
	libcrypt_la-alg-sha512.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_yescrypt_LDADD = \
	libcrypt_la-alg-sha256.lo \
	libcrypt_la-alg-yescrypt-common.lo \
	libcrypt_la-alg-yescrypt-opt.lo \
	$(COMMON_TEST_OBJECTS)
test_crypt_gost_yescrypt_LDADD = \
	libcrypt_la-alg-gost3411-2012-core.lo \
	libcrypt_la-alg-gost3411-2012-hmac.lo \
	libcrypt_la-alg-sha256.lo \
	libcrypt_la-alg-yescrypt-common.lo \
	libcrypt_la-alg-yescrypt-opt.lo \
	libcrypt_la-crypt-yescrypt.lo \
	$(COMMON_TEST_OBJECTS)

test_getrandom_interface_LDADD = \
	libcrypt_la-randombytes.lo \
	$(COMMON_TEST_OBJECTS)
test_getrandom_fallbacks_LDADD = \
	libcrypt_la-randombytes.lo \
	$(COMMON_TEST_OBJECTS)

if HAVE_LD_WRAP
test_getrandom_fallbacks_LDFLAGS = \
  -Wl,--wrap,getentropy -Wl,--wrap,getrandom -Wl,--wrap,syscall \
  -Wl,--wrap,open -Wl,--wrap,open64 -Wl,--wrap,read -Wl,--wrap,close \
  $(AM_LDFLAGS)
endif

# Every object file depends on crypt-symbol-vers.h and crypt-hashes.h,
# which are generated files, so automatic dependency generation is not
# sufficient.
include $(builddir)/Makefile.deps

# Add additional targets
.PHONY: $(phony_targets)
install-exec-hook: $(install_exec_hook_targets)
uninstall-hook: $(uninstall_hook_targets)

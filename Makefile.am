#
# Copyright (c) 2002, 2007 SuSE Linux AG, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.14 gnits
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = $(WARN_CFLAGS)

EXTRA_DIST = \
	LICENSING THANKS \
	libcrypt.map.in libcrypt.minver \
	gen-map.awk gen-vers.awk gen-crypt-h.awk \
	gen-hashes.awk sel-hashes.awk hashes.lst

notrans_dist_man3_MANS = crypt_rn.3 crypt_gensalt.3
notrans_dist_man5_MANS = crypt.5

nodist_include_HEADERS = crypt.h
nodist_noinst_HEADERS = crypt-hashes.h
noinst_HEADERS = \
	alg-des.h alg-hmac-sha1.h alg-md4.h alg-md5.h \
	alg-sha1.h alg-sha256.h alg-sha512.h byteorder.h \
	crypt-base.h crypt-obsolete.h crypt-private.h \
	crypt-port.h test-des-cases.h

lib_LTLIBRARIES = libcrypt.la
libcrypt_la_SOURCES = \
	alg-des.c alg-des-tables.c alg-hmac-sha1.c alg-md4.c alg-md5.c \
	alg-sha1.c alg-sha256.c alg-sha512.c \
	crypt.c crypt-bcrypt.c crypt-des.c crypt-gensalt-static.c \
	crypt-gensalt.c crypt-md5.c crypt-nthash.c crypt-pbkdf1-sha1.c \
	crypt-sha256.c crypt-sha512.c crypt-static.c crypt-sunmd5.c \
	randombytes.c

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

libcrypt_la_LDFLAGS = \
	-version-info $(libcrypt_la_VERSION) \
	-Wl,--version-script=libcrypt.map \
	-Wl,-z,defs -Wl,-z,text
libcrypt_la_CPPFLAGS = $(AM_CPPFLAGS) -DIN_LIBCRYPT

CONFIG_STATUS_DEPENDENCIES = libcrypt.minver
EXTRA_libcrypt_la_DEPENDENCIES = libcrypt.map
CLEANFILES = libcrypt.map libcrypt.map.T \
	crypt-symbol-vers.h crypt-symbol-vers.h.T \
	crypt-hashes.h crypt-hashes.h.T \
	crypt.h crypt.h.T

libcrypt.map: libcrypt.map.in gen-map.awk Makefile
	$(AM_V_GEN)LC_ALL=C $(AWK) \
	  -v SYMVER_MIN=$(SYMVER_MIN) \
	  -v SYMVER_FLOOR=$(SYMVER_FLOOR) \
	  -v COMPAT_ABI=$(COMPAT_ABI) \
	  -f $(srcdir)/gen-map.awk $(srcdir)/libcrypt.map.in > libcrypt.map.T
	$(AM_V_at)mv -f libcrypt.map.T libcrypt.map

crypt-symbol-vers.h: libcrypt.map.in gen-vers.awk Makefile
	$(AM_V_GEN)LC_ALL=C $(AWK) \
	  -v SYMVER_MIN=$(SYMVER_MIN) \
	  -v SYMVER_FLOOR=$(SYMVER_FLOOR) \
	  -v COMPAT_ABI=$(COMPAT_ABI) \
	  -f $(srcdir)/gen-vers.awk \
	     $(srcdir)/libcrypt.map.in > crypt-symbol-vers.h.T
	$(AM_V_at)mv -f crypt-symbol-vers.h.T crypt-symbol-vers.h

crypt.h: crypt-base.h gen-crypt-h.awk config.h
	$(AM_V_GEN)LC_ALL=C $(AWK) \
	  -f $(srcdir)/gen-crypt-h.awk config.h $(srcdir)/crypt-base.h \
	  > crypt.h.T
	$(AM_V_at)mv -f crypt.h.T crypt.h

crypt-hashes.h: hashes.lst gen-hashes.awk Makefile
	$(AM_V_GEN)LC_ALL=C $(AWK) -f $(srcdir)/gen-hashes.awk \
	  -v ENABLED_HASHES=$(hashes_enabled) \
	  $(srcdir)/hashes.lst > crypt-hashes.h.T
	$(AM_V_at)mv -f crypt-hashes.h.T crypt-hashes.h

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
install-exec-hook: install-exec-hook-libstatic
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
install-exec-hook: install-exec-hook-libshared
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
	test-alg-des test-alg-hmac-sha1 test-alg-md4 test-alg-md5 \
	test-alg-sha1 test-alg-sha256 test-alg-sha512 \
	test-crypt-bcrypt test-crypt-des \
	test-crypt-md5 test-crypt-nthash \
	test-crypt-pbkdf1-sha1 test-crypt-sha256 test-crypt-sha512 \
	test-crypt-sunmd5 \
	test-byteorder test-badsalt test-badsetting test-gensalt \
	test-crypt-badargs test-short-outbuf \
        test-getrandom-interface test-getrandom-fallbacks

if ENABLE_OBSOLETE_API
libcrypt_la_SOURCES += crypt-des-obsolete.c
check_PROGRAMS += test-des-obsolete test-des-obsolete_r
endif

TESTS = $(check_PROGRAMS)
if ENABLE_STATIC
TESTS += test-symbols-static
if HAVE_CPP_dD
TESTS += test-symbols-renames
endif
endif
if ENABLE_OBSOLETE_API
TESTS += test-symbols-compat
endif
EXTRA_DIST += test-symbols-static test-symbols-compat test-symbols-renames

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

test_crypt_bcrypt_LDADD = libcrypt.la
test_crypt_des_LDADD = libcrypt.la
test_crypt_md5_LDADD = libcrypt.la
test_crypt_nthash_LDADD = libcrypt.la
test_crypt_pbkdf1_sha1_LDADD = libcrypt.la
test_crypt_sha256_LDADD = libcrypt.la
test_crypt_sha512_LDADD = libcrypt.la
test_crypt_sunmd5_LDADD = libcrypt.la
test_badsalt_LDADD = libcrypt.la
test_badsetting_LDADD = libcrypt.la
test_gensalt_LDADD = libcrypt.la
test_des_obsolete_LDADD = libcrypt.la
test_des_obsolete_r_LDADD = libcrypt.la
test_crypt_badargs_LDADD = libcrypt.la
test_short_outbuf_LDADD = libcrypt.la

# These tests call internal APIs that may not be accessible from the
# fully linked shared library.
test_alg_des_LDADD = alg-des.lo alg-des-tables.lo
test_alg_hmac_sha1_LDADD = alg-sha1.lo alg-hmac-sha1.lo
test_alg_md4_LDADD = alg-md4.lo
test_alg_md5_LDADD = alg-md5.lo
test_alg_sha1_LDADD = alg-sha1.lo
test_alg_sha256_LDADD = alg-sha256.lo
test_alg_sha512_LDADD = alg-sha512.lo

test_getrandom_interface_LDADD = randombytes.lo
test_getrandom_fallbacks_LDADD = randombytes.lo
if HAVE_LD_WRAP
test_getrandom_fallbacks_LDFLAGS = \
  -Wl,--wrap,getentropy -Wl,--wrap,getrandom -Wl,--wrap,syscall \
  -Wl,--wrap,open -Wl,--wrap,open64 -Wl,--wrap,read -Wl,--wrap,close
endif

# Every object file depends on crypt-symbol-vers.h and crypt-hashes.h,
# which are generated files, so automatic dependency generation is not
# sufficient.  Most of the test programs depend on either libcrypt.la
# or one of its components, so they do not need an explicit dependency
# (after the first *successful* build, automatic dependency generation
# will reveal the direct dependency) but a few don't.
$(libcrypt_la_OBJECTS): crypt-symbol-vers.h crypt-hashes.h
$(test_byteorder_OBJECTS): crypt-symbol-vers.h crypt-hashes.h

# Add additional targets
.PHONY: $(phony_targets)
uninstall-hook: $(uninstall_hook_targets)

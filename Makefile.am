#
# Copyright (c) 2002, 2007 SuSE Linux AG, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.15 gnits
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = $(WARN_CFLAGS)

EXTRA_DIST = \
	LICENSING THANKS \
	libcrypt.map.in libcrypt.minver \
	gen-map.awk gen-vers.awk gen-crypt-h.awk

notrans_dist_man3_MANS = crypt_rn.3 crypt_gensalt.3
notrans_dist_man5_MANS = crypt.5

nodist_include_HEADERS = crypt.h
noinst_HEADERS = \
	alg-des.h alg-hmac-sha1.h alg-md4.h alg-md5.h \
	alg-sha1.h alg-sha256.h alg-sha512.h byteorder.h \
	crypt-base.h crypt-obsolete.h crypt-private.h \
	crypt-port.h test-des-cases.h

lib_LTLIBRARIES = libcrypt.la
libcrypt_la_SOURCES = \
	crypt.c crypt-static.c crypt-gensalt.c crypt-gensalt-static.c \
	crypt-bcrypt.c crypt-sha512.c crypt-sha256.c \
	alg-sha512.c alg-sha256.c randombytes.c

pkgconfig_DATA = libxcrypt.pc

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
	crypt.h crypt.h.T

libcrypt.map: libcrypt.map.in gen-map.awk Makefile
	$(AM_V_GEN)LC_ALL=C $(AWK) \
	  -v SYMVER_MIN=$(SYMVER_MIN) -v SYMVER_FLOOR=$(SYMVER_FLOOR) \
	  -f $(srcdir)/gen-map.awk $(srcdir)/libcrypt.map.in > libcrypt.map.T
	$(AM_V_at)mv -f libcrypt.map.T libcrypt.map

crypt-symbol-vers.h: libcrypt.map.in gen-vers.awk Makefile
	$(AM_V_GEN)LC_ALL=C $(AWK) \
	  -v SYMVER_MIN=$(SYMVER_MIN) -v SYMVER_FLOOR=$(SYMVER_FLOOR) \
	  -f $(srcdir)/gen-vers.awk \
	     $(srcdir)/libcrypt.map.in > crypt-symbol-vers.h.T
	$(AM_V_at)mv -f crypt-symbol-vers.h.T crypt-symbol-vers.h

crypt.h: crypt-base.h gen-crypt-h.awk config.h
	$(AM_V_GEN)LC_ALL=C $(AWK) \
	  -f $(srcdir)/gen-crypt-h.awk config.h $(srcdir)/crypt-base.h \
	  > crypt.h.T
	$(AM_V_at)mv -f crypt.h.T crypt.h

# When we are being binary compatible, also install symbolic links to
# mimic SuSE's libowcrypt; any program that uses -lowcrypt in its
# build, or already has a NEEDED entry for libowcrypt.so.1, will be
# redirected to libcrypt.  The OW_CRYPT_1.0 symbol versions are already
# present in libcrypt.so.1.
#
# Caution: this hardwires the expected (so)names of the shared
# libraries involved, libcrypt.so.1 and libowcrypt.so.1.  (We should
# be able to get away with this because in any circumstance where the
# soname of libcrypt isn't libcrypt.so.1, ENABLE_OBSOLETE_API should
# be automatically turned off, and as best I can tell, SuSE only ever
# shipped libowcrypt.so.1.)
if ENABLE_OBSOLETE_API
if ENABLE_STATIC
.PHONY: install-exec-hook-libstatic uninstall-hook-libstatic
install-exec-hook: install-exec-hook-libstatic
uninstall-hook: uninstall-hook-libstatic
install-exec-hook-libstatic:
	cd $(DESTDIR)$(libdir) && \
		$(LN_S) libcrypt.a libowcrypt.a
uninstall-hook-libstatic:
	-rm -f $(DESTDIR)$(libdir)/libowcrypt.a
endif
if ENABLE_SHARED
.PHONY: install-exec-hook-libshared uninstall-hook-libshared
install-exec-hook: install-exec-hook-libshared
uninstall-hook: uninstall-hook-libshared
install-exec-hook-libshared:
	cd $(DESTDIR)$(libdir) && \
		$(LN_S) libcrypt.so libowcrypt.so && \
		$(LN_S) libcrypt.so.1 libowcrypt.so.1
uninstall-hook-libshared:
	-rm -f  $(DESTDIR)$(libdir)/libowcrypt.so \
		$(DESTDIR)$(libdir)/libowcrypt.so.1
endif
endif

check_PROGRAMS = \
	test-alg-sha256 test-alg-sha512 \
	test-crypt-sha256 test-crypt-sha512 test-crypt-bcrypt \
	test-crypt-nonnull test-byteorder test-gensalt

if ENABLE_WEAK_HASHES
libcrypt_la_SOURCES += \
	crypt-md5.c crypt-des.c crypt-nthash.c crypt-pbkdf1-sha1.c \
	crypt-sunmd5.c \
	alg-des.c alg-hmac-sha1.c alg-md4.c alg-md5.c alg-sha1.c

nodist_libcrypt_la_SOURCES = \
	alg-des-tables.c
CLEANFILES += alg-des-tables.c alg-des-tables.c.T

noinst_PROGRAMS = gen-des-tables

LINK_FOR_BUILD = $(CC_FOR_BUILD) $(CFLAGS_FOR_BUILD) $(CPPFLAGS_FOR_BUILD) \
	$(LDFLAGS_FOR_BUILD) $(TARGET_ARCH_FOR_BUILD) -o $@

gen-des-tables$(BUILD_EXEEXT): $(gen_des_tables_OBJECTS)
	@rm -f gen-des-tables$(BUILD_EXEEXT)
	$(AM_V_CCLD)$(LINK_FOR_BUILD) $(gen_des_tables_OBJECTS) $(gen_des_tables_LDADD) $(LIBS)
# suppress the built-in rule for
gen-des-tables$(EXEEXT):

$(gen_des_tables_OBJECTS) : CC=$(CC_FOR_BUILD)
$(gen_des_tables_OBJECTS) : CFLAGS=$(CFLAGS_FOR_BUILD)
$(gen_des_tables_OBJECTS) : CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
$(gen_des_tables_OBJECTS) : AM_CFLAGS=$(WARN_CFLAGS_FOR_BUILD)

alg-des-tables.c: gen-des-tables
	$(AM_V_GEN)./gen-des-tables$(BUILD_EXEEXT) > alg-des-tables.c.T
	$(AM_V_at)mv -f alg-des-tables.c.T alg-des-tables.c

check_PROGRAMS += \
	test-alg-des test-alg-hmac-sha1 test-alg-md4 \
        test-alg-md5 test-alg-sha1 \
	test-crypt-badsalt test-crypt-des test-crypt-md5 \
	test-crypt-nthash test-crypt-sunmd5 test-crypt-pbkdf1-sha1
endif

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

test_crypt_badsalt_LDADD = libcrypt.la
test_crypt_bcrypt_LDADD = libcrypt.la
test_crypt_des_LDADD = libcrypt.la
test_crypt_md5_LDADD = libcrypt.la
test_crypt_nonnull_LDADD = libcrypt.la
test_crypt_nthash_LDADD = libcrypt.la
test_crypt_pbkdf1_sha1_LDADD = libcrypt.la
test_crypt_sha256_LDADD = libcrypt.la
test_crypt_sha512_LDADD = libcrypt.la
test_crypt_sunmd5_LDADD = libcrypt.la
test_gensalt_LDADD = libcrypt.la
test_des_obsolete_LDADD = libcrypt.la
test_des_obsolete_r_LDADD = libcrypt.la

# These tests call internal APIs that may not be accessible from the
# fully linked shared library.
test_alg_des_LDADD = alg-des.lo alg-des-tables.lo
test_alg_hmac_sha1_LDADD = alg-sha1.lo alg-hmac-sha1.lo
test_alg_md4_LDADD = alg-md4.lo
test_alg_md5_LDADD = alg-md5.lo
test_alg_sha1_LDADD = alg-sha1.lo
test_alg_sha256_LDADD = alg-sha256.lo
test_alg_sha512_LDADD = alg-sha512.lo


# Every object file in the library depends on crypt-symbol-vers.h,
# which is a generated file, so automatic dependency generation will
# not detect it.
$(libcrypt_la_OBJECTS): crypt-symbol-vers.h

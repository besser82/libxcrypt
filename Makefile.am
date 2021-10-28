#
# Copyright (c) 2002, 2007 SuSE Linux AG, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = \
	1.14 \
	dist-bzip2 \
	dist-xz \
	filename-length-max=99 \
	gnits \
	subdir-objects

ACLOCAL_AMFLAGS = -I build-aux/m4

AM_CPPFLAGS = -I$(srcdir)/lib
AM_CFLAGS = $(WARN_CFLAGS) $(OPTI_FLAGS)
AM_LDFLAGS = $(RELRO_FLAG) $(BINDNOW_FLAG)

SCRIPTS_AUX = $(srcdir)/build-aux/scripts
STAMP = echo timestamp >

@VALGRIND_CHECK_RULES@

TEST_EXTENSIONS = .pl

EXTRA_DIST = \
	LICENSING \
	THANKS \
	lib/alg-yescrypt-platform.c \
	lib/crypt.h.in \
	lib/hashes.conf \
	lib/libcrypt.map.in \
	lib/libcrypt.minver \
	lib/xcrypt.h.in \
	build-aux/scripts/BuildCommon.pm \
	build-aux/scripts/check-perlcritic-config \
	build-aux/scripts/compute-symver-floor \
	build-aux/scripts/expand-selected-hashes \
	build-aux/scripts/gen-crypt-h \
	build-aux/scripts/gen-crypt-hashes-h \
	build-aux/scripts/gen-crypt-symbol-vers-h \
	build-aux/scripts/gen-libcrypt-map \
	build-aux/scripts/move-if-change \
	build-aux/scripts/skip-if-exec-format-error \
	test/TestCommon.pm \
	test/symbols-compat.pl \
	test/symbols-renames.pl \
	test/symbols-static.pl

notrans_dist_man3_MANS = \
	doc/crypt.3 \
	doc/crypt_checksalt.3 \
	doc/crypt_gensalt.3 \
	doc/crypt_gensalt_ra.3 \
	doc/crypt_gensalt_rn.3 \
	doc/crypt_preferred_method.3 \
	doc/crypt_r.3 \
	doc/crypt_ra.3 \
	doc/crypt_rn.3
notrans_dist_man5_MANS = \
	doc/crypt.5

nodist_include_HEADERS = \
	crypt.h
nodist_noinst_HEADERS = \
	crypt-hashes.h \
	crypt-symbol-vers.h
noinst_HEADERS = \
	lib/alg-des.h \
	lib/alg-gost3411-2012-const.h \
	lib/alg-gost3411-2012-core.h \
	lib/alg-gost3411-2012-hmac.h \
	lib/alg-gost3411-2012-precalc.h \
	lib/alg-gost3411-2012-ref.h \
	lib/alg-hmac-sha1.h \
	lib/alg-md4.h \
	lib/alg-md5.h \
	lib/alg-sha1.h \
	lib/alg-sha256.h \
	lib/alg-sha512.h \
	lib/alg-yescrypt.h \
	lib/byteorder.h \
	lib/crypt-obsolete.h \
	lib/crypt-port.h \
	test/des-cases.h \
	test/ka-table.inc

if ENABLE_XCRYPT_COMPAT_FILES
nodist_include_HEADERS += xcrypt.h
endif

noinst_PROGRAMS = \
	lib/gen-des-tables

lib_LTLIBRARIES = \
	libcrypt.la

libcrypt_la_SOURCES = \
	lib/alg-des-tables.c \
	lib/alg-des.c \
	lib/alg-gost3411-2012-core.c \
	lib/alg-gost3411-2012-hmac.c \
	lib/alg-hmac-sha1.c \
	lib/alg-md4.c \
	lib/alg-md5.c \
	lib/alg-sha1.c \
	lib/alg-sha256.c \
	lib/alg-sha512.c \
	lib/alg-yescrypt-common.c \
	lib/alg-yescrypt-opt.c \
	lib/crypt-bcrypt.c \
	lib/crypt-des.c \
	lib/crypt-gensalt-static.c \
	lib/crypt-gost-yescrypt.c \
	lib/crypt-md5.c \
	lib/crypt-nthash.c \
	lib/crypt-pbkdf1-sha1.c \
	lib/crypt-scrypt.c \
	lib/crypt-sha256.c \
	lib/crypt-sha512.c \
	lib/crypt-static.c \
	lib/crypt-sunmd5.c \
	lib/crypt-yescrypt.c \
	lib/crypt.c \
	lib/util-base64.c \
	lib/util-gensalt-sha.c \
	lib/util-get-random-bytes.c \
	lib/util-make-failure-token.c \
	lib/util-xbzero.c \
	lib/util-xstrcpy.c

pkgconfig_DATA = libxcrypt.pc

# Install libcrypt.pc symlink to libxcrypt.pc file.
phony_targets = \
	install-data-hook-pkgconfig uninstall-hook-pkgconfig
install-data-hook: install-data-hook-pkgconfig
uninstall_hook_targets = \
	uninstall-hook-pkgconfig
install-data-hook-pkgconfig:
	cd $(DESTDIR)$(pkgconfigdir) && \
		$(LN_S) -f libxcrypt.pc libcrypt.pc
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
APPLY_SYMVERS = yes
else
APPLY_SYMVERS = no
endif

libcrypt_la_LDFLAGS += $(UNDEF_FLAG) $(TEXT_RELOC_FLAG) $(AM_LDFLAGS)

libcrypt_la_CPPFLAGS = $(AM_CPPFLAGS) -DIN_LIBCRYPT

CONFIG_STATUS_DEPENDENCIES = lib/libcrypt.minver
EXTRA_libcrypt_la_DEPENDENCIES = libcrypt.map
CLEANFILES = \
	Makefile.deps Makefile.deps.T \
	libcrypt.map libcrypt.map.T libcrypt.map.stamp \
	crypt-symbol-vers.h crypt-symbol-vers.h.T crypt-symbol-vers.h.stamp \
	crypt-hashes.h crypt-hashes.h.T crypt-hashes.h.stamp \
	crypt.h crypt.h.T crypt.h.stamp \
	xcrypt.h xcrypt.h.T xcrypt.h.stamp \
	./*.gcda ./*.gcno \
	lib/*.gcda lib/*.gcno \
	test/*.gcda test/*.gcno

DISTCLEANFILES = .deps/*.Plo

# Force generated headers to be generated before any source files that
# might depend on them are compiled.
Makefile.deps: crypt.h crypt-hashes.h crypt-symbol-vers.h
	$(AM_V_GEN)LC_ALL=C echo "# Deps" > Makefile.deps.T
	$(AM_V_at)mv -f Makefile.deps.T Makefile.deps

# Almost everything depends on the generated headers; the generated
# headers depend on the Makefile; *most* changes to the Makefile won't
# affect the contents of the generated headers.  Arrange for the
# timestamps of the generated headers not to change if their contents
# haven't.  The rule idiom used here was borrowed from GCC's Makefile;
# in https://gcc.gnu.org/git/?p=gcc.git;a=blob;f=gcc/Makefile.in;hb=HEAD
# search for the phrase "On the use of stamps".
AM_V_GENS = $(am__v_GENS_@AM_V@)
am__v_GENS_ = $(am__v_GENS_@AM_DEFAULT_V@)
am__v_GENS_0 = @echo "  GEN     " $(@:.stamp=);
am__v_GENS_1 =

libcrypt.map: libcrypt.map.stamp; @:
libcrypt.map.stamp: \
		lib/libcrypt.map.in $(SCRIPTS_AUX)/gen-libcrypt-map \
		$(SCRIPTS_AUX)/BuildCommon.pm Makefile
	$(AM_V_GENS)LC_ALL=C $(PERL) $(SCRIPTS_AUX)/gen-libcrypt-map \
	  SYMVER_MIN=$(SYMVER_MIN) \
	  SYMVER_FLOOR=$(SYMVER_FLOOR) \
	  COMPAT_ABI=$(COMPAT_ABI) \
	  $(srcdir)/lib/libcrypt.map.in > libcrypt.map.T
	$(AM_V_at)$(SCRIPTS_AUX)/move-if-change libcrypt.map.T libcrypt.map
	$(AM_V_at)$(STAMP) libcrypt.map.stamp

crypt-hashes.h: crypt-hashes.h.stamp; @:
crypt-hashes.h.stamp: \
		$(SCRIPTS_AUX)/gen-crypt-hashes-h $(SCRIPTS_AUX)/BuildCommon.pm \
		lib/hashes.conf Makefile
	$(AM_V_GENS)LC_ALL=C $(PERL) \
	  $(SCRIPTS_AUX)/gen-crypt-hashes-h \
	  $(srcdir)/lib/hashes.conf $(hashes_enabled) > crypt-hashes.h.T
	$(AM_V_at)$(SCRIPTS_AUX)/move-if-change crypt-hashes.h.T crypt-hashes.h
	$(AM_V_at)$(STAMP) crypt-hashes.h.stamp

crypt-symbol-vers.h: crypt-symbol-vers.h.stamp; @:
crypt-symbol-vers.h.stamp: \
		$(SCRIPTS_AUX)/gen-crypt-symbol-vers-h \
		$(SCRIPTS_AUX)/BuildCommon.pm \
		lib/libcrypt.map.in Makefile
	$(AM_V_GENS)LC_ALL=C $(PERL) \
	  $(SCRIPTS_AUX)/gen-crypt-symbol-vers-h \
	  $(APPLY_SYMVERS) \
	  SYMVER_MIN=$(SYMVER_MIN) \
	  SYMVER_FLOOR=$(SYMVER_FLOOR) \
	  COMPAT_ABI=$(COMPAT_ABI) \
	     $(srcdir)/lib/libcrypt.map.in > crypt-symbol-vers.h.T
	$(AM_V_at)$(SCRIPTS_AUX)/move-if-change crypt-symbol-vers.h.T crypt-symbol-vers.h
	$(AM_V_at)$(STAMP) crypt-symbol-vers.h.stamp

crypt.h: crypt.h.stamp; @:
crypt.h.stamp: \
		$(SCRIPTS_AUX)/gen-crypt-h $(SCRIPTS_AUX)/BuildCommon.pm \
		lib/crypt.h.in lib/hashes.conf config.h Makefile
	$(AM_V_GENS)LC_ALL=C $(PERL) \
	  $(SCRIPTS_AUX)/gen-crypt-h \
	  $(srcdir)/lib/crypt.h.in config.h \
	  $(srcdir)/lib/hashes.conf $(hashes_enabled) \
	  > crypt.h.T
	$(AM_V_at)$(SCRIPTS_AUX)/move-if-change crypt.h.T crypt.h
	$(AM_V_at)$(STAMP) crypt.h.stamp

xcrypt.h: xcrypt.h.stamp; @:
xcrypt.h.stamp: \
		$(SCRIPTS_AUX)/gen-crypt-h $(SCRIPTS_AUX)/BuildCommon.pm \
		lib/xcrypt.h.in config.h
	$(AM_V_GENS)LC_ALL=C $(PERL) \
	  $(SCRIPTS_AUX)/gen-crypt-h \
	  $(srcdir)/lib/xcrypt.h.in config.h \
	  > xcrypt.h.T
	$(AM_V_at)$(SCRIPTS_AUX)/move-if-change xcrypt.h.T xcrypt.h
	$(AM_V_at)$(STAMP) xcrypt.h.stamp

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
		$(LN_S) -f libcrypt.a libxcrypt.a
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
		$(LN_S) -f libcrypt.so libxcrypt.so
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
		$(LN_S) -f libcrypt.a libowcrypt.a
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
		$(LN_S) -f libcrypt.so libowcrypt.so && \
		$(LN_S) -f libcrypt.so.1 libowcrypt.so.1
uninstall-hook-libshared:
	-rm -f  $(DESTDIR)$(libdir)/libowcrypt.so \
		$(DESTDIR)$(libdir)/libowcrypt.so.1
endif
endif
endif

# The ka-* tests are first in this list because they are the slowest.
# The list should otherwise be kept in alphabetical order.

check_PROGRAMS = \
	test/ka-bcrypt \
	test/ka-bcrypt-a \
	test/ka-bcrypt-x \
	test/ka-bcrypt-y \
	test/ka-bigcrypt \
	test/ka-bsdicrypt \
	test/ka-descrypt \
	test/ka-gost-yescrypt \
	test/ka-md5crypt \
	test/ka-nt \
	test/ka-scrypt \
	test/ka-sha1crypt \
	test/ka-sha256crypt \
	test/ka-sha512crypt \
	test/ka-sunmd5 \
	test/ka-yescrypt \
	test/alg-des \
	test/alg-gost3411-2012 \
	test/alg-gost3411-2012-hmac \
	test/alg-hmac-sha1 \
	test/alg-md4 \
	test/alg-md5 \
	test/alg-pbkdf-hmac-sha256 \
	test/alg-sha1 \
	test/alg-sha256 \
	test/alg-sha512 \
	test/alg-yescrypt \
	test/badsalt \
	test/badsetting \
	test/byteorder \
	test/checksalt \
	test/compile-strong-alias \
	test/crypt-badargs \
	test/crypt-gost-yescrypt \
	test/explicit-bzero \
	test/gensalt \
	test/gensalt-extradata \
	test/gensalt-nthash \
	test/getrandom-fallbacks \
	test/getrandom-interface \
	test/preferred-method \
	test/short-outbuf \
	test/special-char-salt

# All of the known-answer tests are compiled from the same source file,
# with different macros defined.
test_ka_bcrypt_SOURCES		= test/ka-tester.c
test_ka_bcrypt_a_SOURCES	= test/ka-tester.c
test_ka_bcrypt_x_SOURCES	= test/ka-tester.c
test_ka_bcrypt_y_SOURCES	= test/ka-tester.c
test_ka_bigcrypt_SOURCES	= test/ka-tester.c
test_ka_bsdicrypt_SOURCES	= test/ka-tester.c
test_ka_descrypt_SOURCES	= test/ka-tester.c
test_ka_gost_yescrypt_SOURCES	= test/ka-tester.c
test_ka_md5crypt_SOURCES	= test/ka-tester.c
test_ka_nt_SOURCES		= test/ka-tester.c
test_ka_scrypt_SOURCES		= test/ka-tester.c
test_ka_sha1crypt_SOURCES	= test/ka-tester.c
test_ka_sha256crypt_SOURCES	= test/ka-tester.c
test_ka_sha512crypt_SOURCES	= test/ka-tester.c
test_ka_sunmd5_SOURCES		= test/ka-tester.c
test_ka_yescrypt_SOURCES	= test/ka-tester.c

test_ka_bcrypt_CPPFLAGS		= $(AM_CPPFLAGS) -DTEST_bcrypt
test_ka_bcrypt_a_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_bcrypt_a
test_ka_bcrypt_x_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_bcrypt_x
test_ka_bcrypt_y_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_bcrypt_y
test_ka_bigcrypt_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_bigcrypt
test_ka_bsdicrypt_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_bsdicrypt
test_ka_descrypt_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_descrypt
test_ka_gost_yescrypt_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_gost_yescrypt
test_ka_md5crypt_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_md5crypt
test_ka_nt_CPPFLAGS		= $(AM_CPPFLAGS) -DTEST_nt
test_ka_scrypt_CPPFLAGS		= $(AM_CPPFLAGS) -DTEST_scrypt
test_ka_sha1crypt_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_sha1crypt
test_ka_sha256crypt_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_sha256crypt
test_ka_sha512crypt_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_sha512crypt
test_ka_sunmd5_CPPFLAGS		= $(AM_CPPFLAGS) -DTEST_sunmd5
test_ka_yescrypt_CPPFLAGS	= $(AM_CPPFLAGS) -DTEST_yescrypt

if ENABLE_KA_TABLE_GEN
if ENABLE_SHARED
# test/ka-table.inc can be regenerated by running test/ka-table-gen.py.
# This is very slow and requires nonstandard Python libraries and a shared
# library build of libcrypt already present in the build-tree, so we only
# do it when explicitly requested.
regen-ka-table: libcrypt.la
	$(PYTHON) $(srcdir)/test/ka-table-gen.py > ka-table.inc.T
	@if cmp -s ka-table.inc.T $(srcdir)/test/ka-table.inc; \
	then echo ka-table.inc is unchanged; rm ka-table.inc.T; \
	else echo mv -f ka-table.inc.T $(srcdir)/test/ka-table.inc; \
	mv -f ka-table.inc.T $(srcdir)/test/ka-table.inc; fi
phony_targets += regen-ka-table
CLEANFILES += ka-table.inc.T
endif
endif

if ENABLE_OBSOLETE_API
libcrypt_la_SOURCES += lib/crypt-des-obsolete.c
check_PROGRAMS += test/des-obsolete test/des-obsolete_r
endif

TESTS = $(check_PROGRAMS)

if ENABLE_STATIC
TESTS += test/symbols-static.pl test/symbols-renames.pl
endif

if ENABLE_OBSOLETE_API
TESTS += test/symbols-compat.pl
endif

AM_TESTS_ENVIRONMENT = \
    lib_la="./libcrypt.la"; \
    lib_map="$(srcdir)/lib/libcrypt.map.in"; \
    HAVE_CPP_dD="$(HAVE_CPP_dD)"; \
    SYMBOL_PREFIX="$(SYMBOL_PREFIX)"; \
    CC="$(CC)"; \
    CPP="$(CPP)"; \
    CPPFLAGS="$(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES)"; \
    CPPFLAGS="$${CPPFLAGS} $(AM_CPPFLAGS) $(CPPFLAGS)"; \
    CFLAGS="$(CFLAGS)"; \
    LDFLAGS="$(LDFLAGS)"; \
    NM="$(NM)"; \
    SHELL="$(SHELL)"; \
    export lib_la lib_map HAVE_CPP_dD SYMBOL_PREFIX; \
    export CC CPP CPPFLAGS CFLAGS LDFLAGS NM SHELL;

PL_LOG_COMPILER = $(PERL)
if CROSS_COMPILING
LOG_COMPILER = $(PERL) $(SCRIPTS_AUX)/skip-if-exec-format-error
endif

test/symbols-compat.log test/symbols-compat.trs: test/TestCommon.pm
test/symbols-renames.log test/symbols-renames.trs: test/TestCommon.pm
test/symbols-static.log test/symbols-static.trs: test/TestCommon.pm

COMMON_TEST_OBJECTS = libcrypt.la

test_badsalt_LDADD = $(COMMON_TEST_OBJECTS)
test_badsetting_LDADD = $(COMMON_TEST_OBJECTS)
test_gensalt_nthash_LDADD = $(COMMON_TEST_OBJECTS)
test_gensalt_extradata_LDADD = $(COMMON_TEST_OBJECTS)
test_checksalt_LDADD = $(COMMON_TEST_OBJECTS)
test_des_obsolete_LDADD = $(COMMON_TEST_OBJECTS)
test_des_obsolete_r_LDADD = $(COMMON_TEST_OBJECTS)
test_crypt_badargs_LDADD = $(COMMON_TEST_OBJECTS)
test_short_outbuf_LDADD = $(COMMON_TEST_OBJECTS)
test_preferred_method_LDADD = $(COMMON_TEST_OBJECTS)
test_special_char_salt_LDADD = $(COMMON_TEST_OBJECTS)

test_ka_bcrypt_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_bcrypt_a_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_bcrypt_x_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_bcrypt_y_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_bigcrypt_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_bsdicrypt_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_descrypt_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_gost_yescrypt_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_md5crypt_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_nt_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_scrypt_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_sha1crypt_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_sha256crypt_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_sha512crypt_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_sunmd5_LDADD = $(COMMON_TEST_OBJECTS)
test_ka_yescrypt_LDADD = $(COMMON_TEST_OBJECTS)

# These tests call internal APIs that may not be accessible from the
# fully linked shared library.
# Refer to object files that are linked into libxcrypt with the
# qualified name, lib/libcrypt_la-foobar.lo, to prevent them from
# being compiled a second time.
test_gensalt_LDADD = \
	lib/libcrypt_la-util-xstrcpy.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_des_LDADD = \
	lib/libcrypt_la-alg-des.lo \
	lib/libcrypt_la-alg-des-tables.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_gost3411_2012_LDADD = \
	lib/libcrypt_la-alg-gost3411-2012-core.lo \
	lib/libcrypt_la-alg-gost3411-2012-hmac.lo \
	lib/libcrypt_la-util-xbzero.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_gost3411_2012_hmac_LDADD = \
	lib/libcrypt_la-alg-gost3411-2012-core.lo \
	lib/libcrypt_la-alg-gost3411-2012-hmac.lo \
	lib/libcrypt_la-util-xbzero.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_hmac_sha1_LDADD = \
	lib/libcrypt_la-alg-sha1.lo \
	lib/libcrypt_la-alg-hmac-sha1.lo \
	lib/libcrypt_la-util-xbzero.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_md4_LDADD = \
	lib/libcrypt_la-alg-md4.lo \
	lib/libcrypt_la-util-xbzero.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_md5_LDADD = \
	lib/libcrypt_la-alg-md5.lo \
	lib/libcrypt_la-util-xbzero.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_pbkdf_hmac_sha256_LDADD = \
	lib/libcrypt_la-alg-sha256.lo \
	lib/libcrypt_la-util-xbzero.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_sha1_LDADD = \
	lib/libcrypt_la-alg-sha1.lo \
	lib/libcrypt_la-util-xbzero.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_sha256_LDADD = \
	lib/libcrypt_la-alg-sha256.lo \
	lib/libcrypt_la-util-xbzero.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_sha512_LDADD = \
	lib/libcrypt_la-alg-sha512.lo \
	lib/libcrypt_la-util-xbzero.lo \
	$(COMMON_TEST_OBJECTS)
test_alg_yescrypt_LDADD = \
	lib/libcrypt_la-alg-sha256.lo \
	lib/libcrypt_la-alg-yescrypt-common.lo \
	lib/libcrypt_la-alg-yescrypt-opt.lo \
	lib/libcrypt_la-util-base64.lo \
	lib/libcrypt_la-util-xbzero.lo \
	$(COMMON_TEST_OBJECTS)
test_crypt_gost_yescrypt_LDADD = \
	lib/libcrypt_la-alg-gost3411-2012-core.lo \
	lib/libcrypt_la-alg-gost3411-2012-hmac.lo \
	lib/libcrypt_la-alg-sha256.lo \
	lib/libcrypt_la-alg-yescrypt-common.lo \
	lib/libcrypt_la-alg-yescrypt-opt.lo \
	lib/libcrypt_la-crypt-yescrypt.lo \
	lib/libcrypt_la-util-base64.lo \
	lib/libcrypt_la-util-xbzero.lo \
	lib/libcrypt_la-util-xstrcpy.lo \
	$(COMMON_TEST_OBJECTS)

test_explicit_bzero_LDADD = \
	lib/libcrypt_la-util-xbzero.lo
test_getrandom_interface_LDADD = \
	lib/libcrypt_la-util-get-random-bytes.lo \
	lib/libcrypt_la-util-xbzero.lo
test_getrandom_fallbacks_LDADD = \
	lib/libcrypt_la-util-get-random-bytes.lo \
	lib/libcrypt_la-util-xbzero.lo


if HAVE_LD_WRAP
test_getrandom_fallbacks_LDFLAGS = \
  -Wl,--wrap,getentropy -Wl,--wrap,getrandom -Wl,--wrap,syscall \
  -Wl,--wrap,open -Wl,--wrap,open64 -Wl,--wrap,read -Wl,--wrap,close \
  $(AM_LDFLAGS)
endif

# CI sometimes wants to compile all the test programs but not run them.
test-programs: $(check_PROGRAMS)
phony_targets += test-programs

# Additional checks to run in `make distcheck'.
distcheck-hook:
	cd $(top_srcdir) && \
	  $(PERL) ./$(SCRIPTS_AUX)/check-perlcritic-config && \
	  perlcritic --quiet ./

# Target for generating a signed release tarball.
release: libxcrypt-$(VERSION).tar.xz.sha256sum libxcrypt-gpgkey.gpg
phony_targets += release

libxcrypt-$(VERSION).tar.xz.asc: dist-xz
	$(GPG2) \
		--quiet \
		--armor \
		--detach-sign \
		--default-key F52E98007594C21D \
		--output libxcrypt-$(VERSION).tar.xz.asc.T \
		libxcrypt-$(VERSION).tar.xz
	$(AM_V_at)$(SCRIPTS_AUX)/move-if-change \
		libxcrypt-$(VERSION).tar.xz.asc.T \
		libxcrypt-$(VERSION).tar.xz.asc

libxcrypt-$(VERSION).tar.xz.sha256sum: libxcrypt-$(VERSION).tar.xz.asc
	$(SHA256SUM) \
		libxcrypt-$(VERSION).tar.xz \
		libxcrypt-$(VERSION).tar.xz.asc \
		> libxcrypt-$(VERSION).tar.xz.sha256sum.T
	$(AM_V_at)$(SCRIPTS_AUX)/move-if-change \
		libxcrypt-$(VERSION).tar.xz.sha256sum.T \
		libxcrypt-$(VERSION).tar.xz.sha256sum

libxcrypt-gpgkey.gpg:
	$(GPG2) \
		--export \
		--export-options \
			export-minimal \
			F52E98007594C21D \
		> libxcrypt-gpgkey.gpg.T
	$(AM_V_at)$(SCRIPTS_AUX)/move-if-change \
		libxcrypt-gpgkey.gpg.T \
		libxcrypt-gpgkey.gpg

CLEANFILES += \
	libxcrypt-$(VERSION).tar.xz.asc* \
	libxcrypt-$(VERSION).tar.xz.sha256sum* \
	libxcrypt-gpgkey.gpg*

# Every object file depends on crypt-symbol-vers.h and crypt-hashes.h,
# which are generated files, so automatic dependency generation is not
# sufficient.
include $(builddir)/Makefile.deps

# Add additional targets
.PHONY: $(phony_targets)
install-exec-hook: $(install_exec_hook_targets)
uninstall-hook: $(uninstall_hook_targets)

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

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(srcdir)/lib
AM_CFLAGS = $(WARN_CFLAGS) $(OPTI_FLAGS)
AM_LDFLAGS = $(UNDEF_FLAG) $(TEXT_RELOC_FLAG) $(RELRO_FLAG) $(BINDNOW_FLAG)

AM_DISTCHECK_CONFIGURE_FLAGS = PYTHON=$(PYTHON)

CONFIG_STATUS_DEPENDENCIES = \
	lib/hashes.conf \
	lib/libcrypt.minver \
	scripts/compute-symver-floor \
	scripts/expand-selected-hashes

@VALGRIND_CHECK_RULES@

EXTRA_DIST = \
	LICENSING \
	THANKS \
	lib/alg-yescrypt-platform.c \
	lib/crypt.h.in \
	lib/hashes.conf \
	lib/libcrypt.map.in \
	lib/libcrypt.minver \
	lib/libcrypt.2.map \
	lib/xcrypt.h.in \
	scripts/common.py \
	scripts/compute-symbol-renames \
	scripts/compute-symver-floor \
	scripts/expand-selected-hashes \
	scripts/gen-crypt-h \
	scripts/gen-crypt-hashes-h \
	scripts/gen-crypt-symbol-vers-h \
	scripts/gen-libcrypt-map \
	scripts/skip-if-exec-format-error \
	scripts/test-symbols-compat.py \
	scripts/test-symbols-static.py

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
	lib/alg-yescrypt-sysendian.h \
	lib/alg-yescrypt.h \
	lib/byteorder.h \
	lib/crypt-common.h \
	lib/crypt-obsolete.h \
	lib/crypt-port.h \
	test/des-cases.h \
	test/ka-table.inc

if ENABLE_XCRYPT_COMPAT_FILES
nodist_include_HEADERS += xcrypt.h
else
nodist_noinst_HEADERS += xcrypt.h
endif

# Not actually used anymore; preserved as documentation.
noinst_PROGRAMS = \
	lib/gen-des-tables

CLEANFILES = \
	Makefile.deps Makefile.deps.T \
	crypt-symbol-vers.h crypt-symbol-vers.h.T \
	crypt-hashes.h crypt-hashes.h.T \
	crypt.h crypt.h.T \
	xcrypt.h xcrypt.h.T \
	*.gcda *.gcno \
	lib/*.gcda lib/*.gcno \
	test/*.gcda test/*.gcno

# Conditionally added to below.
lib_LIBRARIES =
noinst_LIBRARIES =
noinst_SCRIPTS =
phony_targets =
install_exec_hook_targets =
install_data_hook_targets =
uninstall_hook_targets =

libcrypt_base_a_SOURCES = \
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
	lib/crypt-common.c \
	lib/crypt-des.c \
	lib/crypt-gensalt-static.c \
	lib/crypt-gensalt.c \
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
	lib/randombytes.c

libcrypt_base_a_CPPFLAGS = $(AM_CPPFLAGS) -DIN_LIBCRYPT

# The public static library, libcrypt.a, is built from libcrypt-base.a
# by renaming all the internal symbols.  In order to avoid a conflict
# with Automake's built-in rule for building a library, we call the
# libcrypt.a artifact a noinst_SCRIPT and we install it by hand from
# the install-exec-hook.
if ENABLE_STATIC
noinst_LIBRARIES += libcrypt-base.a
noinst_SCRIPTS += libcrypt.a

libcrypt-base.a.exports: libcrypt-base.a
	$(LIST_EXPORTS_CMD)

libcrypt.a.renames: libcrypt-base.a.exports lib/libcrypt.2.map \
	            scripts/compute-symbol-renames Makefile
	$(PYTHON) $(srcdir)/scripts/compute-symbol-renames \
	    $(RENAMES_FORMAT) -p _crypt_ -o $@ libcrypt-base.a.exports \
	    $(srcdir)/lib/libcrypt.2.map $(host_os)

libcrypt.a: libcrypt.a.renames libcrypt-base.a
	$(RENAME_INTERNALS_CMD)

install_exec_hook_targets += install-exec-hook-libcrypt-a
install-exec-hook-libcrypt-a:
	$(MKDIR_P) "$(DESTDIR)$(libdir)"
	$(INSTALL) $(INSTALL_STRIP_FLAG) libcrypt.a "$(DESTDIR)$(libdir)"

uninstall_hook_targets += uninstall-libcrypt-a
uninstall-libcrypt-a:
	rm -f "$(DESTDIR)$(libdir)/libcrypt.a"

CLEANFILES += libcrypt-base.a.exports.T libcrypt-base.a.exports \
	      libcrypt.a.renames libcrypt.a
endif


# The shared library is built as a static library first, and then
# converted.
if ENABLE_SHARED
noinst_LIBRARIES += libcrypt-pic.a

libcrypt_pic_a_SOURCES  = $(libcrypt_base_a_SOURCES)
libcrypt_pic_a_CPPFLAGS = $(libcrypt_base_a_CPPFLAGS) -DPIC
libcrypt_pic_a_CFLAGS   = $(AM_CFLAGS) $(PICFLAGS)

if ENABLE_OBSOLETE_API
libcrypt_so_VER = 1
else
libcrypt_so_VER = 2
endif
if SOVER_AFTER_EXT
libcrypt_so = libcrypt$(SOEXT).$(libcrypt_so_VER)
libowcrypt_so = libowcrypt$(SOEXT).$(libcrypt_so_VER)
else
libcrypt_so = libcrypt.$(libcrypt_so_VER)$(SOEXT)
libowcrypt_so = libowcrypt.$(libcrypt_so_VER)$(SOEXT)
endif

# These variables must have names that automake does not recognize as
# per-target variable names, or it will complain about the absence of
# a buildable "libcrypt_so".
libcrypt_so_LFLAGS =
libcrypt_so_XDEPS =
if HAVE_SONAME
libcrypt_so_LFLAGS += $(SONAME)$(libcrypt_so)
endif
if HAVE_VSCRIPT
libcrypt_so_LFLAGS += $(VSCRIPT_LDFLAGS),$(builddir)/libcrypt.map
libcrypt_so_XDEPS += libcrypt.map
endif

$(libcrypt_so): libcrypt-pic.a Makefile $(libcrypt_so_XDEPS)
	$(AM_V_CCLD)$(LINK) $(SO_LDFLAGS) $(libcrypt_so_LFLAGS) \
              $(WHOLE_A) libcrypt-pic.a $(END_WHOLE_A) $(SO_LIBS)

libcrypt$(SOEXT): Makefile
	-$(AM_V_at)rm -f libcrypt$(SOEXT)
	$(AM_V_GEN)$(LN_S) $(libcrypt_so) libcrypt$(SOEXT)

# Automake rejects lib_PROGRAMS, _DATA, ... anything but LIBRARIES or
# LTLIBRARIES.  Using LTLIBRARIES will bring libtool back in, and
# automake also rejects anything that doesn't look like an .a library
# in a _LIBRARIES variable.  So we use noinst_SCRIPTS to get the
# shared library built by "make all", and we install it by hand from
# install-exec-hook.
noinst_SCRIPTS += $(libcrypt_so) libcrypt$(SOEXT)

install_exec_hook_targets += install-exec-hook-libcrypt-so
install-exec-hook-libcrypt-so:
	$(MKDIR_P) "$(DESTDIR)$(libdir)"
	$(INSTALL) $(INSTALL_STRIP_FLAG) $(libcrypt_so) "$(DESTDIR)$(libdir)"
	cd "$(DESTDIR)$(libdir)" && $(LN_S) $(libcrypt_so) libcrypt$(SOEXT)

uninstall_hook_targets += uninstall-libcrypt-so
uninstall-libcrypt-so:
	rm -f "$(DESTDIR)$(libdir)/$(libcrypt_so)" \
	      "$(DESTDIR)$(libdir)/libcrypt$(SOEXT)"

CLEANFILES += \
	libcrypt.map libcrypt.map.T \
	libcrypt$(SOEXT) $(libcrypt_so)

endif

pkgconfig_DATA = libxcrypt.pc

# Install libcrypt.pc symlink to libxcrypt.pc file.
install_data_hook_targets += install-data-hook-pkgconfig
install-data-hook-pkgconfig:
	cd "$(DESTDIR)$(pkgconfigdir)" && \
		$(LN_S) libxcrypt.pc libcrypt.pc

uninstall_hook_targets += uninstall-hook-pkgconfig
uninstall-hook-pkgconfig:
	-rm -f "$(DESTDIR)$(pkgconfigdir)/libcrypt.pc"

# Force generated headers to be generated before any source files that
# might depend on them are compiled.
Makefile.deps: crypt.h crypt-hashes.h crypt-symbol-vers.h xcrypt.h
	$(AM_V_GEN)echo "# Deps" > Makefile.deps.T
	$(AM_V_at)mv -f Makefile.deps.T Makefile.deps

libcrypt.map: lib/libcrypt.map.in scripts/gen-libcrypt-map Makefile
	$(AM_V_GEN)$(PYTHON) $(srcdir)/scripts/gen-libcrypt-map \
	  --symver-min=$(SYMVER_MIN) \
	  --symver-floor=$(SYMVER_FLOOR) \
	  --compat-api=$(COMPAT_API) \
	  libcrypt.map $(srcdir)/lib/libcrypt.map.in

crypt-hashes.h: lib/hashes.conf scripts/gen-crypt-hashes-h Makefile
	$(AM_V_GEN)$(PYTHON) $(srcdir)/scripts/gen-crypt-hashes-h \
	  --hashes=$(hashes_enabled) \
	  crypt-hashes.h $(srcdir)/lib/hashes.conf

crypt-symbol-vers.h: lib/libcrypt.map.in scripts/gen-crypt-symbol-vers-h \
		     Makefile
	$(AM_V_GEN)$(PYTHON) $(srcdir)/scripts/gen-crypt-symbol-vers-h \
	  --symver-min=$(SYMVER_MIN) \
	  --symver-floor=$(SYMVER_FLOOR) \
	  --compat-api=$(COMPAT_API) \
	  crypt-symbol-vers.h $(srcdir)/lib/libcrypt.map.in

crypt.h: lib/crypt.h.in crypt-hashes.h config.h scripts/gen-crypt-h Makefile
	$(AM_V_GEN)$(PYTHON) $(srcdir)/scripts/gen-crypt-h \
	  --config-h=config.h --hashes-h=crypt-hashes.h \
	  crypt.h $(srcdir)/lib/crypt.h.in

xcrypt.h: lib/xcrypt.h.in scripts/gen-crypt-h config.h Makefile
	$(AM_V_GEN)$(PYTHON) $(srcdir)/scripts/gen-crypt-h \
	  --config-h=config.h \
	  xcrypt.h $(srcdir)/lib/xcrypt.h.in

if ENABLE_XCRYPT_COMPAT_FILES
if ENABLE_STATIC
# Install libxcrypt.a symlink to libcrypt.a file.
install_exec_hook_targets += install-exec-hook-xcrypt-static
install-exec-hook-xcrypt-static:
	cd "$(DESTDIR)$(libdir)" && \
		$(LN_S) libcrypt.a libxcrypt.a

uninstall_hook_targets += uninstall-hook-xcrypt-static
uninstall-hook-xcrypt-static:
	-rm -f "$(DESTDIR)$(libdir)/libxcrypt.a"
endif

if ENABLE_SHARED
# Install libxcrypt$(SOEXT) symlink to libcrypt$(SOEXT) file.
install_exec_hook_targets += install-exec-hook-xcrypt-shared
install-exec-hook-xcrypt-shared:
	cd "$(DESTDIR)$(libdir)" && $(LN_S) libcrypt$(SOEXT) libxcrypt$(SOEXT)

uninstall_hook_targets += uninstall-hook-xcrypt-shared
uninstall-hook-xcrypt-shared:
	-rm -f "$(DESTDIR)$(libdir)/libxcrypt$(SOEXT)"
endif
endif

if ENABLE_COMPAT_SUSE
# When we are being binary compatible, also install symbolic links to
# mimic SUSE's libowcrypt; any program that uses -lowcrypt in its
# build, or already has a NEEDED entry for libowcrypt.so.1, will be
# redirected to libcrypt.  The OW_CRYPT_1.0 symbol versions are already
# present in libcrypt.so.1.
if ENABLE_OBSOLETE_API
if ENABLE_STATIC
install_exec_hook_targets += install-exec-hook-owcrypt-static
install-exec-hook-owcrypt-static:
	cd "$(DESTDIR)$(libdir)" && $(LN_S) libcrypt.a libowcrypt.a

uninstall_hook_targets += uninstall-hook-owcrypt-static
uninstall-hook-owcrypt-static:
	-rm -f "$(DESTDIR)$(libdir)/libowcrypt.a"
endif
if ENABLE_SHARED
install_exec_hook_targets += install-exec-hook-owcrypt-shared
install-exec-hook-libshared:
	cd "$(DESTDIR)$(libdir)" && \
		$(LN_S) libcrypt$(SOEXT) libowcrypt$(SOEXT) && \
		$(LN_S) $(libcrypt_so) $(libowcrypt_so)

uninstall_hook_targets += uninstall-hook-owcrypt-shared
uninstall-hook-owcrypt-shared:
	-rm -f "$(DESTDIR)$(libdir)/libowcrypt$(SOEXT)" \
	       "$(DESTDIR)$(libdir)/$(libowcrypt_so)"
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
	test/gensalt \
	test/gensalt-extradata \
	test/gensalt-nthash \
	test/getrandom-fallbacks \
	test/getrandom-interface \
	test/preferred-method \
	test/short-outbuf

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

# ENABLE_SHARED cannot be false when ENABLE_OBSOLETE_API is true,
# but automake does not know that.
if ENABLE_OBSOLETE_API
if ENABLE_SHARED
libcrypt_pic_a_SOURCES += lib/crypt-des-obsolete.c
check_PROGRAMS += test/des-obsolete test/des-obsolete_r test/fcrypt-enosys
endif
endif

TESTS = $(check_PROGRAMS)

if ENABLE_STATIC
TESTS += scripts/test-symbols-static.py
endif

if ENABLE_OBSOLETE_API
if ENABLE_SHARED
TESTS += scripts/test-symbols-compat.py
endif
endif

AM_TESTS_ENVIRONMENT = \
    host_os="$(host_os)"; \
    lib_a="./libcrypt.a"; \
    lib_so="./libcrypt$(SOEXT)"; \
    lib_map="$(srcdir)/lib/libcrypt.map.in"; \
    CC="$(CC)"; \
    CPP="$(CPP)"; \
    LDD="$(LDD)"; \
    NM="$(NM)"; \
    CPPFLAGS="$(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES)"; \
    CPPFLAGS="$${CPPFLAGS} $(AM_CPPFLAGS) $(CPPFLAGS)"; \
    LD_LIBRARY_PATH="$(builddir)"; DYLD_LIBRARY_PATH="$(builddir)"; \
    export host_os lib_a lib_so lib_map CC CPP CPPFLAGS LDD NM; \
    export LD_LIBRARY_PATH; export DYLD_LIBRARY_PATH;

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)

if CROSS_COMPILING
LOG_COMPILER = scripts/skip-if-exec-format-error
endif

# Refer to object files that are linked into libcrypt with the
# qualified name, lib/libcrypt_{base,pic{_a-foobar.o, to prevent
# them from being compiled a second time.
if ENABLE_SHARED
LIBCRYPT = libcrypt$(SOEXT)
LIBCRYPT_OBJ = lib/libcrypt_pic_a-
else
LIBCRYPT = libcrypt.a
LIBCRYPT_OBJ = lib/libcrypt_base_a-
endif

COMMON_TEST_OBJECTS = $(LIBCRYPT_OBJ)crypt-common.o $(LIBCRYPT)

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
test_alg_des_LDADD = \
	$(LIBCRYPT_OBJ)alg-des.o \
	$(LIBCRYPT_OBJ)alg-des-tables.o \
	$(COMMON_TEST_OBJECTS)
test_alg_gost3411_2012_LDADD = \
	$(LIBCRYPT_OBJ)alg-gost3411-2012-core.o \
	$(LIBCRYPT_OBJ)alg-gost3411-2012-hmac.o \
	$(COMMON_TEST_OBJECTS)
test_alg_gost3411_2012_hmac_LDADD = \
	$(LIBCRYPT_OBJ)alg-gost3411-2012-core.o \
	$(LIBCRYPT_OBJ)alg-gost3411-2012-hmac.o \
	$(COMMON_TEST_OBJECTS)
test_alg_hmac_sha1_LDADD = \
	$(LIBCRYPT_OBJ)alg-sha1.o \
	$(LIBCRYPT_OBJ)alg-hmac-sha1.o \
	$(COMMON_TEST_OBJECTS)
test_alg_md4_LDADD = \
	$(LIBCRYPT_OBJ)alg-md4.o \
	$(COMMON_TEST_OBJECTS)
test_alg_md5_LDADD = \
	$(LIBCRYPT_OBJ)alg-md5.o \
	$(COMMON_TEST_OBJECTS)
test_alg_pbkdf_hmac_sha256_LDADD = \
	$(LIBCRYPT_OBJ)alg-sha256.o \
	$(COMMON_TEST_OBJECTS)
test_alg_sha1_LDADD = \
	$(LIBCRYPT_OBJ)alg-sha1.o \
	$(COMMON_TEST_OBJECTS)
test_alg_sha256_LDADD = \
	$(LIBCRYPT_OBJ)alg-sha256.o \
	$(COMMON_TEST_OBJECTS)
test_alg_sha512_LDADD = \
	$(LIBCRYPT_OBJ)alg-sha512.o \
	$(COMMON_TEST_OBJECTS)
test_alg_yescrypt_LDADD = \
	$(LIBCRYPT_OBJ)alg-sha256.o \
	$(LIBCRYPT_OBJ)alg-yescrypt-common.o \
	$(LIBCRYPT_OBJ)alg-yescrypt-opt.o \
	$(COMMON_TEST_OBJECTS)
test_crypt_gost_yescrypt_LDADD = \
	$(LIBCRYPT_OBJ)alg-gost3411-2012-core.o \
	$(LIBCRYPT_OBJ)alg-gost3411-2012-hmac.o \
	$(LIBCRYPT_OBJ)alg-sha256.o \
	$(LIBCRYPT_OBJ)alg-yescrypt-common.o \
	$(LIBCRYPT_OBJ)alg-yescrypt-opt.o \
	$(LIBCRYPT_OBJ)crypt-yescrypt.o \
	$(COMMON_TEST_OBJECTS)

test_getrandom_interface_LDADD = \
	$(LIBCRYPT_OBJ)randombytes.o \
	$(COMMON_TEST_OBJECTS)
test_getrandom_fallbacks_LDADD = \
	$(LIBCRYPT_OBJ)randombytes.o \
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
.PHONY: $(phony_targets) \
	$(install_exec_hook_targets) \
	$(install_data_hook_targets) \
	$(uninstall_hook_targets)
install-exec-hook: $(install_exec_hook_targets)
install-data-hook: $(install_data_hook_targets)
uninstall-hook: $(uninstall_hook_targets)

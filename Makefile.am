#
# Copyright (c) 2002, 2007 SuSE Linux AG, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.15 gnits
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = $(WARN_CFLAGS)
AM_CPPFLAGS = -include crypt-symbols.h

include_HEADERS = crypt.h
noinst_HEADERS = \
	alg-des.h alg-md5.h alg-sha256.h alg-sha512.h byteorder.h \
	crypt-obsolete.h crypt-private.h crypt-symbols.h \
	test-des-cases.h

lib_LTLIBRARIES = libcrypt.la
libcrypt_la_SOURCES = \
	crypt.c crypt-gensalt.c crypt-bcrypt.c crypt-sha512.c crypt-sha256.c \
	alg-sha512.c alg-sha256.c

# Build libcrypt.so.2 if obsolete APIs are excluded, libcrypt.so.1 otherwise.
if ENABLE_OBSOLETE_API
libcrypt_la_VERSION = 2:0:1
else
libcrypt_la_VERSION = 2:0:0
endif

libcrypt_la_LDFLAGS = \
	-version-info $(libcrypt_la_VERSION) \
	-Wl,--version-script=$(srcdir)/libcrypt.map \
	-Wl,-z,defs -Wl,-z,text

EXTRA_DIST = libcrypt.map.in
EXTRA_libcrypt_la_DEPENDENCIES = libcrypt.map
CLEANFILES = libcrypt.map libcrypt.map.T

libcrypt.map: libcrypt.map.in
	$(AM_V_GEN)$(CPP) -P - < libcrypt.map.in > libcrypt.map.T
	$(AM_V_at)mv -f libcrypt.map.T libcrypt.map

check_PROGRAMS = \
	test-alg-sha256 test-alg-sha512 \
	test-crypt-sha256 test-crypt-sha512 test-crypt-bcrypt \
	test-byteorder test-gensalt

if ENABLE_WEAK_HASHES
libcrypt_la_SOURCES += \
	crypt-md5.c crypt-des.c alg-md5.c alg-des.c

nodist_libcrypt_la_SOURCES = \
	alg-des-tables.c
noinst_PROGRAMS = alg-des-mktables
CLEANFILES += alg-des-tables.c alg-des-tables.c.T

alg-des-tables.c: alg-des-mktables
	$(AM_V_GEN)./alg-des-mktables > alg-des-tables.c.T
	$(AM_V_at)mv -f alg-des-tables.c.T alg-des-tables.c

check_PROGRAMS += test-alg-des test-alg-md5 test-crypt-des test-crypt-md5
endif

if ENABLE_OBSOLETE_API
libcrypt_la_SOURCES += crypt-des-obsolete.c
check_PROGRAMS += test-des-obsolete test-bigcrypt
endif

TESTS = $(check_PROGRAMS) test-symbols.sh

AM_TESTS_ENVIRONMENT = \
    lib_la="./libcrypt.la"; lib_map="$(srcdir)/libcrypt.map"; \
    export lib_la lib_map;

test_crypt_bcrypt_LDADD = libcrypt.la
test_crypt_des_LDADD = libcrypt.la
test_crypt_md5_LDADD = libcrypt.la
test_crypt_sha256_LDADD = libcrypt.la
test_crypt_sha512_LDADD = libcrypt.la
test_bigcrypt_LDADD = libcrypt.la
test_gensalt_LDADD = libcrypt.la

# These tests call internal APIs that may not be accessible from the
# fully linked shared library.
test_alg_des_LDADD = alg-des.lo alg-des-tables.lo
test_alg_md5_LDADD = alg-md5.lo
test_alg_sha256_LDADD = alg-sha256.lo
test_alg_sha512_LDADD = alg-sha512.lo
test_des_obsolete_LDADD = alg-des.lo alg-des-tables.lo crypt-des-obsolete.lo

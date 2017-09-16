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
	crypt-md5.c crypt-des.c crypt-des-obsolete.c \
	alg-sha512.c alg-sha256.c alg-md5.c alg-des.c

nodist_libcrypt_la_SOURCES = \
	alg-des-tables.c

libcrypt_la_LDFLAGS = \
	-version-info 2:0:0 \
	-Wl,--version-script=$(srcdir)/libcrypt.map \
	-Wl,-z,defs -Wl,-z,text

alg-des-tables.c: alg-des-mktables
	./alg-des-mktables > alg-des-tables.c.T
	mv -f alg-des-tables.c.T alg-des-tables.c

TESTS = test-alg-des test-alg-md5 test-alg-sha256 test-alg-sha512 \
	test-crypt-des test-crypt-md5 test-crypt-sha256 test-crypt-sha512 \
	test-crypt-bcrypt \
	test-byteorder test-des-obsolete test-bigcrypt test-gensalt

noinst_PROGRAMS = $(TESTS) alg-des-mktables

EXTRA_DIST = libcrypt.map
CLEANFILES = alg-des-tables.c

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

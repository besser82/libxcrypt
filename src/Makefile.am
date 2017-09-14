#
# Copyright (c) 2002, 2007 SuSE Linux AG, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.7 gnits

AM_CFLAGS = $(WARN_CFLAGS)
AM_CPPFLAGS = -include libc-symbols.h

CLEANFILES = *~

EXTRA_DIST = libxcrypt.map

TESTS = test-bcrypt test-bigcrypt test-byteorder test-des test-gensalt \
	test-md5 test-md5-crypt test-sha256 test-sha256-crypt test-sha512 \
	test-sha512-crypt

include_HEADERS = crypt.h
noinst_HEADERS = byteorder.h crypt-obsolete.h libc-symbols.h \
	xcrypt-private.h des.h md5.h sha256.h sha512.h bcrypt.h

libxcrypt_la_LDFLAGS = -version-info 2:0:0 \
			-Wl,--version-script=$(srcdir)/libxcrypt.map \
			-Wl,-z,defs -Wl,-z,text

lib_LTLIBRARIES = libxcrypt.la

libxcrypt_la_SOURCES = \
	xcrypt.c xcrypt-gensalt.c bcrypt.c sha256.c sha256-crypt.c \
	sha512.c sha512-crypt.c md5.c md5-crypt.c \
	des.c des-crypt.c des-tables.c des-obsolete.c

nodist_libxcrypt_la_SOURCES = \
	des-tables2.c

CLEANFILES += des-tables2.c

des-tables2.c: des-mktables
	./des-mktables > des-tables2.c.T
	-mv -f des-tables2.c.T des-tables2.c

noinst_PROGRAMS = $(TESTS) des-mktables

des_mktables_SOURCES = des-mktables.c
des_mktables_LDADD = des-tables.lo

test_bcrypt_LDADD = libxcrypt.la
test_bigcrypt_LDADD = libxcrypt.la
test_des_LDADD = libxcrypt.la
test_gensalt_LDADD = libxcrypt.la
test_md5_crypt_LDADD = libxcrypt.la
test_sha256_crypt_LDADD = libxcrypt.la
test_sha512_crypt_LDADD = libxcrypt.la

test_md5_LDADD = md5.lo
test_sha256_LDADD = sha256.lo
test_sha512_LDADD = sha512.lo

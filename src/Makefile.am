#
# Copyright (c) 2002, 2007 SuSE Linux AG, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.7 gnits

AM_CFLAGS = @EXTRA_CFLAGS@ -D_REENTRANT=1 -D_GNU_SOURCE
AM_CPPFLAGS = -include libc-symbols.h

CLEANFILES = *~

EXTRA_DIST = libxcrypt.map cert.sh cert.input

TESTS = cert.sh bigcrypt-test gensalt-test blowfish-test \
	md5test md5c-test sha256test sha256c-test sha512test sha512c-test

include_HEADERS = crypt.h
noinst_HEADERS = crypt-private.h libc-symbols.h ufc-crypt.h \
	xcrypt-private.h md5.h sha256.h sha512.h \
	crypt_blowfish.h ow-crypt.h crypt-obsolete.h

libxcrypt_la_LDFLAGS = -version-info 2:0:0 \
			-Wl,--version-script=$(srcdir)/libxcrypt.map \
			-Wl,-z,defs -Wl,-z,text
libxcrypt_la_LIBADD = -lpthread

lib_LTLIBRARIES = libxcrypt.la

libxcrypt_la_SOURCES = \
	crypt-entry.c crypt.c crypt_util.c crypt_gensalt.c xcrypt.c bigcrypt.c \
	crypt_blowfish.c md5.c md5-crypt.c sha256.c sha256-crypt.c \
	sha512.c sha512-crypt.c

noinst_PROGRAMS = cert bigcrypt-test gensalt-test blowfish-test \
	md5test md5c-test sha256test sha256c-test sha512test sha512c-test

cert_LDADD = libxcrypt.la
bigcrypt_test_LDADD = libxcrypt.la
gensalt_test_LDADD = libxcrypt.la
blowfish_test_LDADD = libxcrypt.la
md5c_test_LDADD = libxcrypt.la
sha256c_test_LDADD = libxcrypt.la
sha512c_test_LDADD = libxcrypt.la

md5test_LDADD = md5.lo
sha256test_LDADD = sha256.lo
sha512test_LDADD = sha512.lo

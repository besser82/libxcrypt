#
# Copyright (c) 2002, 2007 SuSE Linux AG, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.7 gnits

plugindir = $(libdir)/xcrypt

AM_CFLAGS = @EXTRA_CFLAGS@ -D_REENTRANT=1 -D_GNU_SOURCE \
	-DPLUGINDIR=\"$(plugindir)\"
INCLUDES = -include libc-symbols.h

CLEANFILES = *~

EXTRA_DIST = libxcrypt.map cert.sh cert.input

TESTS = cert.sh bigcrypt-test gensalt-test

include_HEADERS = xcrypt.h
noinst_HEADERS = crypt-private.h libc-symbols.h ufc-crypt.h xcrypt-private.h

libxcrypt_la_LDFLAGS = -version-info 2:0:0 \
			-Wl,--version-script=$(srcdir)/libxcrypt.map
libxcrypt_la_LIBADD = -ldl

lib_LTLIBRARIES = libxcrypt.la

libxcrypt_la_SOURCES = crypt-entry.c crypt.c crypt_util.c \
                      crypt_gensalt.c xcrypt.c bigcrypt.c

noinst_PROGRAMS = cert bigcrypt-test gensalt-test

cert_LDADD = libxcrypt.la
bigcrypt_test_LDADD = libxcrypt.la
gensalt_test_LDADD = libxcrypt.la


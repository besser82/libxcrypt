#
# Copyright (c) 2007 SUSE Linux Products GmbH, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.7 gnits

plugindir = $(libdir)/xcrypt

AM_CFLAGS = @EXTRA_CFLAGS@ -D_REENTRANT=1 -D_GNU_SOURCE

AM_CPPFLAGS = -I $(top_srcdir)/src -I $(top_srcdir)/plugins

CLEANFILES = *~

TESTS = sha512test sha512c-test

libxcrypt_6_la_LDFLAGS = -version-info 1:0:0 \
		-Wl,--version-script=$(top_srcdir)/plugins/plugin.map

plugin_LTLIBRARIES = libxcrypt_6.la

libxcrypt_6_la_SOURCES = sha512.c sha512-crypt.c

noinst_PROGRAMS = sha512test sha512c-test
noinst_HEADERS = sha512.h

sha512test_LDADD = sha512.lo
sha512c_test_LDADD = libxcrypt_6.la

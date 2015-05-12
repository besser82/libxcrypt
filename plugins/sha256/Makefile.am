#
# Copyright (c) 2007 SUSE Linux Products GmbH, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.7 gnits

plugindir = $(libdir)/xcrypt

AM_CFLAGS = @EXTRA_CFLAGS@ -D_REENTRANT=1 -D_GNU_SOURCE

INCLUDES = -I $(top_srcdir)/src -I $(top_srcdir)/plugins

CLEANFILES = *~

TESTS = sha256test sha256c-test

libxcrypt_5_la_LDFLAGS = -version-info 1:0:0 \
		-Wl,--version-script=$(top_srcdir)/plugins/plugin.map

plugin_LTLIBRARIES = libxcrypt_5.la

libxcrypt_5_la_SOURCES = sha256.c sha256-crypt.c

noinst_PROGRAMS = sha256test sha256c-test
noinst_HEADERS = sha256.h

sha256test_LDADD = sha256.lo
sha256c_test_LDADD = libxcrypt_5.la

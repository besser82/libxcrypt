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

TESTS = md5test md5c-test

libxcrypt_1_la_LDFLAGS = -version-info 1:0:0 \
		-Wl,--version-script=$(top_srcdir)/plugins/plugin.map

plugin_LTLIBRARIES = libxcrypt_1.la

libxcrypt_1_la_SOURCES = md5.c md5-crypt.c

noinst_PROGRAMS = md5test md5c-test
noinst_HEADERS = md5.h

md5test_LDADD = md5.lo
md5c_test_LDADD = libxcrypt_1.la

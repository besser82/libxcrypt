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

TESTS = blowfish-test

libxcrypt_2a_la_LDFLAGS = -version-info 1:0:0 \
		-Wl,--version-script=$(top_srcdir)/plugins/plugin.map

plugin_LTLIBRARIES = libxcrypt_2a.la

libxcrypt_2a_la_SOURCES = crypt_blowfish.c

noinst_PROGRAMS = blowfish-test

blowfish_test_CFLAGS = $(AM_CFLAGS) -DTEST_THREADS=10
blowfish_test_LDADD = libxcrypt_2a.la -lpthread

#
# Copyright (c) 2002, 2003 SuSE Linux AG, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#
ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = 1.7 foreign dist-bzip2
MAINT_CHARSET = latin1
#
SUBDIRS = src

CLEANFILES = *~

EXTRA_DIST = ChangeLog README README.bcrypt README.ufc-crypt COPYING.LIB LICENSE.bcrypt

LIBTOOL_DEPS = @LIBTOOL_DEPS@

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

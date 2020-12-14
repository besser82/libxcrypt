# Generation of crypt.h from crypt.h.in and config.h.
#
# Written by Zack Weinberg <zackw at panix.com> in 2017.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

BEGIN {
    HAVE_SYS_CDEFS_H = 0
    HAVE_SYS_CDEFS_BEGIN_END_DECLS = 0
    HAVE_SYS_CDEFS_THROW = 0
}
END {
    if (!HAVE_SYS_CDEFS_H &&
        (HAVE_SYS_CDEFS_BEGIN_END_DECLS ||
         HAVE_SYS_CDEFS_THROW)) {
        print "config.h is inconsistent" > "/dev/stderr"
        close("/dev/stderr")
        exit 1
    }
}
FILENAME ~ /config\.h$/ {
    if ($0 ~ /^#define HAVE_SYS_CDEFS_H 1$/) {
        HAVE_SYS_CDEFS_H = 1
    } else if ($0 ~ /^#define HAVE_SYS_CDEFS_BEGIN_END_DECLS 1$/) {
        HAVE_SYS_CDEFS_BEGIN_END_DECLS = 1
    } else if ($0 ~ /^#define HAVE_SYS_CDEFS_THROW 1$/) {
        HAVE_SYS_CDEFS_THROW = 1
    }
}
FILENAME !~ /config\.h$/ {
    if ($0 ~ /^\/\*HEADER\*\/$/) {
        if (HAVE_SYS_CDEFS_H) {
            print "#include <sys/cdefs.h>"
        }
        if (!HAVE_SYS_CDEFS_THROW) {
            print "#define __THROW /* nothing */"
        }
        print ""
        if (HAVE_SYS_CDEFS_BEGIN_END_DECLS) {
            print "__BEGIN_DECLS"
        } else {
            print "#ifdef __cplusplus"
            print "extern \"C\" {"
            print "#endif"
        }

    } else if ($0 ~ /^\/\*TRAILER\*\/$/) {
        if (HAVE_SYS_CDEFS_BEGIN_END_DECLS) {
            print "__END_DECLS"
        } else {
            print "#ifdef __cplusplus"
            print "} /* extern \"C\" */"
            print "#endif"
        }

    } else {
        print;
    }
}

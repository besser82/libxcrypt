#! /usr/bin/perl
# Written by Zack Weinberg <zackw at panix.com> in 2017 and 2020.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

# This test is only run if we are building a shared library intended
# to be binary backward compatible with GNU libc (libcrypt.so.1).
# It locates any installed version of libcrypt.so.1, and verifies that
# each public symbol exposed by that library is also exposed by our
# libcrypt.so.1 with a matching symbol version.
#
# Due to limitations in Automake, this program takes parameters from
# the environment:
# $lib_la - full pathname of libcrypt.la
# $SYMBOL_PREFIX - prefix, if any, added to global symbols defined from C
# $CC, $NM - names of tools to run (defaults to 'cc' and 'nm' respectively)
# $CFLAGS, $LDFLAGS - options to pass to $CC when linking (default: empty)

use v5.14;    # implicit use strict, use feature ':5.14'
use warnings FATAL => 'all';
use utf8;
use open qw(:std :utf8);
no  if $] >= 5.022, warnings => 'experimental::re_strict';
use if $] >= 5.022, re       => 'strict';

use FindBin ();
use lib $FindBin::Bin;
use TestCommon qw(
    compare_symbol_lists
    ensure_C_locale
    find_real_library
    get_symbols
    popen
    sh_split
    skip
    subprocess_error
    which
);

# Some differences between the symbols exported by heritage libcrypt.so.1
# and our libcrypt.so.1 are expected:
#
#  * All of the symbols we define with GLIBC_2.xx version tags are
#    compatibility symbols (nm prints only one @); naturally,
#    glibc-provided libcrypt.so.1 defines some of those symbols as
#    linkable symbols (two @).
#
#  * Older versions of libcrypt defined five symbols as linkable,
#    with the XCRYPT_2.0 version tag, which are now compatibility-only:
#    crypt_gensalt_r, xcrypt, xcrypt_gensalt, xcrypt_gensalt_r, and
#    xcrypt_r.
#
# This sub is applied to the symbol listing from the system-provided
# libcrypt.so.1; it edits that listing so that the comparison below
# succeeds despite any expected differences.
sub filter_expected_differences {
    my $symbols = shift;
    my %filtered;
    my $formerly_linkable = qr{
        ^ (?: crypt_gensalt_r
            | xcrypt(?: _r)?
            | xcrypt_gensalt(?: _r)?
          ) @@
    }x;
    for my $s (keys %{$symbols}) {
        $s =~ s/\b@@(?=GLIBC_)/@/;
        $s =~ s/\b@@(?=XCRYPT_2\.0)/@/ if $s =~ $formerly_linkable;
        $filtered{$s} = 1;
    }
    return \%filtered;
}

sub find_system_libcrypt {
    # Ask the compiler whether a libcrypt.so.1 exists in its search
    # path.  The compiler option -print-file-name should be supported
    # on all operating systems where there's an older libcrypt that we
    # can be backward compatible with.
    state @CC;
    if (!@CC) {
        @CC = which($ENV{CC} || 'cc');
        skip('C compiler not available') unless @CC;
    }

    state @CFLAGS;
    if (!@CFLAGS) {
        @CFLAGS = sh_split($ENV{CFLAGS} || q{});
    }
    state @LDFLAGS;
    if (!@LDFLAGS) {
        @LDFLAGS = sh_split($ENV{LDFLAGS} || q{});
    }

    my $fh =
        popen('-|', @CC, @CFLAGS, @LDFLAGS, '-print-file-name=libcrypt.so.1');
    my $path;
    {
        local $/ = undef;    # slurp
        $path = <$fh>;
    }
    close $fh or subprocess_error($CC[0]);

    chomp $path;
    # If we get back either the empty string or the same string we put
    # in, it means there is no libcrypt.so.1 on this system.
    if ($path eq q{} || $path eq 'libcrypt.so.1') {
        skip('no system-provided libcrypt.so.1');
    }
    return $path;
}

sub get_our_symbols {
    return get_symbols(find_real_library(shift, 'shared'));
}

sub get_their_symbols {
    return filter_expected_differences(get_symbols(find_system_libcrypt()));
}

#
# Main
#
my $lib_la = $ENV{lib_la} || '/nonexistent';
if (!-f $lib_la) {
    print {*STDERR} "usage: lib_la=/path/to/library.la $0";
    exit 1;
}

ensure_C_locale();
exit compare_symbol_lists(
    get_our_symbols($lib_la),
    get_their_symbols(),
    'symbol versions',
    1,    # extra symbols are allowed
);

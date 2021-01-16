#! /usr/bin/perl
# Written by Zack Weinberg <zackw at panix.com> in 2017 and 2020.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

# Check that all of the symbols renamed by crypt-port.h
# still appear somewhere in the source code.  This test does not attempt
# to parse the source code, so it can get false negatives (e.g. a word used
# in a comment will be enough).
#
# Due to limitations in Automake, this program takes parameters from
# the environment:
# $lib_la - full pathname of libcrypt.la
# $SYMBOL_PREFIX - prefix, if any, added to global symbols defined from C
# $NM, $CPP, $CPPFLAGS - nm utility, C preprocessor, and parameters

use v5.14;    # implicit use strict, use feature ':5.14'
use warnings FATAL => 'all';
use utf8;
use open qw(:std :utf8);
no  if $] >= 5.022, warnings => 'experimental::re_strict';
use if $] >= 5.022, re       => 'strict';

use File::Temp ();

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

sub list_library_internals {
    # We are only interested in symbols with the internal prefix,
    # _crypt_.
    return get_symbols(find_real_library(shift, 'static'),
        sub { $_[0] =~ /^_crypt_/ });
}

sub list_symbol_renames {
    state @CPP;
    if (!@CPP) {
        @CPP = which($ENV{CPP} || 'cc -E');
        skip('C compiler not available') unless @CPP;
    }
    state @CPPFLAGS;
    if (!@CPPFLAGS) {
        @CPPFLAGS = sh_split($ENV{CPPFLAGS} || q{});
    }

    my $tmp = File::Temp->new(
        DIR      => '.',
        TEMPLATE => 'symbols-renames-XXXXXX',
        SUFFIX   => '.c',
        EXLOCK   => 0,
    );
    print {$tmp} qq{#include "crypt-port.h"\n};

    my $fh = popen('-|', @CPP, @CPPFLAGS, '-dD', $tmp->filename);
    local $_;
    my %symbols;
    my $pp_define = qr{
        ^\#define \s+
            [a-zA-Z_][a-zA-Z0-9_(),]* \s+
            (_crypt_[a-zA-Z0-9_]*) \b
    }x;
    while (<$fh>) {
        chomp;
        s/\s+$//;
        if ($_ =~ $pp_define) {
            print {*STDERR} "| $1\n";
            $symbols{$1} = 1;
        }
    }
    close $fh or subprocess_error($CPP[0]);
    return \%symbols;
}

#
# Main
#
my $lib_la = $ENV{lib_la} || '/nonexistent';
if (!-f $lib_la) {
    print {*STDERR} "usage: lib_la=/path/to/library.la $0";
    exit 1;
}
if (($ENV{HAVE_CPP_dD} // 'yes') eq 'no') {
    skip('cpp -dD not available');
}

ensure_C_locale();
exit compare_symbol_lists(
    list_library_internals($lib_la),
    list_symbol_renames(),
    'renames',
    0,    # extra symbols not allowed
);

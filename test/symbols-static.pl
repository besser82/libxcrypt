#! /usr/bin/perl
# Written by Zack Weinberg <zackw at panix.com> in 2017 and 2020.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

# Test that all global symbols in the static version of the library
# (libcrypt.a) are either listed as global and supported for new code
# in libcrypt.map.in, or begin with a _crypt prefix.  Also test that
# all of the global, supported for new code, symbols mentioned in
# libcrypt.map.in are in fact defined.
#
# Due to limitations in Automake, this program takes parameters from
# the environment:
# $lib_la - full pathname of libcrypt.la
# $lib_map - full pathname of libcrypt.map.in
# $SYMBOL_PREFIX - prefix, if any, added to global symbols defined from C
# $NM, $CPP, $CPPFLAGS - nm utility, C preprocessor, and parameters

use v5.14;    # implicit use strict, use feature ':5.14'
use warnings FATAL => 'all';
use utf8;
use open qw(:std :utf8);
no  if $] >= 5.022, warnings => 'experimental::re_strict';
use if $] >= 5.022, re       => 'strict';

use FindBin ();
use lib $FindBin::Bin;
use TestCommon qw(
    error
    ensure_C_locale
    find_real_library
    get_symbols
    compare_symbol_lists
);

my $symbol_prefix = $ENV{SYMBOL_PREFIX} || q{};

sub list_library_globals {
    # Symbols that begin with _crypt_ are private to the library.
    # Symbols that begin with _[_A-Y] are private to the C
    # implementation.  All other symbols (including any that begin
    # with _Z, which are C++ mangled names) are part of the library's
    # public interface.
    return get_symbols(
        find_real_library(shift, 'static'),
        sub { $_[0] !~ /^_(?:[_A-Y]|crypt_)/ },
    );
}

sub list_expected_globals {
    my ($lib_map) = @_;
    open my $fh, '<', $lib_map
        or error("$lib_map: $!");

    local $_;
    my %symbols;
    while (<$fh>) {
        chomp;
        s/\s+$//;
        next if /^($|#|%chain\b)/;

        my @fields = split;
        $symbols{$fields[0]} = 1 if $fields[1] ne '-';
    }
    return \%symbols;
}

#
# Main
#
my $lib_la  = $ENV{lib_la}  || '/nonexistent';
my $lib_map = $ENV{lib_map} || '/nonexistent';
if (!-f $lib_la || !-f $lib_map) {
    print {*STDERR} "usage: lib_la=/p/lib.la lib_map=/p/lib.map $0";
    exit 1;
}

ensure_C_locale();
exit compare_symbol_lists(
    list_library_globals($lib_la),
    list_expected_globals($lib_map),
    'globals',
    0,    # extra symbols not allowed
);

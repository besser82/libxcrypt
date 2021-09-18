# Written by Zack Weinberg <zackw at panix.com> in 2020.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

# Code shared among all of the Perl-language tests in this directory.

package TestCommon;

use v5.14;    # implicit use strict, use feature ':5.14'
use warnings FATAL => 'all';
use utf8;
use open qw(:utf8);

no  if $] >= 5.022, warnings => 'experimental::re_strict';
use if $] >= 5.022, re       => 'strict';

use Cwd qw(realpath);
use File::Spec::Functions qw(
    catdir
    catpath
    splitpath
);
use FindBin ();
use POSIX   ();

use lib "$FindBin::Bin/../build-aux/scripts";
## ProhibitUnusedImport does not notice uses from @EXPORT_OK.
## no critic (TooMuchCode::ProhibitUnusedImport)
use BuildCommon qw(
    ensure_C_locale
    error
    popen
    sh_split
    sh_quote
    subprocess_error
    which
);
## use critic

our @EXPORT_OK;
use Exporter qw(import);

BEGIN {
    # Re-export all the subprocess handling routines from BuildCommon
    # as a convenience for individual tests.
    @EXPORT_OK = qw(
        compare_symbol_lists
        ensure_C_locale
        error
        fail
        find_real_library
        get_symbols
        popen
        sh_quote
        sh_split
        skip
        subprocess_error
        which
    );
}

# Diagnostics: report that the test has failed.
sub fail {    ## no critic (Subroutines::RequireArgUnpacking)
    my $msg = join q{ }, @_;
    print {*STDERR} $FindBin::Script, ': FAIL: ', $msg, "\n";
    exit 1;
}

# Diagnostics: report that the test should be 'skipped' because
# some piece of infrastructure we need is missing.
sub skip {    ## no critic (Subroutines::RequireArgUnpacking)
    my $msg = join q{ }, @_;
    print {*STDERR} $FindBin::Script, ': skipping test: ', $msg, "\n";
    exit 77;
}

# Parse a .la file (arg 1) and determine the name of the actual .a or
# .so file it refers to (arg 2: 'static' for .a, 'shared' for .so)
sub find_real_library {
    my ($lib_la, $type) = @_;

    state @SH;
    if (!@SH) {
        @SH = which($ENV{SHELL} || $ENV{CONFIG_SHELL} || '/bin/sh');
        error('no shell available???') if !@SH;
    }

    my $param;
    if ($type eq 'shared') {
        $param = 'dlname';
    } elsif ($type eq 'static') {
        $param = 'old_library';
    } else {
        error("unknown library type: '$type'");
    }

    # We're going to interpolate $lib_la into a shell command.
    # Save the unmangled directory part first, then quote it.
    my ($vol, $dir, undef) = splitpath($lib_la);
    $lib_la = sh_quote($lib_la);

    # .la files are shell script fragments.  The easiest way to learn
    # the name of the actual library is to ask a shell to parse the
    # fragment for us.
    my $fh = popen('-|', @SH, '-c', ". $lib_la; printf %s \"\$$param\"");
    my $real_library;
    {
        local $/ = undef;    # slurp
        $real_library = <$fh>;
    }
    close $fh or subprocess_error($SH[0]);

    chomp $real_library;
    $real_library = catpath($vol, catdir($dir, '.libs'), $real_library);
    error("'$real_library' does not exist") unless -f $real_library;
    return realpath($real_library);
}

# In some object file formats, all symbols defined in C have an
# underscore prepended to their names.  The configure script detects
# this and the Makefiles set this environment variable appropriately.
my $symbol_prefix = $ENV{SYMBOL_PREFIX} || q{};

# Return a hashset of symbols exported by the library $_[0], using readelf.
# If it is a dynamic library, annotate each symbol with its version tag.
sub get_symbols_readelf {
    my $lib    = shift;
    my $filter = shift // sub { 1 };

    state $readelf_works = 1;
    die "readelf doesn't work\n" unless $readelf_works;

    state @READELF;
    if (!@READELF) {
        @READELF = which($ENV{READELF} || 'readelf');
        die "readelf not available\n" unless @READELF;
    }

    my @opts              = ('--wide');
    my $want_version_tags = 0;
    if ($lib =~ /\.(?:a|lib)$/) {
        push @opts, '--syms';
    } else {
        push @opts, '--dyn-syms';
        $want_version_tags = 1;
    }

    my $fh = popen('-|', @READELF, @opts, $lib);

    local $_;
    my %symbols;
    my $saw_version_tags = 0;
    while (<$fh>) {
        chomp;
        s/\s+$//;
        next if /^(?:$|File:|Symbol table)/;
        next if /^\s*Num:\s+Value\s+Size\s+Type\s+Bind\s+Vis\s+Ndx\s+Name$/;

        my ($num, $value, $size, $type, $bind, $vis, $ndx, $name) = split;

        # We are only interested in globally visible, defined,
        # non-absolute symbols.
        next
            if $ndx eq 'UND'
            || $ndx eq 'ABS'
            || $bind eq 'LOCAL';

        # Strip the symbol prefix, if any, from each symbol.
        $name =~ s/^$symbol_prefix// if $symbol_prefix ne q{};

        $saw_version_tags = 1 if $name =~ /@[A-Z_]+[0-9]/;

        if (&{$filter}($name)) {
            print {*STDERR} "|+ $name\n";
            $symbols{$name} = 1;
        } else {
            print {*STDERR} "|- $name\n";
        }
    }
    if (!close $fh) {
        # If it ran but exited 1 or 2, don't give up yet, we still
        # have nm to try.
        if ($! == 0 && ($? == 256 || $? == 512)) {
            $readelf_works = 0;
            die "$READELF[0] exited " . ($? >> 2) . "\n";
        }
        subprocess_error($READELF[0]);
    }
    if ($want_version_tags && !$saw_version_tags) {
        $readelf_works = 0;
        die "$READELF[0] did not print version tags\n";
    }
    return \%symbols;
}

# Return a hashset of symbols exported by the library $_[0], using nm.
# If it is a dynamic library, annotate each symbol with its version tag.
sub get_symbols_nm {
    my $lib    = shift;
    my $filter = shift // sub { 1 };

    state $nm_works = 1;
    die "nm doesn't work\n" unless $nm_works;

    state @NM;
    if (!@NM) {
        @NM = which($ENV{NM} || 'nm');
        die "nm not available\n" unless @NM;
    }

    my @opts              = qw(--format=bsd --extern-only --defined-only);
    my $want_version_tags = 0;
    if ($lib !~ /\.(?:a|lib)$/) {
        push @opts, qw(--dynamic --with-symbol-versions);
        $want_version_tags = 1;
    }

    my $fh = popen('-|', @NM, @opts, $lib);
    local $_;
    my %symbols;
    my $saw_version_tags = 0;
    while (<$fh>) {
        chomp;
        s/\s+$//;
        next unless $_;

        # BSD-format nm output, when restricted to external, defined
        # symbols, has three fields per line: address type name.
        # We shouldn't ever see symbols with the address field blank,
        # but just in case, discard them.
        next unless /^([0-9a-fA-F]+)\s+([A-Za-z])\s+(\S+)$/;
        my $addr = $1;
        my $type = $2;
        my $name = $3;

        # Symbols whose address is 0 and type is A are uninteresting;
        # they define the set of symbol version tags.
        next if $addr =~ /^0+$/ && $type eq 'A';

        # Strip the symbol prefix, if any, from each symbol.
        $name =~ s/^$symbol_prefix// if $symbol_prefix;

        # Compensate for a bug in some versions of GNU nm
        # where the symbol version is printed twice.
        $name =~ s/(@+[A-Z0-9_.]+)\1$/$1/;

        $saw_version_tags = 1 if $name =~ /@[A-Z_]+[0-9]/;

        if (&{$filter}($name)) {
            print {*STDERR} "|+ $name\n";
            $symbols{$name} = 1;
        } else {
            print {*STDERR} "|- $name\n";
        }
    }
    if (!close $fh) {
        # If it ran but exited 1 or 2, don't give up yet, we still
        # have readelf to try.
        if ($! == 0 && ($? == 256 || $? == 512)) {
            $nm_works = 0;
            die "$NM[0] exited " . ($? >> 8) . "\n";
        }
        subprocess_error($NM[0]);
    }
    if ($want_version_tags && !$saw_version_tags) {
        $nm_works = 0;
        die "$NM[0] did not print version tags\n";
    }
    return \%symbols;
}

# Return a hashset of symbols exported by the library $_[0], using
# readelf or nm, whichever works on this system.  If it is a dynamic
# library, annotate each symbol with its version tag.  If $_[1] is
# defined, it is a filter procedure; only symbols for which the filter
# returns true are included in the hashset.
sub get_symbols {    ## no critic (Subroutines::RequireArgUnpacking)
    my $result;

    $result = eval { get_symbols_nm(@_); };
    return $result if $result;
    print {*STDERR} "get_symbols_nm: $@";

    $result = eval { get_symbols_readelf(@_); };
    return $result if $result;
    print {*STDERR} "get_symbols_readelf: $@";

    skip('cannot get symbols using either readelf or nm');
}

sub compare_symbol_lists {
    my ($found, $expected, $tag, $extra_allowed) = @_;
    my @extra;
    my @missing;
    local $_;
    for (keys %{$expected}) {
        push @missing, $_ unless exists $found->{$_};
    }
    for (keys %{$found}) {
        push @extra, $_ unless exists $expected->{$_};
    }

    my $error = 0;
    if (@extra) {
        $error = 1 unless $extra_allowed;
        print {*STDERR} "*** Extra $tag:\n";
        for (sort @extra) {
            s/^_crypt_//;
            print {*STDERR} "  $_\n";
        }
    }
    if (@missing) {
        $error = 1;
        print {*STDERR} "*** Missing $tag:\n";
        for (sort @missing) {
            s/^_crypt_//;
            print {*STDERR} "  $_\n";
        }
    }
    return $error;
}

1;

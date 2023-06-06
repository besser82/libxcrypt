# Written by Zack Weinberg <zackw at panix.com> in 2017 and 2020.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

package BuildCommon;

use v5.14;    # implicit use strict, use feature ':5.14'
use warnings FATAL => 'all';
use utf8;
use open qw(:utf8);
no  if $] >= 5.022, warnings => 'experimental::re_strict';
use if $] >= 5.022, re       => 'strict';

use Cwd qw(realpath);
use File::Spec::Functions qw(
    catfile
    catpath
    file_name_is_absolute
    path
    splitpath
);
use FindBin ();
use POSIX   ();

our @EXPORT_OK;
use Exporter qw(import);

BEGIN {
    @EXPORT_OK = qw(
        enabled_set
        ensure_C_locale
        error
        parse_hashes_conf
        parse_version_map_in
        popen
        sh_split
        sh_quote
        subprocess_error
        which
    );
}

#
# Utilities for dealing with subprocesses.
#

# Diagnostics: report some kind of catastrophic internal error.
# Exit code 99 tells the Automake test driver to mark a test as
# 'errored' rather than 'failed'.
sub error {    ## no critic (Subroutines::RequireArgUnpacking)
    my $msg = join q{ }, @_;
    print {*STDERR} $FindBin::Script, ': ERROR: ', $msg, "\n";
    exit 99;
}

# Like 'error', but the problem was with a subprocess, detected upon
# trying to start the program named as @_.
sub invocation_error {    ## no critic (Subroutines::RequireArgUnpacking)
    my $err = "$!";
    my $cmd = join q{ }, @_;
    error("failed to invoke $cmd: $err");
}

# Like 'error', but the problem was with a subprocess, detected upon
# termination of the program named as @_; interpret both $! and $?
# appropriately.
sub subprocess_error {    ## no critic (Subroutines::RequireArgUnpacking)
    my $syserr = $!;
    my $status = $?;
    my $cmd    = join q{ }, @_;
    if ($syserr) {
        error("system error with pipe to $cmd: $syserr");

    } elsif ($status == 0) {
        return;

    } elsif (($status & 0xFF) == 0) {
        # we wouldn't be here if the exit status was zero
        error("$cmd: exit " . ($status >> 8));

    } else {
        my $sig = ($status & 0x7F);
        # Neither Perl core nor the POSIX module exposes strsignal.
        # This is the least terrible kludge I can presently find;
        # it decodes the numbers to their <signal.h> constant names
        # (e.g. "SIGKILL" instead of "Killed" for signal 9).
        # Linear search through POSIX's hundreds of symbols is
        # acceptable because this function terminates the process,
        # so it can only ever be called once per run.
        my $signame;
        while (my ($name, $glob) = each %{'POSIX::'}) {
            if ($name =~ /^SIG(?!_|RT)/ && (${$glob} // -1) == $sig) {
                $signame = $name;
                last;
            }
        }
        $signame //= "signal $sig";
        error("$cmd: killed by $signame");
    }
}

# Split a string into words, exactly the way the Bourne shell would do
# it, with the default setting of IFS, when the string is the result
# of a variable expansion.  If any of the resulting words would be
# changed by filename expansion, throw an exception, otherwise return
# a list of the words.
#
# Note: the word splitting process does *not* look for nested
# quotation, substitutions, or operators.  For instance, if a
# shell variable was set with
#    var='"ab cd"'
# then './a.out $var' would pass two arguments to a.out:
# '"ab' and 'cd"'.
sub sh_split {
    my @words = split /[ \t\n]+/, shift;
    for my $w (@words) {
        die "sh_split: '$w' could be changed by filename expansion"
            if $w =~ / (?<! \\) [\[?*] /ax;
    }
    return @words;
}

# Quote a string, or list of strings, so that they will pass
# unmolested through the shell.  Avoids adding quotation whenever
# possible.  Algorithm copied from Python's shlex.quote.
sub sh_quote {    ## no critic (Subroutines::RequireArgUnpacking)
    my @quoted;
    for my $w (@_) {
        if ($w =~ m{[^\w@%+=:,./-]}a) {
            my $q = $w;
            $q =~ s/'/'\\''/g;
            $q =~ s/^/'/;
            $q =~ s/$/'/;
            push @quoted, $q;
        } else {
            push @quoted, $w;
        }
    }
    return wantarray ? @quoted : $quoted[0];
}

# Emit a logging message for the execution of a subprocess whose
# argument vector is @_.
sub log_execution {    ## no critic (Subroutines::RequireArgUnpacking)
    print {*STDERR} '+ ', join(q{ }, sh_quote(@_)), "\n";
    return;
}

# Run, and log execution of, a subprocess.  @_ should be one of the
# open modes that creates a pipe, followed by an argument vector.
# An anonymous filehandle for the pipe is returned.
# Calls invocation_error() if open() fails.
# Does *not* call which(); do that yourself if you need it.
sub popen {
    my ($mode, @args) = @_;
    die "popen: inappropriate mode argument '$mode'"
        unless $mode eq '-|' || $mode eq '|-';
    die 'popen: no command to execute'
        if scalar(@args) == 0;

    log_execution(@args);
    open my $fh, $mode, @args
        or invocation_error($args[0]);
    return $fh;
}

# Force use of the C locale for this process and all subprocesses.
# This is necessary because subprocesses' output may be locale-
# dependent.  If the C.UTF-8 locale is available, it is used,
# otherwise the plain C locale.  Note that we do *not*
# 'use locale' here or anywhere else!
sub ensure_C_locale {
    use POSIX qw(setlocale LC_ALL);

    for my $k (keys %ENV) {
        if ($k eq 'LANG' || $k eq 'LANGUAGE' || $k =~ /^LC_/) {
            delete $ENV{$k};
        }
    }
    if (defined(setlocale(LC_ALL, 'C.UTF-8'))) {
        $ENV{LC_ALL} = 'C.UTF-8'; ## no critic (RequireLocalizedPunctuationVars)
    } elsif (defined(setlocale(LC_ALL, 'C'))) {
        $ENV{LC_ALL} = 'C';       ## no critic (RequireLocalizedPunctuationVars)
    } else {
        error("could not set 'C' locale: $!");
    }
    return;
}

# Clean up $ENV{PATH}, and return the cleaned path as a list.
sub clean_PATH {
    state @path;
    if (!@path) {
        for my $d (path()) {
            # Discard all entries that are not absolute paths.
            next unless file_name_is_absolute($d);
            # Discard all entries that are not directories, or don't
            # exist.  (This is not just for tidiness; realpath()
            # behaves unpredictably if called on a nonexistent
            # pathname.)
            next unless -d $d;
            # Resolve symlinks in all remaining entries.
            $d = realpath($d);
            # Discard duplicates.
            push @path, $d unless grep { $_ eq $d } @path;
        }
        error('nothing left after cleaning PATH')
            unless @path;

        # File::Spec knows internally whether $PATH is colon-separated
        # or semicolon-separated, but it won't tell us.  Assume it's
        # colon-separated unless the first element of $PATH has a
        # colon in it (and is therefore probably a DOS-style absolute
        # path, with a drive letter).
        my $newpath;
        if ($path[0] =~ /:/) {
            $newpath = join ';', @path;
        } else {
            $newpath = join ':', @path;
        }
        $ENV{PATH} = $newpath;    ## no critic (RequireLocalizedPunctuationVars)
    }
    return @path;
}

# Locate a program that we need.
# $_[0] is the name of the program along with any options that are
# required to use it correctly.  Split this into an argument list,
# exactly as /bin/sh would do it, and then search $PATH for the
# executable.  If we find it, return a list whose first element is
# the absolute pathname of the executable, followed by any options.
# Otherwise return an empty list.
sub which {
    my ($command) = @_;
    my @PATH = clean_PATH();

    # Split the command name from any options attached to it.
    my ($cmd, @options) = sh_split($command);
    my ($vol, $path, $file) = splitpath($cmd);

    if ($file eq 'false') {
        # Special case: the command 'false' is never considered to be
        # available.  Autoconf sets config variables like $CC and $NM to
        # 'false' if it can't find the requested tool.
        return ();

    } elsif ($file ne $cmd) {
        # $cmd was not a bare filename.  Do not do path search, but do
        # verify that $cmd exists and is executable, then convert it
        # to a canonical absolute path.
        #
        # Note: the result of realpath() is unspecified if its
        # argument does not exist, so we must test its existence
        # first.
        #
        # Note: if $file is a symlink, we must *not* resolve that
        # symlink, because that may change the name of the program,
        # which in turn may change what the program does.
        # For instance, suppose $CC is /usr/lib/ccache/cc, and this
        # 'cc' is a symlink to /usr/bin/ccache.  Resolving the symlink
        # will cause ccache to be invoked as 'ccache' instead of 'cc'
        # and it will error out because it's no longer being told
        # it's supposed to run the compiler.
        if (-f -x $cmd) {
            return (catfile(realpath(catpath($vol, $path, q{})), $file),
                @options);
        } else {
            return ();
        }

    } else {
        for my $d (@PATH) {
            my $cand = catfile($d, $cmd);
            if (-f -x $cand) {
                # @PATH came from clean_PATH, so all of the directories
                # have already been canonicalized.  If the last element
                # of $cand is a symlink, we should *not* resolve it (see
                # above).  Therefore, we do not call realpath here.
                return ($cand, @options);
            }
        }
        return ();

    }
}

#
# Code shared among scripts that work from hashes.conf
#

use Class::Struct HashSpec => [
    name      => '$',
    prefix    => '$',
    nrbytes   => '$',
    is_strong => '$',
];
use Class::Struct HashesConfData => [
    hashes             => '*%',
    groups             => '*%',
    max_namelen        => '$',
    max_nrbyteslen     => '$',
    max_prefixlen      => '$',
    default_candidates => '*@',
];

# The canonical list of flags that can appear in the fourth field
# of a hashes.conf entry.  Alphabetical, except for STRONG and
# DEFAULT.
my %VALID_FLAGS = (
    STRONG  => 1,
    DEFAULT => 1,
    ALT     => 1,
    DEBIAN  => 1,
    FEDORA  => 1,
    FREEBSD => 1,
    GLIBC   => 1,
    NETBSD  => 1,
    OPENBSD => 1,
    OSX     => 1,
    OWL     => 1,
    SOLARIS => 1,
    SUSE    => 1,
);

sub parse_hashes_conf {
    my $fname = shift;
    my $error = 0;

    my $err = sub {
        my ($line, $msg) = @_;
        if (!defined $msg) {
            $msg  = $line;
            $line = $.;
        }
        print {*STDERR} "$fname:$line: error: $msg\n";
        $error = 1;
    };
    my $note = sub {
        my ($line, $msg) = @_;
        if (!defined $msg) {
            $msg  = $line;
            $line = $.;
        }
        print {*STDERR} "$fname:$line: note: $msg\n";
    };

    open my $fh, '<', $fname
        or die "$fname: $!\n";

    my %line_of;
    my %hashes;
    my %groups;
    my $max_namelen    = 0;
    my $max_nrbyteslen = 0;
    my $max_prefixlen  = 0;
    my @default_candidates;
    local $_;
    while (<$fh>) {
        next if /^#/;
        chomp;
        s/\s+$//;
        next if $_ eq q{};

        my @fields = split;
        if (scalar(@fields) != 4) {
            $err->('wrong number of fields');
            next;
        }
        my ($name, $h_prefix, $nrbytes, $flags) = @fields;
        my $default_cand = 0;
        my $is_strong    = 0;
        my @grps;

        if ($name eq ':') {
            $err->('method name cannot be blank');
            $name = "_missing_$.";
        }

        # No two hashing method names can be the same.
        if (exists $line_of{$name}) {
            $err->("method name '$name' reused");
            $note->($line_of{$name}, 'previous use was here');
        } else {
            $line_of{$name} = $.;
            if ($max_namelen < length $name) {
                $max_namelen = length $name;
            }
        }

        $h_prefix = q{} if $h_prefix eq ':';
        if ($max_prefixlen < length $h_prefix) {
            $max_prefixlen = length $h_prefix;
        }

        if ($nrbytes !~ /^[0-9]+$/ || $nrbytes == 0) {
            $err->('nrbytes must be a positive integer');
            $nrbytes = 1;
        }

        if ($max_nrbyteslen < length $nrbytes) {
            $max_nrbyteslen = length $nrbytes;
        }

        $flags = q{} if $flags eq ':';
        for (split /,/, $flags) {
            if (!exists $VALID_FLAGS{$_}) {
                $err->("unrecognized flag $_");
            } elsif ($_ eq 'DEFAULT') {
                $default_cand = 1;
            } else {
                push @grps, lc;
                if ($_ eq 'STRONG') {
                    $is_strong = 1;
                }
            }
        }
        if ($default_cand && !$is_strong) {
            $err->('weak hash marked as default candidate');
        }

        next if $error;

        my $entry = HashSpec->new(
            name      => $name,
            prefix    => $h_prefix,
            nrbytes   => $nrbytes,
            is_strong => $is_strong,
        );
        $hashes{$name} = $entry;
        for my $g (@grps) {
            push @{$groups{$g}}, $entry;
        }
        if ($default_cand) {
            push @default_candidates, $entry;
        }
    }

    # No hash prefix can be a prefix of any other hash prefix, except
    # for the empty prefix.
    for my $p (values %hashes) {
        my $pp = $p->prefix;
        next if $pp eq q{};
        my $mpp = qr/^\Q$pp\E/;
        for my $q (values %hashes) {
            next if $p->name eq $q->name;
            my $pq = $q->prefix;
            next if $pq eq q{};
            if ($pq =~ $mpp) {
                $err->(
                    $line_of{$q->name},
                    "prefix collision: '$pq' begins with '$pp'",
                );
                $note->(
                    $line_of{$p->name},
                    "'$pp' used for hash '" . $p->name . q{'},
                );
            }
        }
    }

    die "errors while parsing '$fname'\n" if $error;
    return HashesConfData->new(
        hashes             => \%hashes,
        groups             => \%groups,
        max_namelen        => $max_namelen,
        max_nrbyteslen     => $max_nrbyteslen,
        max_prefixlen      => $max_prefixlen,
        default_candidates => \@default_candidates,
    );
}

sub enabled_set {
    return map { $_ => 1 }
        grep   { $_ ne q{} }
        split /,/,
        shift;
}

#
# Code shared among scripts that work from libcrypt.map.in
#

use Class::Struct VersionedSymbol => [
    name        => '$',
    included    => '$',
    compat_only => '$',
    versions    => '*@',
];

use Class::Struct SymbolVersionMap => [
    symbols    => '*@',
    versions   => '*@',
    basemap    => '$',
    max_symlen => '$',
];

# Process command-line arguments to a program that works from a
# .map.in file.  These are the name of the .map.in file plus var=value
# settings for SYMVER_MIN, SYMVER_FLOOR, and COMPAT_ABI, in any order.
sub parse_symver_args {
    my (@args) = @_;
    my $usage_error = sub {
        print {*STDERR}
            "${FindBin::Script}: usage: ",
            'SYMVER_MIN=value SYMVER_FLOOR=value ',
            'COMPAT_ABI=value libcrypt.map.in',
            "\n";
        exit 1;
    };
    $usage_error->() if scalar(@args) != 4;

    my $map_in;
    my $SYMVER_MIN;
    my $SYMVER_FLOOR;
    my $COMPAT_ABI;
    local $_;
    for (@args) {
        if (/^SYMVER_MIN=(.+)$/) {
            $usage_error->() if defined $SYMVER_MIN;
            $SYMVER_MIN = $1;
        }
        elsif (/^SYMVER_FLOOR=(.+)$/) {
            $usage_error->() if defined $SYMVER_FLOOR;
            $SYMVER_FLOOR = $1;
        }
        elsif (/^COMPAT_ABI=(.+)$/) {
            $usage_error->() if defined $COMPAT_ABI;
            $COMPAT_ABI = $1;
        }
        else {
            $usage_error->() if defined $map_in;
            $map_in = $_;
        }
    }
    return $map_in, $SYMVER_MIN, $SYMVER_FLOOR, $COMPAT_ABI;
}

# Read a .map.in file and compute the set of symbol versions to be
# included in this build of the library.
#
# All compat symbol versions that do not match COMPAT_ABI are ignored.
# All symbol versions lower than SYMVER_MIN are discarded from the output.
# All symbol versions lower than SYMVER_FLOOR are replaced with SYMVER_FLOOR.
# SYMVER_FLOOR must be greater than or equal to SYMVER_MIN.
#
# The ordering of symbol versions is entirely controlled by the %chain
# directive, which must therefore list both all of the versions
# actually used for symbols, and all of the versions that might be
# used as SYMVER_MIN or SYMVER_FLOOR.
sub parse_version_map_in {    ## no critic (Subroutines::RequireArgUnpacking)
    my ($map_in, $SYMVER_MIN, $SYMVER_FLOOR, $COMPAT_ABI) =
        parse_symver_args(@_);

    my %symbols;
    my %vorder;
    my $vmax = 0;
    my $error;
    my $max_symlen = 0;
    open my $fh, '<', $map_in
        or die "$map_in: $!\n";

    local $_;
    while (<$fh>) {
        next if /^#/;
        chomp;
        s/\s+$//;
        next if $_ eq q{};

        my @vers = split;
        my $sym  = shift @vers;
        if ($sym eq '%chain') {
            for my $v (@vers) {
                if (exists $vorder{$v}) {
                    print {*STDERR}
                        "$map_in:$.: error: '$v' used twice in %chain\n";
                    $error = 1;
                    next;
                }
                $vorder{$v} = $vmax;
                $vmax++;
            }
            next;
        }
        if (exists $symbols{$sym}) {
            print {*STDERR}
                "$map_in:$.: error: more than one entry for '$sym'\n";
            $error = 1;
            next;
        }
        if ($max_symlen < length $sym) {
            $max_symlen = length $sym;
        }

        # Dash in the second field means there is no default version
        # for this symbol.
        my $compat_only = 0;
        if ($vers[0] eq '-') {
            $compat_only = 1;
            shift @vers;
        }

        my @enabled_vers;
        for my $v (@vers) {
            # Each $v is a symbol version name followed by zero
            # or more compatibility tags, separated by colons.
            # If there are no tags, the symbol version is available
            # unconditionally; if there are any tags, the symbol
            # version is available if COMPAT_ABI is equal to 'yes'
            # or equal to one of the tags.
            my @tags = split /:/, $v;
            $v = shift @tags;
            my $enabled = 1;
            if (@tags && $COMPAT_ABI ne 'yes') {
                $enabled = 0;
                for my $t (@tags) {
                    if ($t eq $COMPAT_ABI) {
                        $enabled = 1;
                        last;
                    }
                }
            }
            push @enabled_vers, $v if $enabled;
        }
        $symbols{$sym} = VersionedSymbol->new(
            name        => $sym,
            included    => 1,
            compat_only => $compat_only,
            versions    => \@enabled_vers,
        );
    }

    my $symver_min_idx;
    my $symver_floor_idx;
    if (!%vorder) {
        print {*STDERR} "$map_in: error: missing %chain directive\n";
        $error = 1;
    } else {
        $symver_min_idx   = $vorder{$SYMVER_MIN}   // -2;
        $symver_floor_idx = $vorder{$SYMVER_FLOOR} // -1;
        if ($symver_min_idx < 0) {
            print {*STDERR}
                "$map_in: error: SYMVER_MIN ($SYMVER_MIN) ",
                "not found in %chain directives\n";
            $error = 1;
        }
        if ($symver_floor_idx < 0) {
            print {*STDERR}
                "$map_in: error: SYMVER_FLOOR ($SYMVER_FLOOR) ",
                "not found in %chain directives\n";
            $error = 1;
        }
        if ($symver_floor_idx < $symver_min_idx) {
            print {*STDERR}
                "$map_in: error: SYMVER_FLOOR ($SYMVER_FLOOR) ",
                "is lower than SYMVER_MIN ($SYMVER_MIN)\n";
            $error = 1;
        }
    }
    die "errors processing '$map_in'\n" if $error;

    # For each symbol, remove all of its versions below SYMVER_MIN,
    # and replace all of its versions below SYMVER_FLOOR with a single
    # instance of SYMVER_FLOOR.  If none are left, mark the symbol as
    # not included.  Otherwise, sort its 'versions' array in
    # _descending_ order of symbol version.  As we do this, keep track
    # of all the symbol versions that are actually used.
    my %used_versions;
    for my $sym (values %symbols) {
        my %pruned_versions;
        for my $v (@{$sym->versions}) {
            if (!exists $vorder{$v}) {
                print {*STDERR}
                    "$map_in: error: version '$v' for symbol '",
                    $sym->name, "' not found in %chain\n";
                $error = 1;
                next;
            }
            if ($vorder{$v} < $symver_min_idx) {
                next;
            } elsif ($vorder{$v} < $symver_floor_idx) {
                $pruned_versions{$SYMVER_FLOOR} = 1;
                $used_versions{$SYMVER_FLOOR}   = 1;
            } else {
                $pruned_versions{$v} = 1;
                $used_versions{$v}   = 1;
            }
        }
        if (%pruned_versions) {
            @{$sym->versions} =
                sort { -($vorder{$a} <=> $vorder{$b}) }
                keys %pruned_versions;
        } else {
            $sym->included(0);
            @{$sym->versions} = ();
        }
    }

    # Sort the set of used symbol versions in _ascending_ order.
    my @vchain = sort { $vorder{$a} <=> $vorder{$b} } keys %used_versions;

    my (undef, undef, $basemap) = splitpath($map_in);
    return SymbolVersionMap->new(
        symbols    => [sort { $a->name cmp $b->name } values %symbols],
        versions   => \@vchain,
        basemap    => $basemap,
        max_symlen => $max_symlen,
    );
}

1;

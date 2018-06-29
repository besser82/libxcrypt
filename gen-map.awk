# Generate a version map file from a .map.in file.
#
# Written by Zack Weinberg <zackw at panix.com> in 2017.
# To the extent possible under law, Zack Weinberg has waived all
# copyright and related or neighboring rights to this work.
#
# See https://creativecommons.org/publicdomain/zero/1.0/ for further
# details.

# The .map.in file is the first input file, and we expect the Makefile
# to have set the variables SYMVER_MIN, SYMVER_FLOOR, and COMPAT_ABI.
# All compat symbol versions that do not match COMPAT_ABI are ignored.
# All symbol versions lower than SYMVER_MIN are discarded from the output.
# All symbol versions lower than SYMVER_FLOOR are replaced with SYMVER_FLOOR.
# SYMVER_FLOOR must be greater than or equal to SYMVER_MIN.
#
# The ordering of symbol versions is entirely controlled by the %chain
# directive, which must therefore list both all of the versions
# actually used for symbols, and all of the versions that might be
# used as SYMVER_MIN or SYMVER_FLOOR.
#
# Note: if you change the format of .map.in files you probably need to
# update gen-vers.awk too.

BEGIN {
    split("", SYMBOLS) # ensure SYMBOLS is an array
    split("", VCHAIN)  # ditto VCHAIN
    NVCHAIN = 0

    # This arranges for sorted output if gawk is in use, and is
    # harmless otherwise.
    PROCINFO["sorted_in"] = "@ind_str_asc"
}

NF == 0   { next } # blank line, discard
$1 == "#" { next } # comment, discard
$1 == "%chain" {
    for (i = 2; i <= NF; i++) {
        VCHAIN[++NVCHAIN] = $i
    }
    next
}

{
    for (i = 2; i <= NF; i++) {
        sym=$i
        if (sym != "-") {
            n=split(sym, a, ":")
            if (n > 1) {
                sym="-"
                for (j = 2; j <= n; j++) {
                    if (COMPAT_ABI == "yes" || COMPAT_ABI == a[j]) {
                        sym=a[1]
                    }
                }
            }
        }
        if (sym != "-") {
            if (sym in SYMBOLS) {
                SYMBOLS[sym] = SYMBOLS[sym] SUBSEP $1
            } else {
                SYMBOLS[sym] = $1
            }
        }
    }
}

END {
    if (NVCHAIN == 0) {
        print ARGV[1] ": error: missing %chain directive" > "/dev/stderr"
        close("/dev/stderr")
        exit 1
    }
    symver_min_idx = 0
    symver_floor_idx = 0
    for (i = 1; i <= NVCHAIN; i++) {
        if (VCHAIN[i] == SYMVER_MIN) {
            symver_min_idx = i
        }
        if (VCHAIN[i] == SYMVER_FLOOR) {
            symver_floor_idx = i
        }
    }
    if (symver_min_idx == 0) {
        print ARGV[1] ": error: SYMVER_MIN (" SYMVER_MIN ") " \
            "not found in %chain directives" > "/dev/stderr"
        close("/dev/stderr")
        exit 1
    }
    if (symver_floor_idx == 0) {
        print ARGV[1] ": error: SYMVER_FLOOR (" SYMVER_FLOOR ") " \
            "not found in %chain directives" > "/dev/stderr"
        close("/dev/stderr")
        exit 1
    }
    if (symver_floor_idx < symver_min_idx) {
        print ARGV[1] ": error: SYMVER_FLOOR (" SYMVER_FLOOR ") " \
            "is lower than SYMVER_MIN (" SYMVER_MIN ")" > "/dev/stderr"
        close("/dev/stderr")
        exit 1
    }

    # Construct a pruned set of symbols and versions, including only
    # versions with symbols, discarding all symbols associated with
    # versions below SYMVER_MIN, raising symbols below SYMVER_FLOOR to
    # SYMVER_FLOOR, and removing duplicates.
    for (i = symver_min_idx; i <= NVCHAIN; i++) {
        v = VCHAIN[i]
        if (v in SYMBOLS) {
            nsyms = split(SYMBOLS[v], syms, SUBSEP)
            j = i;
            if (j < symver_floor_idx)
                j = symver_floor_idx;
            vr = VCHAIN[j]
            for (s = 1; s <= nsyms; s++) {
                if (syms[s]) {
                    symset[vr, syms[s]] = 1
                    allsyms[syms[s]] = 1
                }
            }
        }
    }

    vp = ""
    for (i = symver_floor_idx; i <= NVCHAIN; i++) {
        v = VCHAIN[i]
        split("", osyms)
        j = 0
        for (sym in allsyms) {
            if ((v, sym) in symset) {
                osyms[++j] = sym
            }
        }
        if (j > 0) {
            printf("%s {\n  global:\n", v);
            for (s = 1; s <= j; s++) {
                printf("    %s;\n", osyms[s]);
            }
            if (vp == "") {
                vp = v
                printf("  local:\n    *;\n};\n");
            } else {
                printf("} %s;\n", vp);
            }
        }
    }
}

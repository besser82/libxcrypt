# Expand a list of selected hashes to a list of enabled hashes, using
# the information in hashes.lst.
#
#   Copyright 2018 Zack Weinberg
#
#   This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public License
#   as published by the Free Software Foundation; either version 2.1 of
#   the License, or (at your option) any later version.
#
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, see
#   <https://www.gnu.org/licenses/>.

BEGIN {
    enable_all      = 0
    enable_strong   = 0
    enable_glibc    = 0
    enable_freebsd  = 0
    enable_netbsd   = 0
    enable_openbsd  = 0
    enable_osx      = 0
    enable_solaris  = 0
    error = 0
    split(SELECTED_HASHES, selected_hashes_list, ",")
    for (i in selected_hashes_list) {
        h = selected_hashes_list[i]
        if (h == "all") {
            enable_all = 1
        } else if (h == "strong") {
            enable_strong = 1
        } else if (h == "glibc") {
            enable_glibc = 1
        } else if (h == "freebsd") {
            enable_freebsd = 1
        } else if (h == "netbsd") {
            enable_netbsd = 1
        } else if (h == "openbsd") {
            enable_openbsd = 1
        } else if (h == "osx") {
            enable_osx = 1
        } else if (h == "solaris") {
            enable_solaris = 1
        } else {
            enable_some = 1
            selected_hashes[h] = 1
        }
    }
    if (enable_all && (enable_strong  || enable_glibc  || enable_some    || \
                       enable_freebsd || enable_netbsd || enable_openbsd || \
                       enable_osx     || enable_solaris)) {
        error = 1
        exit 1
    }
}

/^#/ {
    next
}

{
    if (enable_all || $1 in selected_hashes) {
        enabled_hashes[$1] = 1
    } else {
        enabled_hashes[$1] = 0

        split($5, flags, ",")
        for (i in flags) {
            flag = flags[i]
            if (flag == "STRONG" && enable_strong) {
                enabled_hashes[$1] = 1
            } else if (flag == "GLIBC" && enable_glibc) {
                enabled_hashes[$1] = 1
            } else if (flag == "FREEBSD" && enable_freebsd) {
                enabled_hashes[$1] = 1
            } else if (flag == "NETBSD" && enable_netbsd) {
                enabled_hashes[$1] = 1
            } else if (flag == "OPENBSD" && enable_openbsd) {
                enabled_hashes[$1] = 1
            } else if (flag == "OSX" && enable_osx) {
                enabled_hashes[$1] = 1
            } else if (flag == "SOLARIS" && enable_solaris) {
                enabled_hashes[$1] = 1
            }
        }
    }
}


END {
    if (error) {
        exit 1
    }

    # Check for individual selected hashes that didn't appear in
    # hashes.lst.
    for (h in selected_hashes) {
        if (!(h in enabled_hashes)) {
            exit 1
        }
    }

    enabled_hash_list = ","
    for (i in enabled_hashes) {
        if (enabled_hashes[i]) {
            enabled_hash_list = enabled_hash_list i ","
        }
    }
    print enabled_hash_list
}

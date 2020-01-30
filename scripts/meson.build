#   Copyright 2017, 2018, 2019 Zack Weinberg
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

# Define file objects for all the scripts, to be used in other
# directories.

foreach script : [
  'check-ld-vscript',
  'check-ld-wrap',
  'compute-symver-floor',
  'compute-symbol-renames',
  'expand-selected-hashes',
  'gen-crypt-h',
  'gen-crypt-hashes-h',
  'gen-crypt-symbol-vers-h',
  'gen-libcrypt-map',
  'install-symlink',
  'test-symbols-compat',
  'test-symbols-static',
]
  set_variable('S_' + script.underscorify(), files(script)[0])
endforeach

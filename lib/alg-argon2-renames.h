/* Copyright (c) 2025 Björn Esser <besser82 at fedoraproject.org>
 * All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * --
 * alg-argon2-renames.h
 * Function renaming for Argon2.
 */

#ifndef ALG_ARGON2_RENAMES_H
#define ALG_ARGON2_RENAMES_H

#define FLAG_clear_internal_memory   argon2_FLAG_clear_internal_memory
#define allocate_memory              argon2_allocate_memory
#define b64len                       argon2_b64len
#define clear_internal_memory        argon2_clear_internal_memory
#define copy_block                   argon2_copy_block
#define decode_string                argon2_decode_string
#define encode_string                argon2_encode_string
#define fill_first_blocks            argon2_fill_first_blocks
#define fill_memory_blocks           argon2_fill_memory_blocks
#define fill_segment                 argon2_fill_segment
#define finalize                     argon2_finalize
#define free_memory                  argon2_free_memory
#define index_alpha                  argon2_index_alpha
#define init_block_value             argon2_init_block_value
#define initial_hash                 argon2_initial_hash
#define initialize                   argon2_initialize
#define numlen                       argon2_numlen
#define validate_inputs              argon2_validate_inputs
#define xor_block                    argon2_xor_block

#endif /* alg-argon2-renames.h */

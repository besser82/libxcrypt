/* Copyright (C) 2018 vt@altlinux.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "crypt-port.h"
#include "crypt-private.h"
#include "byteorder.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "yescrypt.h"

#if INCLUDE_yescrypt

/*
 * As OUTPUT is initialized with a failure token before gensalt_yescrypt_rn
 * is called, in case of an error we could just set an appropriate errno
 * and return.
 * Since O_SIZE is guaranteed to be greater than 2, we may fill OUTPUT
 * with a short failure token when need.
 */
void
gensalt_yescrypt_rn(unsigned long count,
                    const uint8_t *rbytes, size_t nrbytes,
                    uint8_t *output, size_t o_size)
{
	/* Use one of recommended parameter sets as the 'low default'. */
	yescrypt_params_t params = { .flags = YESCRYPT_DEFAULTS,
		.N = 4096, .r = 32, .p = 1 };

	if (count) {
		/*
		 * `1 << (count - 1)` is MiB usage in range of 1MiB..1GiB,
		 * thus, count is in range of 1..11
		 */
		if (count <= 2) {
			params.r = 8; /* N in 1KiB */
			params.N = 512ULL << count;
		} else if (count <= 11) {
			params.r = 32; /* N in 4KiB */
			params.N = 128ULL << count;
		} else {
			errno = EINVAL;
			return;
		}
	}

	if (!yescrypt_encode_params_r(&params, rbytes, nrbytes, output, o_size)) {
		/*
		 * As the output could have already been written,
		 * overwrite it with a short failure token.
		 */
		output[0] = '*';
		output[1] = '\0';
		errno = ERANGE;
		return;
	}
}

void
crypt_yescrypt_rn(const char *phrase, size_t ARG_UNUSED (phr_size),
                  const char *setting, size_t ARG_UNUSED (set_size),
                  uint8_t *output, size_t o_size,
                  ARG_UNUSED(void *scratch), ARG_UNUSED(size_t s_size))
{
	yescrypt_local_t local;
	uint8_t *retval;

	if (o_size < 3) {
		errno = ERANGE;
		return;
	}
	if (yescrypt_init_local(&local)) {
		errno = ENOMEM;
		return;
	}
	retval = yescrypt_r(NULL, &local,
	    (const uint8_t *)phrase, strlen(phrase),
	    (const uint8_t *)setting, NULL,
	    output, o_size);
	if (yescrypt_free_local(&local) ||
	    !retval) {
		/*
		 * As the output could have already been written,
		 * overwrite it with a failure token.
		 */
		output[0] = '*';
		output[1] = '0';
		output[2] = '\0';
		errno = EINVAL;
	}
}

#endif /* INCLUDE_yescrypt */

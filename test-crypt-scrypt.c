/* Copyright (C) 2018 vt@altlinux.org
 * Copyright (C) 2018 Björn Esser <besser82@fedoraproject.org>
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
#include "crypt-base.h"

#include <stdio.h>

#if INCLUDE_scrypt

static int
test(const char *p, const char *s, const char *m)
{
  struct crypt_data cd;
  crypt_r(p, s, &cd);
  if (strcmp(m, cd.output))
    {
      fprintf(stderr, "ERROR: %s %s -> %s\n\t(expected %s)\n",
              p, s, cd.output, m);
      return 1;
    }
  else
    {
      fprintf(stderr, "   ok: %s %s -> %s\n", p, s, cd.output);
      return 0;
    }
}

int
main (void)
{
  int result = test("pleaseletmein", "$7$C6..../....SodiumChloride",
                    "$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D");
  result |= test("pleaseletmein", "$7$06..../....SodiumChloride",
                 "$7$06..../....SodiumChloride$ENlyo6fGw4PCcDBOFepfSZjFUnVatHzCcW55.ZGz3B0");
  result |= test("pleaseletmein", "$7$06..../....SodiumChloride$",
                 "$7$06..../....SodiumChloride$ENlyo6fGw4PCcDBOFepfSZjFUnVatHzCcW55.ZGz3B0");

  result |= test("test", "$7$", "*0");
  result |= test("test", "*0", "*1");
  result |= test("test", "*1", "*0");

  return result;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif /* INCLUDE_scrypt */

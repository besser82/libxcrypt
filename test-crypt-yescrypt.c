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
#include "crypt-base.h"

#include <stdio.h>

#if INCLUDE_yescrypt

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
  int result = test("pleaseletmein", "$y$jD5.7$LdJMENpBABJJ3hIHjB1Bi.",
                    "$y$jD5.7$LdJMENpBABJJ3hIHjB1Bi.$HboGM6qPrsK.StKYGt6KErmUYtioHreJd98oIugoNB6");
  result |= test("", "$y$jD5.7$",  "$y$jD5.7$$JD8dsR.nt1ty0ltQ2HHwauaDRoOUIEaA5i.vpj2nyL.");
  result |= test("", "$y$jD5.7$$", "$y$jD5.7$$JD8dsR.nt1ty0ltQ2HHwauaDRoOUIEaA5i.vpj2nyL.");

  result |= test("test", "$y$", "*0");
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

#endif /* INCLUDE_yescrypt */

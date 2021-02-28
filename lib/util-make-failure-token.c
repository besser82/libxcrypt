/* Copyright (C) 2018-2019 Björn Esser <besser82@fedoraproject.org>
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

/* Fill the output buffer with a failure token.  */
void
make_failure_token (const char *setting, char *output, int size)
{
  if (size >= 3)
    {
      output[0] = '*';
      output[1] = '0';
      output[2] = '\0';

      if (setting && setting[0] == '*' && setting[1] == '0')
        output[1] = '1';
    }

  /* If there's not enough space for the full failure token, do the
     best we can.  */
  else if (size == 2)
    {
      output[0] = '*';
      output[1] = '\0';
    }
  else if (size == 1)
    {
      output[0] = '\0';
    }
}

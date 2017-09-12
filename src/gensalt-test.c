#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/times.h>

#include "xcrypt.h"

#ifndef RANDOM_DEVICE
#define RANDOM_DEVICE "/dev/urandom"
#endif

static int
read_loop (int fd, char *buffer, int count)
{
  int offset, block;

  offset = 0;
  while (count > 0)
    {
      block = read(fd, &buffer[offset], count);

      if (block < 0)
        {
          if (errno == EINTR)
            continue;
          return block;
        }
      if (!block)
        return offset;

      offset += block;
      count -= block;
    }

  return offset;
}

static char *
make_crypt_salt (const char *crypt_prefix, int crypt_rounds)
{
#define CRYPT_GENSALT_OUTPUT_SIZE (7 + 22 + 1)
  int fd;
  char entropy[16];
  char *retval;
  char output[CRYPT_GENSALT_OUTPUT_SIZE];

  fd = open (RANDOM_DEVICE, O_RDONLY);
  if (fd < 0)
    {
      fprintf (stderr, "Can't open %s for reading: %s\n",
	       RANDOM_DEVICE, strerror (errno));
      return NULL;
    }

  if (read_loop (fd, entropy, sizeof(entropy)) != sizeof(entropy))
    {
      close (fd);
      fprintf (stderr, "Unable to obtain entropy from %s\n",
	       RANDOM_DEVICE);
      return NULL;
    }

  close (fd);

  retval = crypt_gensalt_r (crypt_prefix, crypt_rounds, entropy,
                            sizeof (entropy), output, sizeof(output));

  memset (entropy, 0, sizeof (entropy));

  if (!retval)
    {
      fprintf (stderr,
	       "Unable to generate a salt, check your crypt settings.\n");
      return NULL;
    }

  return strdup (retval);
}

static char *salt_input[] =
  { "", "$1$", "$2a$" , "$5$", "$6$" };

int
main(void)
{
  int i;
  int status = 0;

  for (i = 0; i < (int) (sizeof (salt_input) / sizeof (salt_input[0])); i++)
    {
      char *salt = make_crypt_salt (salt_input[i], 0);

      int ok = (salt_input[i][0] == '\0' ||
                strncmp (salt_input[i], salt, strlen (salt_input[i])) == 0);

      fprintf(stderr, "%s: input='%s', output='%s'\n",
              ok ? "ok" : "ERROR",
              salt_input[i], salt);

      if (!ok)
        status = 1;
    }

  return status;
}

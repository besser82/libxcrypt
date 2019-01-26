/*
 * SHA-1 in C
 * By Steve Reid <sreid@sea-to-sky.net>
 * 100% Public Domain
*/

#include "crypt-port.h"
#include "alg-sha1.h"

#include <stdio.h>

#if INCLUDE_sha1crypt

/* Test Vectors (from FIPS PUB 180-1) */
const char *test_data[3] =
{
  "abc",
  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  "A million repetitions of 'a'"
};

const char *test_results[3] =
{
  "a9993e364706816aba3e25717850c26c9cd0d89d",
  "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
  "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
};


static void
bin_to_hex (uint8_t *digest, char *output)
{
  for (uint8_t i = 0; i < 20; ++i)
    {
      sprintf (output, "%02x", *digest);
      ++digest;
      output += 2;
    }
}


int
main (void)
{
  int k;
  struct sha1_ctx ctx;
  uint8_t digest[20];
  char output[80];
  uint8_t retval = 0;

  for (k = 0; k < 2; k++)
    {
      sha1_init_ctx (&ctx);
      sha1_process_bytes ((const uint8_t*)test_data[k], &ctx, strlen(test_data[k]));
      sha1_finish_ctx (&ctx, digest);
      bin_to_hex(digest, output);

      if (strcmp(output, test_results[k]))
        {
          fprintf(stdout, "FAIL\n");
          fprintf(stderr,"* hash of \"%s\" incorrect:\n", test_data[k]);
          fprintf(stderr,"\t%s returned\n", output);
          fprintf(stderr,"\t%s is correct\n", test_results[k]);
          retval = 1;
        }
    }
  /* million 'a' vector we feed separately */
  sha1_init_ctx (&ctx);
  for (k = 0; k < 1000000; k++)
    sha1_process_bytes ((const uint8_t*)"a", &ctx, 1);
  sha1_finish_ctx (&ctx, digest);
  bin_to_hex(digest, output);
  if (strcmp(output, test_results[2]))
    {
      fprintf(stdout, "FAIL\n");
      fprintf(stderr,"* hash of \"%s\" incorrect:\n", test_data[2]);
      fprintf(stderr,"\t%s returned\n", output);
      fprintf(stderr,"\t%s is correct\n", test_results[2]);
      retval = 1;
    }

  /* The same test as above, but with 1000 blocks of 1000 bytes.  */
  char buf[1000];
  memset (buf, 'a', sizeof (buf));
  sha1_init_ctx (&ctx);
  for (k = 0; k < 1000; ++k)
    sha1_process_bytes ((const uint8_t*)buf, &ctx, sizeof (buf));
  sha1_finish_ctx (&ctx, digest);
  bin_to_hex(digest, output);
  if (strcmp(output, test_results[2]))
    {
      fprintf(stdout, "FAIL\n");
      fprintf(stderr,"* hash of \"%s\" incorrect:\n", test_data[2]);
      fprintf(stderr,"\t%s returned\n", output);
      fprintf(stderr,"\t%s is correct\n", test_results[2]);
      retval = 1;
    }

  /* success */
  return retval;
}

#else

int
main (void)
{
  return 77; /* UNSUPPORTED */
}

#endif

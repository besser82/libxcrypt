/* Test the functions defined in byteorder.h.
 *
 * Written by Zack Weinberg <zackw at panix.com> in 2017.
 *
 * No copyright is claimed, and the software is hereby placed in the public
 * domain.  In case this attempt to disclaim copyright and place the software
 * in the public domain is deemed null and void, then the software is
 * Copyright (c) 2017 Zack Weinberg and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include "crypt-port.h"
#include "byteorder.h"

#include <inttypes.h>
#include <stdio.h>

struct test_32
{
  uint32_t val;
  unsigned char bytes[4];
};

struct test_64
{
  uint64_t val;
  unsigned char bytes[8];
};

#define Z(x) ((unsigned int)(unsigned char)(x)) /* zero extend char */

static int
test_le32 (void)
{
  static const struct test_32 cases[] =
  {
    { 0x00000000, "\x00\x00\x00\x00" },
    { 0xFF000000, "\x00\x00\x00\xFF" },
    { 0x00FF0000, "\x00\x00\xFF\x00" },
    { 0x0000FF00, "\x00\xFF\x00\x00" },
    { 0x000000FF, "\xFF\x00\x00\x00" },
    { 0x01234567, "\x67\x45\x23\x01" },
  };
  size_t n_cases = ARRAY_SIZE (cases);
  size_t i;
  uint32_t v;
  unsigned char x[4];
  int status = 0;

  for (i = 0; i < n_cases; i++)
    {
      v = le32_to_cpu (cases[i].bytes);
      if (v != cases[i].val)
        {
          printf ("FAIL: le32_to_cpu: %02x %02x %02x %02x -> "
                  "%08"PRIx32" != %08"PRIx32"\n",
                  Z(cases[i].bytes[0]), Z(cases[i].bytes[1]),
                  Z(cases[i].bytes[2]), Z(cases[i].bytes[3]),
                  v, cases[i].val);
          status = 1;
        }

      cpu_to_le32 (x, cases[i].val);
      if (memcmp (x, cases[i].bytes, 4))
        {
          printf ("FAIL: cpu_to_le32: %08"PRIx32" -> "
                  "%02x %02x %02x %02x != %02x %02x %02x %02x\n",
                  cases[i].val,
                  Z(x[0]), Z(x[1]), Z(x[2]), Z(x[3]),
                  Z(cases[i].bytes[0]), Z(cases[i].bytes[1]),
                  Z(cases[i].bytes[2]), Z(cases[i].bytes[3]));
          status = 1;
        }
    }

  return status;
}

static int
test_be32 (void)
{
  static const struct test_32 cases[] =
  {
    { 0x00000000, "\x00\x00\x00\x00" },
    { 0xFF000000, "\xFF\x00\x00\x00" },
    { 0x00FF0000, "\x00\xFF\x00\x00" },
    { 0x0000FF00, "\x00\x00\xFF\x00" },
    { 0x000000FF, "\x00\x00\x00\xFF" },
    { 0x01234567, "\x01\x23\x45\x67" },
  };
  size_t n_cases = ARRAY_SIZE (cases);
  size_t i;
  uint32_t v;
  unsigned char x[4];
  int status = 0;

  for (i = 0; i < n_cases; i++)
    {
      v = be32_to_cpu (cases[i].bytes);
      if (v != cases[i].val)
        {
          printf ("FAIL: be32_to_cpu: %02x %02x %02x %02x -> "
                  "%08"PRIx32" != %08"PRIx32"\n",
                  Z(cases[i].bytes[0]), Z(cases[i].bytes[1]),
                  Z(cases[i].bytes[2]), Z(cases[i].bytes[3]),
                  v, cases[i].val);
          status = 1;
        }

      cpu_to_be32 (x, cases[i].val);
      if (memcmp (x, cases[i].bytes, 4))
        {
          printf ("FAIL: cpu_to_be32: %08"PRIx32" -> "
                  "%02x %02x %02x %02x != %02x %02x %02x %02x\n",
                  cases[i].val,
                  Z(x[0]), Z(x[1]), Z(x[2]), Z(x[3]),
                  Z(cases[i].bytes[0]), Z(cases[i].bytes[1]),
                  Z(cases[i].bytes[2]), Z(cases[i].bytes[3]));
          status = 1;
        }
    }

  return status;
}

static int
test_le64 (void)
{
  static const struct test_64 cases[] =
  {
    { 0x0000000000000000ull, "\x00\x00\x00\x00\x00\x00\x00\x00" },
    { 0x00000000000000FFull, "\xFF\x00\x00\x00\x00\x00\x00\x00" },
    { 0x000000000000FF00ull, "\x00\xFF\x00\x00\x00\x00\x00\x00" },
    { 0x0000000000FF0000ull, "\x00\x00\xFF\x00\x00\x00\x00\x00" },
    { 0x00000000FF000000ull, "\x00\x00\x00\xFF\x00\x00\x00\x00" },
    { 0x000000FF00000000ull, "\x00\x00\x00\x00\xFF\x00\x00\x00" },
    { 0x0000FF0000000000ull, "\x00\x00\x00\x00\x00\xFF\x00\x00" },
    { 0x00FF000000000000ull, "\x00\x00\x00\x00\x00\x00\xFF\x00" },
    { 0xFF00000000000000ull, "\x00\x00\x00\x00\x00\x00\x00\xFF" },
    { 0x0123456789ABCDEFull, "\xEF\xCD\xAB\x89\x67\x45\x23\x01" },
  };
  size_t n_cases = ARRAY_SIZE (cases);
  size_t i;
  uint64_t v;
  unsigned char x[8];
  int status = 0;

  for (i = 0; i < n_cases; i++)
    {
      v = le64_to_cpu (cases[i].bytes);
      if (v != cases[i].val)
        {
          printf ("FAIL: le64_to_cpu: %02x%02x %02x%02x %02x%02x %02x%02x "
                  "-> %016"PRIx64" != %016"PRIx64"\n",
                  Z(cases[i].bytes[0]), Z(cases[i].bytes[1]),
                  Z(cases[i].bytes[2]), Z(cases[i].bytes[3]),
                  Z(cases[i].bytes[4]), Z(cases[i].bytes[5]),
                  Z(cases[i].bytes[6]), Z(cases[i].bytes[7]),
                  v, cases[i].val);
          status = 1;
        }

      cpu_to_le64 (x, cases[i].val);
      if (memcmp (x, cases[i].bytes, 8))
        {
          printf ("FAIL: cpu_to_le64: %016"PRIx64" -> "
                  "%02x%02x %02x%02x %02x%02x %02x%02x != "
                  "%02x%02x %02x%02x %02x%02x %02x%02x\n",
                  cases[i].val,
                  Z(x[0]), Z(x[1]), Z(x[2]), Z(x[3]),
                  Z(x[4]), Z(x[5]), Z(x[6]), Z(x[7]),
                  Z(cases[i].bytes[0]), Z(cases[i].bytes[1]),
                  Z(cases[i].bytes[2]), Z(cases[i].bytes[3]),
                  Z(cases[i].bytes[4]), Z(cases[i].bytes[5]),
                  Z(cases[i].bytes[6]), Z(cases[i].bytes[7]));
          status = 1;
        }
    }

  return status;
}

static int
test_be64 (void)
{
  static const struct test_64 cases[] =
  {
    { 0x0000000000000000ull, "\x00\x00\x00\x00\x00\x00\x00\x00" },
    { 0x00000000000000FFull, "\x00\x00\x00\x00\x00\x00\x00\xFF" },
    { 0x000000000000FF00ull, "\x00\x00\x00\x00\x00\x00\xFF\x00" },
    { 0x0000000000FF0000ull, "\x00\x00\x00\x00\x00\xFF\x00\x00" },
    { 0x00000000FF000000ull, "\x00\x00\x00\x00\xFF\x00\x00\x00" },
    { 0x000000FF00000000ull, "\x00\x00\x00\xFF\x00\x00\x00\x00" },
    { 0x0000FF0000000000ull, "\x00\x00\xFF\x00\x00\x00\x00\x00" },
    { 0x00FF000000000000ull, "\x00\xFF\x00\x00\x00\x00\x00\x00" },
    { 0xFF00000000000000ull, "\xFF\x00\x00\x00\x00\x00\x00\x00" },
    { 0x0123456789ABCDEFull, "\x01\x23\x45\x67\x89\xAB\xCD\xEF" },
  };
  size_t n_cases = ARRAY_SIZE (cases);
  size_t i;
  uint64_t v;
  unsigned char x[8];
  int status = 0;

  for (i = 0; i < n_cases; i++)
    {
      v = be64_to_cpu (cases[i].bytes);
      if (v != cases[i].val)
        {
          printf ("FAIL: be64_to_cpu: %02x%02x %02x%02x %02x%02x %02x%02x "
                  "-> %016"PRIx64" != %016"PRIx64"\n",
                  Z(cases[i].bytes[0]), Z(cases[i].bytes[1]),
                  Z(cases[i].bytes[2]), Z(cases[i].bytes[3]),
                  Z(cases[i].bytes[4]), Z(cases[i].bytes[5]),
                  Z(cases[i].bytes[6]), Z(cases[i].bytes[7]),
                  v, cases[i].val);
          status = 1;
        }

      cpu_to_be64 (x, cases[i].val);
      if (memcmp (x, cases[i].bytes, 8))
        {
          printf ("FAIL: cpu_to_be64: %016"PRIx64" -> "
                  "%02x%02x %02x%02x %02x%02x %02x%02x != "
                  "%02x%02x %02x%02x %02x%02x %02x%02x\n",
                  cases[i].val,
                  Z(x[0]), Z(x[1]), Z(x[2]), Z(x[3]),
                  Z(x[4]), Z(x[5]), Z(x[6]), Z(x[7]),
                  Z(cases[i].bytes[0]), Z(cases[i].bytes[1]),
                  Z(cases[i].bytes[2]), Z(cases[i].bytes[3]),
                  Z(cases[i].bytes[4]), Z(cases[i].bytes[5]),
                  Z(cases[i].bytes[6]), Z(cases[i].bytes[7]));
          status = 1;
        }
    }

  return status;
}

int
main (void)
{
  int status = 0;
  status |= test_le32 ();
  status |= test_be32 ();
  status |= test_le64 ();
  status |= test_be64 ();
  return status;
}

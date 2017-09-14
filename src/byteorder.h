/* Functions to copy data between possibly-unaligned byte buffers
 * and machine integers, fixing the endianness.
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

#ifndef _BYTEORDER_H
#define _BYTEORDER_H 1

#include <stdint.h>

static inline uint32_t
le32_to_cpu (const char *buf)
{
  const unsigned char *u = (const unsigned char *)buf;
  return ((((uint32_t)u[0]) <<  0) |
          (((uint32_t)u[1]) <<  8) |
          (((uint32_t)u[2]) << 16) |
          (((uint32_t)u[3]) << 24) );
}

static inline uint32_t
be32_to_cpu (const char *buf)
{
  const unsigned char *u = (const unsigned char *)buf;
  return ((((uint32_t)u[0]) << 24) |
          (((uint32_t)u[1]) << 16) |
          (((uint32_t)u[2]) <<  8) |
          (((uint32_t)u[3]) <<  0) );
}

static inline uint64_t
le64_to_cpu (const char *buf)
{
  const unsigned char *u = (const unsigned char *)buf;
  return ((((uint64_t)u[0]) <<  0) |
          (((uint64_t)u[1]) <<  8) |
          (((uint64_t)u[2]) << 16) |
          (((uint64_t)u[3]) << 24) |
          (((uint64_t)u[4]) << 32) |
          (((uint64_t)u[5]) << 40) |
          (((uint64_t)u[6]) << 48) |
          (((uint64_t)u[7]) << 56) );
}

static inline uint64_t
be64_to_cpu (const char *buf)
{
  const unsigned char *u = (const unsigned char *)buf;
  return ((((uint64_t)u[0]) << 56) |
          (((uint64_t)u[1]) << 48) |
          (((uint64_t)u[2]) << 40) |
          (((uint64_t)u[3]) << 32) |
          (((uint64_t)u[4]) << 24) |
          (((uint64_t)u[5]) << 16) |
          (((uint64_t)u[6]) <<  8) |
          (((uint64_t)u[7]) <<  0) );
}

static inline void
cpu_to_le32 (char *buf, uint32_t n)
{
  buf[0] = (n & 0x000000FFu) >>  0;
  buf[1] = (n & 0x0000FF00u) >>  8;
  buf[2] = (n & 0x00FF0000u) >> 16;
  buf[3] = (n & 0xFF000000u) >> 24;
}

static inline void
cpu_to_be32 (char *buf, uint32_t n)
{
  buf[0] = (n & 0xFF000000u) >> 24;
  buf[1] = (n & 0x00FF0000u) >> 16;
  buf[2] = (n & 0x0000FF00u) >>  8;
  buf[3] = (n & 0x000000FFu) >>  0;
}

static inline void
cpu_to_le64 (char *buf, uint64_t n)
{
  buf[0] = (n & 0x00000000000000FFull) >>  0;
  buf[1] = (n & 0x000000000000FF00ull) >>  8;
  buf[2] = (n & 0x0000000000FF0000ull) >> 16;
  buf[3] = (n & 0x00000000FF000000ull) >> 24;
  buf[4] = (n & 0x000000FF00000000ull) >> 32;
  buf[5] = (n & 0x0000FF0000000000ull) >> 40;
  buf[6] = (n & 0x00FF000000000000ull) >> 48;
  buf[7] = (n & 0xFF00000000000000ull) >> 56;
}

static inline void
cpu_to_be64 (char *buf, uint64_t n)
{
  buf[0] = (n & 0xFF00000000000000ull) >> 56;
  buf[1] = (n & 0x00FF000000000000ull) >> 48;
  buf[2] = (n & 0x0000FF0000000000ull) >> 40;
  buf[3] = (n & 0x000000FF00000000ull) >> 32;
  buf[4] = (n & 0x00000000FF000000ull) >> 24;
  buf[5] = (n & 0x0000000000FF0000ull) >> 16;
  buf[6] = (n & 0x000000000000FF00ull) >>  8;
  buf[7] = (n & 0x00000000000000FFull) >>  0;
}

#endif

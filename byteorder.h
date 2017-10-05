/* Functions to copy data between possibly-unaligned byte buffers
   and machine integers, fixing the endianness.

   Written by Zack Weinberg <zackw at panix.com> in 2017.
   To the extent possible under law, Zack Weinberg has waived all
   copyright and related or neighboring rights to this work.

   See https://creativecommons.org/publicdomain/zero/1.0/ for further
   details.  */

#ifndef _CRYPT_BYTEORDER_H
#define _CRYPT_BYTEORDER_H 1

static inline uint32_t
le32_to_cpu (const unsigned char *buf)
{
  return ((((uint32_t)buf[0]) <<  0) |
          (((uint32_t)buf[1]) <<  8) |
          (((uint32_t)buf[2]) << 16) |
          (((uint32_t)buf[3]) << 24) );
}

static inline uint32_t
be32_to_cpu (const unsigned char *buf)
{
  return ((((uint32_t)buf[0]) << 24) |
          (((uint32_t)buf[1]) << 16) |
          (((uint32_t)buf[2]) <<  8) |
          (((uint32_t)buf[3]) <<  0) );
}

static inline uint64_t
le64_to_cpu (const unsigned char *buf)
{
  return ((((uint64_t)buf[0]) <<  0) |
          (((uint64_t)buf[1]) <<  8) |
          (((uint64_t)buf[2]) << 16) |
          (((uint64_t)buf[3]) << 24) |
          (((uint64_t)buf[4]) << 32) |
          (((uint64_t)buf[5]) << 40) |
          (((uint64_t)buf[6]) << 48) |
          (((uint64_t)buf[7]) << 56) );
}

static inline uint64_t
be64_to_cpu (const unsigned char *buf)
{
  return ((((uint64_t)buf[0]) << 56) |
          (((uint64_t)buf[1]) << 48) |
          (((uint64_t)buf[2]) << 40) |
          (((uint64_t)buf[3]) << 32) |
          (((uint64_t)buf[4]) << 24) |
          (((uint64_t)buf[5]) << 16) |
          (((uint64_t)buf[6]) <<  8) |
          (((uint64_t)buf[7]) <<  0) );
}

static inline void
cpu_to_le32 (unsigned char *buf, uint32_t n)
{
  buf[0] = (unsigned char)((n & 0x000000FFu) >>  0);
  buf[1] = (unsigned char)((n & 0x0000FF00u) >>  8);
  buf[2] = (unsigned char)((n & 0x00FF0000u) >> 16);
  buf[3] = (unsigned char)((n & 0xFF000000u) >> 24);
}

static inline void
cpu_to_be32 (unsigned char *buf, uint32_t n)
{
  buf[0] = (unsigned char)((n & 0xFF000000u) >> 24);
  buf[1] = (unsigned char)((n & 0x00FF0000u) >> 16);
  buf[2] = (unsigned char)((n & 0x0000FF00u) >>  8);
  buf[3] = (unsigned char)((n & 0x000000FFu) >>  0);
}

static inline void
cpu_to_le64 (unsigned char *buf, uint64_t n)
{
  buf[0] = (unsigned char)((n & 0x00000000000000FFull) >>  0);
  buf[1] = (unsigned char)((n & 0x000000000000FF00ull) >>  8);
  buf[2] = (unsigned char)((n & 0x0000000000FF0000ull) >> 16);
  buf[3] = (unsigned char)((n & 0x00000000FF000000ull) >> 24);
  buf[4] = (unsigned char)((n & 0x000000FF00000000ull) >> 32);
  buf[5] = (unsigned char)((n & 0x0000FF0000000000ull) >> 40);
  buf[6] = (unsigned char)((n & 0x00FF000000000000ull) >> 48);
  buf[7] = (unsigned char)((n & 0xFF00000000000000ull) >> 56);
}

static inline void
cpu_to_be64 (unsigned char *buf, uint64_t n)
{
  buf[0] = (unsigned char)((n & 0xFF00000000000000ull) >> 56);
  buf[1] = (unsigned char)((n & 0x00FF000000000000ull) >> 48);
  buf[2] = (unsigned char)((n & 0x0000FF0000000000ull) >> 40);
  buf[3] = (unsigned char)((n & 0x000000FF00000000ull) >> 32);
  buf[4] = (unsigned char)((n & 0x00000000FF000000ull) >> 24);
  buf[5] = (unsigned char)((n & 0x0000000000FF0000ull) >> 16);
  buf[6] = (unsigned char)((n & 0x000000000000FF00ull) >>  8);
  buf[7] = (unsigned char)((n & 0x00000000000000FFull) >>  0);
}

#endif /* byteorder.h */

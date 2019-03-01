/* Retrieval of cryptographically random bytes from the operating system.
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

#include <errno.h>
#include <stdlib.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* If we have O_CLOEXEC, we use it, but if we don't, we don't worry
   about it.  */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* There is no universally portable way to access a system CSPRNG.
   If the C library provides any of the following functions, we try them,
   in order of preference: arc4random_buf, getentropy, getrandom.
   If none of those are available or they don't work, we attempt to
   make direct system calls for getentropy and getrandom.  If *that*
   doesn't work, we try opening and reading /dev/urandom.

   This function returns true if the exact number of requested bytes
   was successfully read, false otherwise; if it returns false, errno
   has been set.  It may block.  It cannot be used to read more than
   256 bytes at a time (this is a limitation inherited from
   getentropy() and enforced regardless of the actual back-end in use).

   If we fall all the way back to /dev/urandom, we open and close it on
   each call.  */

bool
get_random_bytes(void *buf, size_t buflen)
{
  if (buflen == 0)
    return true;
  if (buflen > 256)
    {
      errno = EIO;
      return false;
    }
  /* To eliminate the possibility of one of the primitives below failing
     with EFAULT, force a crash now if the buffer is unwritable.  */
  XCRYPT_SECURE_MEMSET (buf, buflen);

#ifdef HAVE_ARC4RANDOM_BUF
  /* arc4random_buf, if it exists, can never fail.  */
  arc4random_buf (buf, buflen);
  return true;

#else /* no arc4random_buf */

#ifdef HAVE_GETENTROPY
  /* getentropy may exist but lack kernel support.  */
  static bool getentropy_doesnt_work;
  if (!getentropy_doesnt_work)
    {
      if (!getentropy (buf, buflen))
        return true;
      getentropy_doesnt_work = true;
    }
#endif

#ifdef HAVE_GETRANDOM
  /* Likewise getrandom.  */
  static bool getrandom_doesnt_work;
  if (!getrandom_doesnt_work)
    {
      if ((size_t)getrandom (buf, buflen, 0) == buflen)
        return true;
      getrandom_doesnt_work = true;
    }
#endif

  /* If we can make arbitrary syscalls, try getentropy and getrandom
     again that way.  */
#ifdef HAVE_SYSCALL
#ifdef SYS_getentropy
  static bool sys_getentropy_doesnt_work;
  if (!sys_getentropy_doesnt_work)
    {
      if (!syscall (SYS_getentropy, buf, buflen))
        return true;
      sys_getentropy_doesnt_work = true;
    }
#endif

#ifdef SYS_getrandom
  static bool sys_getrandom_doesnt_work;
  if (!sys_getrandom_doesnt_work)
    {
      if ((size_t)syscall (SYS_getrandom, buf, buflen, 0) == buflen)
        return true;
      sys_getrandom_doesnt_work = true;
    }
#endif
#endif

#if defined HAVE_SYS_STAT_H && defined HAVE_FCNTL_H && defined HAVE_UNISTD_H
  /* Try reading from /dev/urandom.  */
  static bool dev_urandom_doesnt_work;
  if (!dev_urandom_doesnt_work)
    {
      int fd = open ("/dev/urandom", O_RDONLY|O_CLOEXEC);
      if (fd == -1)
        dev_urandom_doesnt_work = true;
      else
        {
          ssize_t nread = read (fd, buf, buflen);
          if (nread < 0 || (size_t)nread < buflen)
            dev_urandom_doesnt_work = true;

          close(fd);
          return !dev_urandom_doesnt_work;
        }
    }
#endif
#endif /* no arc4random_buf */

  /* if we get here, we're just completely hosed */
  errno = ENOSYS;
  return false;
}

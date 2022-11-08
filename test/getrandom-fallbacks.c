/* Test the fallback logic in get_random_bytes.

   Written by Zack Weinberg <zackw at panix.com> in 2018.
   To the extent possible under law, Zack Weinberg has waived all
   copyright and related or neighboring rights to this work.

   See https://creativecommons.org/publicdomain/zero/1.0/ for further
   details.  */

#include "crypt-port.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if defined HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/* If arc4random_buf is available, all of the fallback logic is compiled
   out and this test is unnecessary.  If ld --wrap is not available this
   test will not work.  */
#if defined HAVE_ARC4RANDOM_BUF || !defined HAVE_LD_WRAP

int
main (void)
{
  return 77;
}

#else

/* All of the mock system primitives below fill in their buffer with
   repeats of these bytes, so we can tell where the data came from.  */
#define MOCK_getentropy     'e'
#define MOCK_getrandom      'r'
#define MOCK_sys_getentropy 'E'
#define MOCK_sys_getrandom  'R'
#define MOCK_urandom        'u'

#ifdef HAVE_GETENTROPY
static bool getentropy_should_fail = false;
extern int __wrap_getentropy (void *, size_t);
int
__wrap_getentropy (void *buf, size_t buflen)
{
  if (getentropy_should_fail)
    {
      errno = ENOSYS;
      return -1;
    }
  else
    {
      memset (buf, MOCK_getentropy, buflen);
      return 0;
    }
}
#endif

#ifdef HAVE_GETRANDOM
static bool getrandom_should_fail = false;
extern ssize_t __wrap_getrandom (void *, size_t, unsigned int);
ssize_t
__wrap_getrandom (void *buf, size_t buflen, unsigned int ARG_UNUSED(flags))
{
  if (getrandom_should_fail)
    {
      errno = ENOSYS;
      return -1;
    }
  else
    {
      buflen = MIN (buflen, INT16_MAX);
      memset (buf, MOCK_getrandom, buflen);
      return (ssize_t)buflen;
    }
}
#endif

#ifdef HAVE_SYSCALL
#ifdef SYS_getentropy
static bool sys_getentropy_should_fail = false;
#endif
#ifdef SYS_getrandom
static bool sys_getrandom_should_fail = false;
#endif
static bool other_syscalls = false;
extern long __wrap_syscall (long, ...);
long
__wrap_syscall(long number, ...)
{
#ifdef SYS_getentropy
  if (number == SYS_getentropy)
    {
      if (sys_getentropy_should_fail)
        {
          errno = ENOSYS;
          return -1;
        }
      else
        {
          va_list ap;
          va_start (ap, number);
          void *buf = va_arg (ap, void *);
          size_t buflen = va_arg (ap, size_t);
          va_end (ap);
          memset (buf, MOCK_sys_getentropy, buflen);
          return 0;
        }
    }
#endif
#ifdef SYS_getrandom
  if (number == SYS_getrandom)
    {
      if (sys_getrandom_should_fail)
        {
          errno = ENOSYS;
          return -1;
        }
      else
        {
          va_list ap;
          va_start (ap, number);
          void *buf = va_arg (ap, void *);
          size_t buflen = va_arg (ap, size_t);
          buflen = MIN (buflen, INT16_MAX);
          va_end (ap);
          memset (buf, MOCK_sys_getrandom, buflen);
          return (ssize_t)buflen;
        }
    }
#endif
  /* There is no vsyscall.  We just have to hope nobody in this test
     program wants to use syscall() for anything else.  */
  other_syscalls = true;
  fprintf (stderr, "ERROR: unexpected syscall(%ld)\n", number);
  errno = ENOSYS;
  return -1;
}
#endif /* HAVE_SYSCALL */

/* It is not possible to hit both of the code paths that can set the
   "/dev/urandom doesn't work" flag in a single test program, because
   there's no way to _clear_ that flag again.  This test chooses to
   exercise the read-failure path, not the open-failure path.  */
#if defined HAVE_SYS_STAT_H && defined HAVE_FCNTL_H && defined HAVE_UNISTD_H
static bool urandom_should_fail = false;
static int urandom_fd = -1;
extern int __wrap_open (const char *, int, mode_t);
extern int __real_open (const char *, int, mode_t);
int
__wrap_open (const char *path, int flags, mode_t mode)
{
  int ret = __real_open (path, flags, mode);
  if (ret == -1)
    return ret;
  if (!strcmp (path, "/dev/urandom"))
    urandom_fd = ret;
  return ret;
}

#ifdef HAVE_OPEN64
extern int __wrap_open64 (const char *, int, mode_t);
extern int __real_open64 (const char *, int, mode_t);
int
__wrap_open64 (const char *path, int flags, mode_t mode)
{
  int ret = __real_open64 (path, flags, mode);
  if (ret == -1)
    return ret;
  if (!strcmp (path, "/dev/urandom"))
    urandom_fd = ret;
  return ret;
}
#endif

extern int __wrap_close (int);
extern int __real_close (int);
int
__wrap_close (int fd)
{
  if (fd == urandom_fd)
    urandom_fd = -1;
  return __real_close (fd);
}

extern ssize_t __wrap_read (int, void *, size_t);
extern ssize_t __real_read (int, void *, size_t);
ssize_t
__wrap_read (int fd, void *buf, size_t count)
{
  if (fd == urandom_fd)
    {
      if (urandom_should_fail)
        {
          errno = ENOSYS;
          return -1;
        }
      else
        {
          count = MIN (count, INT16_MAX);
          memset (buf, MOCK_urandom, count);
          return (ssize_t)count;
        }
    }
  else
    return __real_read (fd, buf, count);
}

#endif

struct subtest
{
  const char *what;
  bool *make_fail;
  char expected;
};
const struct subtest subtests[] =
{
  { "initial", 0, 'x' },

#ifdef HAVE_GETENTROPY
  { "getentropy", &getentropy_should_fail, MOCK_getentropy },
#endif
#ifdef HAVE_GETRANDOM
  { "getrandom", &getrandom_should_fail, MOCK_getrandom },
#endif

#ifdef HAVE_SYSCALL
#ifdef SYS_getentropy
  { "sys_getentropy", &sys_getentropy_should_fail, MOCK_sys_getentropy },
#endif
#ifdef SYS_getrandom
  { "sys_getrandom", &sys_getrandom_should_fail, MOCK_sys_getrandom },
#endif
#endif

#if defined HAVE_SYS_STAT_H && defined HAVE_FCNTL_H && defined HAVE_UNISTD_H
  { "/dev/urandom", &urandom_should_fail, MOCK_urandom },
#endif

  { "final", 0, 0 }
};

int
main (void)
{
  char buf[257];
  char expected[2] = { 0, 0 };
  memset (buf, 'x', sizeof buf - 1);
  buf[sizeof buf - 1] = '\0';
  bool failed = false;
  const struct subtest *s;

  for (s = subtests; s->expected;)
    {
      expected[0] = s->expected;
      if (strspn (buf, expected) != 256)
        {
          printf ("FAIL: %s: buffer not filled with '%c'\n",
                  s->what, s->expected);
          failed = true;
        }
      else
        printf ("ok: %s (output)\n", s->what);

      if (s->make_fail)
        *(s->make_fail) = true;
      s++;

      bool r = get_random_bytes (buf, sizeof buf - 1);
      buf[sizeof buf - 1] = '\0';
      if ((s->expected && !r) || (!s->expected && r))
        {
          printf ("FAIL: %s: get_random_bytes: %s\n",
                  s->what, strerror (errno));
          failed = true;
        }
      else
        printf ("ok: %s (return)\n", s->what);
    }
#if HAVE_SYSCALL
  failed |= other_syscalls;
#endif
  return failed;
}

#endif

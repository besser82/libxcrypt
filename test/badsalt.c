/* Test rejection of ill-formed password hashes.
   Copyright (C) 2012-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include "crypt-port.h"
#undef yescrypt

#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>

/* If VERBOSE is true, passing testcases will be printed out as well
   as failing ones.  */
static bool verbose = false;

/* All hashes are hashes of this passphrase, an infamous error message
   used for some forgotten can't-happen condition in Unix V6; see
   <https://wiki.tuhs.org/doku.php?id=anecdotes:values_of_beta>.  */
static const char phrase[] = "values of β will give rise to dom!";

/* Correct setting strings, from which we derive incorrect ones by
   replacing one character at a time with a character that cannot
   appear in a valid passphrase (namely ':') and/or truncating the
   string.  */
struct valid_setting;

/* Type of functions to use in is_valid_trunc.  */
typedef bool (*valid_trunc_p)(const struct valid_setting *original,
                              const char *truncated);

struct valid_setting
{
  /* Human-readable name for this test */
  const char *tag;

  /* The setting string */
  const char *setting;

  /* Length of the actual setting, within the setting string.  This is
     usually equal to strlen(setting), but a couple of the strings are
     padded on the right for hash-specific reasons.  */
  size_t setting_len;

  /* Given a truncation of a valid setting string, decide whether the
   truncation is also valid.  */
  valid_trunc_p is_valid_trunc;

  /* Numeric parameter for is_valid_trunc; usually the length of a
     subfield of the setting.  */
  uint16_t is_valid_trunc_param;

  /* Whether support for this hash was compiled into the library.  */
  bool enabled;

};

/* is_valid_trunc functions -- forward declarations */

static bool vt_never(const struct valid_setting *, const char *);
static bool vt_varsuffix(const struct valid_setting *, const char *);
static bool vt_sunmd5(const struct valid_setting *, const char *);
static bool vt_sm3(const struct valid_setting *, const char *);
static bool vt_sha2gnu(const struct valid_setting *, const char *);
static bool vt_yescrypt(const struct valid_setting *, const char *);

/* shorthands for use in valid_cases */

#define V_(  hash,      setting, vt, vp) \
  { #hash,               setting, sizeof setting - 1, vt, vp, INCLUDE_##hash }
#define Vp_( hash,      setting, vt, vp) \
  { #hash,               setting, vp,                 vt, vp, INCLUDE_##hash }
#define Vt_( hash, tag, setting, vt, vp) \
  { #hash " (" #tag ")", setting, sizeof setting - 1, vt, vp, INCLUDE_##hash }
#define Vtp_(hash, tag, setting, vt, vp) \
  { #hash " (" #tag ")", setting, vp,                 vt, vp, INCLUDE_##hash }

#define V(  hash,          setting) V_(  hash,      setting, vt_never,     0)
#define Vn( hash,      vt, setting) V_(  hash,      setting, vt_##vt,      0)
#define Vp( hash,      sl, setting) Vp_( hash,      setting, vt_varsuffix, sl)
#define Vv( hash,      sl, setting) V_(  hash,      setting, vt_varsuffix, sl)
#define Vt( hash, tag,     setting) Vt_( hash, tag, setting, vt_never,     0)
#define Vtn(hash, tag, vt, setting) Vt_( hash, tag, setting, vt_##vt,      0)
#define Vtp(hash, tag, sl, setting) Vtp_(hash, tag, setting, vt_varsuffix, sl)
#define Vtv(hash, tag, sl, setting) Vt_( hash, tag, setting, vt_varsuffix, sl)

/* Each of these is a valid setting string for some algorithm,
   from which we will derive many invalid setting strings.
   This is an expensive test, so where possible, the number of
   "rounds" of the hash function has been set abnormally low.  */
static const struct valid_setting valid_cases[] =
{
  V  (descrypt,                            "Mp"                               ),
  /* bigcrypt is extra special:
     this salt is a valid descrypt salt when bigcrypt isn't enabled
       but descrypt is;
     truncations down to 2 are valid when descrypt is enabled, but
       if *only* bigcrypt is enabled, then truncations can only
       go down to 14.  */
  {
    INCLUDE_bigcrypt ? "bigcrypt" : "descrypt (padded)",
    "Mp............", 2, vt_varsuffix,
    INCLUDE_descrypt ? 2 : 14,
    INCLUDE_descrypt || INCLUDE_bigcrypt
  },
  V  (bsdicrypt,                           "_J9..MJHn"                          ),
  Vv (md5crypt,                  3,        "$1$MJHnaAke$"                       ),
  Vtn(sunmd5,        plain,      sunmd5,   "$md5$1xMeE.at$"                     ),
  Vtn(sunmd5,        rounds,     sunmd5,   "$md5,rounds=123$1xMeE.at$"          ),
  Vt (nt,            plain,                "$3$"                                ),
  Vtp(nt,            fake salt,  3,        "$3$__not_used__c809a450df09a3"      ),
  Vv (sha1crypt,                 11,       "$sha1$123$GGXpNqoJvglVTkGU$"        ),
  Vtn(sha256crypt,   plain,      sha2gnu,  "$5$MJHnaAkegEVYHsFK$"               ),
  Vtn(sha256crypt,   rounds,     sha2gnu,  "$5$rounds=1000$MJHnaAkegEVYHsFK$"   ),
  Vtn(sha512crypt,   plain,      sha2gnu,  "$6$MJHnaAkegEVYHsFK$"               ),
  Vtn(sha512crypt,   rounds,     sha2gnu,  "$6$rounds=1000$MJHnaAkegEVYHsFK$"   ),
  Vtn(sm3crypt,      plain,      sm3,      "$sm3$MJHnaAkegEVYHsFK$"             ),
  Vtn(sm3crypt,      rounds,     sm3,      "$sm3$rounds=1000$MJHnaAkegEVYHsFK$" ),
  V  (bcrypt,                              "$2b$04$UBVLHeMpJ/QQCv3XqJx8zO"      ),
  V  (bcrypt_a,                            "$2a$04$UBVLHeMpJ/QQCv3XqJx8zO"      ),
  V  (bcrypt_x,                            "$2x$04$UBVLHeMpJ/QQCv3XqJx8zO"      ),
  V  (bcrypt_y,                            "$2y$04$UBVLHeMpJ/QQCv3XqJx8zO"      ),
  Vv (scrypt,                    14,       "$7$C6..../....SodiumChloride$"      ),
  Vn (yescrypt,                  yescrypt, "$y$j9T$PKXc3hCOSyMqdaEQArI62/$"     ),
  Vn (gost_yescrypt,             yescrypt, "$gy$j9T$PKXc3hCOSyMqdaEQArI62/$"    ),
  Vn (sm3_yescrypt,              yescrypt, "$sm3y$j9T$PKXc3hCOSyMqdaEQArI62/$"  ),
};

#undef V_
#undef Vp_
#undef Vt_
#undef Vtp_

#undef V
#undef Vn
#undef Vp
#undef Vv
#undef Vt
#undef Vtn
#undef Vtp
#undef Vtv

/* Additional tests of manually constructed, invalid setting
   strings.  */
struct invalid_setting
{
  const char *tag;
  const char *setting;
};
static const struct invalid_setting invalid_cases[] =
{
  /* These strings are invalid regardless of the algorithm.  */
  { "too short 1",                 "/"                                        },
  { "too short 2",                 "M"                                        },
  { "too short 3",                 "$"                                        },
  { "too short 4",                 "_"                                        },
  { "too short 5",                 "."                                        },
  { "invalid char :",              ":"                                        },
  { "invalid char ;",              ";"                                        },
  { "invalid char *",              "*"                                        },
  { "invalid char !",              "!"                                        },
  { "invalid char \\",             "\\"                                       },
  { "invalid char SPC",            " "                                        },
  { "invalid char TAB",            "\t"                                       },
  { "invalid char ^M",             "\r"                                       },
  { "invalid char ^J",             "\n"                                       },
  { "invalid char ^L",             "\f"                                       },
  { "invalid char ^A",             "\001"                                     },
  { "invalid char DEL",            "\177"                                     },
  { "failure token 1",             "*0"                                       },
  { "failure token 2",             "*1"                                       },
  { "unsupported algorithm",       "$un$upp0rt3d$"                            },
  { "empty string",                ""                                         },

  /* These strings are invalid for specific algorithms, in ways
     that the generic error generator cannot produce.  */
  { "sunmd5 absent rounds",        "$md5,rounds=$1xMeE.at$"                   },
  { "sunmd5 low rounds",           "$md5,rounds=0$1xMeE.at$"                  },
  { "sunmd5 octal rounds",         "$md5,rounds=012$1xMeE.at$"                },
  { "sunmd5 high rounds",          "$md5,rounds=4294967296$1xMeE.at$"         },
  { "sha256 absent rounds",        "$5$rounds=$MJHnaAkegEVYHsFK$"             },
  { "sha256 low rounds",           "$5$rounds=0$MJHnaAkegEVYHsFK$"            },
  { "sha256 octal rounds",         "$5$rounds=0100$MJHnaAkegEVYHsFK$"         },
  { "sha256 high rounds",          "$5$rounds=4294967295$MJHnaAkegEVYHsFK$"   },
  { "sha512 absent rounds",        "$6$rounds=$MJHnaAkegEVYHsFK$"             },
  { "sha512 low rounds",           "$6$rounds=0$MJHnaAkegEVYHsFK$"            },
  { "sha512 octal rounds",         "$6$rounds=0100$MJHnaAkegEVYHsFK$"         },
  { "sha512 high rounds",          "$6$rounds=4294967295$MJHnaAkegEVYHsFK$"   },
  { "sm3 absent rounds",           "$sm3$rounds=$MJHnaAkegEVYHsFK$"           },
  { "sm3 low rounds",              "$sm3$rounds=0$MJHnaAkegEVYHsFK$"          },
  { "sm3 octal rounds",            "$sm3$rounds=0100$MJHnaAkegEVYHsFK$"       },
  { "sm3 high rounds",             "$sm3$rounds=4294967295$MJHnaAkegEVYHsFK$" },
  { "bcrypt no subtype",           "$2$04$UBVLHeMpJ/QQCv3XqJx8zO"             },
  { "bcrypt_b low rounds",         "$2b$03$UBVLHeMpJ/QQCv3XqJx8zO"            },
  { "bcrypt_b high rounds",        "$2b$32$UBVLHeMpJ/QQCv3XqJx8zO"            },
  { "bcrypt_a low rounds",         "$2a$03$UBVLHeMpJ/QQCv3XqJx8zO"            },
  { "bcrypt_a high rounds",        "$2a$32$UBVLHeMpJ/QQCv3XqJx8zO"            },
  { "bcrypt_x low rounds",         "$2x$03$UBVLHeMpJ/QQCv3XqJx8zO"            },
  { "bcrypt_x high rounds",        "$2x$32$UBVLHeMpJ/QQCv3XqJx8zO"            },
  { "bcrypt_y low rounds",         "$2y$03$UBVLHeMpJ/QQCv3XqJx8zO"            },
  { "bcrypt_y low rounds",         "$2y$32$UBVLHeMpJ/QQCv3XqJx8zO"            },
  { "yescrypt short params",       "$y$j9$PKXc3hCOSyMqdaEQArI62/$"            },
  { "gost-yescrypt short params",  "$gy$j9$PKXc3hCOSyMqdaEQArI62/$"           },
  { "sm3-yescrypt short params",   "$sm3y$j9$PKXc3hCOSyMqdaEQArI62/$"         },
};

/* is_valid_trunc functions -- definitions.
   Note: these only need to be correct for the patterns we actually test.  */

/* All truncations of this setting string are invalid.  */
static bool
vt_never(const struct valid_setting * ARG_UNUSED(original),
         const char * ARG_UNUSED(truncated))
{
  return false;
}

/* This setting string has a variable-length suffix; truncations are
   valid as long as the result has at least `is_valid_trunc_param'
   characters.  */
static bool
vt_varsuffix(const struct valid_setting *original,
             const char *truncated)
{
  return strlen(truncated) >= original->is_valid_trunc_param;
}

/* Special validity rule for sunmd5, sha256crypt, and sha512crypt: ... */
static bool
vt_roundseq(const char *truncated, size_t minlen, size_t roundslen,
            const char *roundstag1, const char *roundstag2)
{
  /* ... the setting cannot be valid if it's shorter than 'minlen'
     characters ... */
  if (strlen(truncated) < minlen)
    return false;

  /* ... if it begins with roundstag1 or roundstag2 then a sequence of
     digits must follow, then a dollar sign; roundstag2 may be null;
     ... */
  if (!strncmp(truncated, roundstag1, roundslen)
      || (roundstag2 && !strncmp(truncated, roundstag2, roundslen)))
    {
      size_t i = roundslen;
      while (truncated[i] >= '0' && truncated[i] <= '9')
        i++;
      if (truncated[i] != '$')
        return false;
    }

  /* ... otherwise it's ok.  */
  return true;
}

/* Special validity rule for sunmd5.  */
static bool
vt_sunmd5(const struct valid_setting *ARG_UNUSED(original),
          const char *truncated)
{
  return vt_roundseq(truncated, strlen("$md5$"), strlen("$md5,rounds="),
                     "$md5,rounds=", 0);
}

/* Special validity rule for sm3.  */
static bool
vt_sm3(const struct valid_setting *ARG_UNUSED(original),
          const char *truncated)
{
  return vt_roundseq(truncated, strlen("$sm3$"), strlen("$sm3$rounds="),
                     "$sm3$rounds=", 0);
}

/* Special validity rule for sha256crypt and sha512crypt.  */
static bool
vt_sha2gnu(const struct valid_setting *ARG_UNUSED(original),
           const char *truncated)
{
  return vt_roundseq(truncated, strlen("$5$"), strlen("$5$rounds="),
                     "$5$rounds=", "$6$rounds=");
}

/* Special validity rule for yescrypt and gost_yescrypt: ... */
static bool
vt_yescrypt(const struct valid_setting *ARG_UNUSED(original),
            const char *truncated)
{
  /* ... the setting string must begin with "$y$j9T$" or "$gy$j9T$"
     (other introductory sequences are possible but those are the
     only ones we use); ... */
  size_t y_intro_len = strlen("$y$j9T$");
  size_t gy_intro_len = strlen("$gy$j9T$");
  size_t sm3y_intro_len = strlen("$sm3y$j9T$");
  size_t intro_len;
  if (!strncmp(truncated, "$y$j9T$", y_intro_len))
    intro_len = y_intro_len;
  else if (!strncmp(truncated, "$gy$j9T$", gy_intro_len))
    intro_len = gy_intro_len;
  else if (!strncmp(truncated, "$sm3y$j9T$", sm3y_intro_len))
    intro_len = sm3y_intro_len;
  else
    return false;

  /* ... and the remainder must be one of these lengths.  (I do not
     see a pattern.)  */
  switch (strlen(truncated) - intro_len)
    {
    case  0:
    case  4:
    case  7:
    case  8:
    case 12:
    case 16:
    case 20:
    case 22:
    case 23:
      return true;
    default:
      return false;
    }
}


/* Some of the test setting strings contain unprintable characters,
   which we print as hex escapes.  For readability, whenever we print
   out a setting string we pad it on the right with spaces to the
   length of the longest setting string we have.  (There is always
   something after that on the line.)  */
static size_t longest_setting;

static void
print_setting (const char *setting, bool pad)
{
  size_t n = 0;
  for (; *setting; setting++)
    {
      unsigned int c = (unsigned int)(unsigned char) *setting;
      if (0x20 <= c && c <= 0x7e)
        {
          putchar ((int)c);
          n += 1;
        }
      else
        {
          printf ("\\x%02x", c);
          n += 4;
        }
    }
  if (!pad)
    return;
  while (n < longest_setting)
    {
      putchar (' ');
      n += 1;
    }
}

static size_t
measure_setting (const char *setting)
{
  size_t n = 0;
  for (; *setting; setting++)
    {
      unsigned int c = (unsigned int)(unsigned char) *setting;
      if (0x20 <= c && c <= 0x7e)
        n += 1;
      else
        n += 4;
    }
  return n;
}

static void
measure_settings (void)
{
  size_t ls = 0;
  for (size_t i = 0; i < ARRAY_SIZE (valid_cases); i++)
    ls = MAX (ls, measure_setting(valid_cases[i].setting));

  for (size_t i = 0; i < ARRAY_SIZE (invalid_cases); i++)
    ls = MAX (ls, measure_setting(invalid_cases[i].setting));

  longest_setting = ls;
}

static void
print_result (const char *result, const char *setting,
              const char *tag, bool expected_valid)
{
  printf ("%s: ", result);
  print_setting (setting, true);
  printf (" (%s, %s)", tag, expected_valid ? "valid" : "invalid");
}

/* Part of what we're testing, is whether any of the hashing methods
   can read past the end of a properly terminated C string that
   happens to contain an invalid setting.  We do this by placing the
   invalid setting right next to a page of inaccessible memory and
   trapping the fault.  */
static volatile sig_atomic_t signal_loop = 0;
static sigjmp_buf env;
static void
segv_handler (int sig)
{
  if (signal_loop == 0)
    {
      signal_loop = 1;
      siglongjmp (env, sig);
    }
  else
    {
      signal (sig, SIG_DFL);
      raise (sig);
    }
}

/* We use only crypt_rn in this test, because it only exercises the
   error handling logic within the hashing methods, not the
   higher-level error handling logic that varies slightly among the
   entry points (that's all taken care of in crypt-badargs.c).  We use
   crypt_rn instead of crypt_r so that this test does not need to vary
   any of its logic based on --enable-failure-tokens.  */
static bool
test_one_setting (const char *setting, size_t l_setting,
                  const char *tag, bool expected_valid,
                  struct crypt_data *cd)
{
  volatile bool fail = false;
  signal_loop = 0;
  int sig = sigsetjmp (env, 1);
  if (!sig)
    {
      char *retval = crypt_rn (phrase, setting, cd, (int) sizeof *cd);
      if (expected_valid)
        {
          if (!retval)
            {
              fail = true;
              print_result ("FAIL", setting, tag, expected_valid);
              puts(": returned NULL");
            }
          else if (retval != cd->output)
            {
              fail = true;
              print_result ("FAIL", setting, tag, expected_valid);
              printf(": returned %p, should be %p\n",
                     (const void *)retval, (const void *)cd->output);
            }
          else if (strncmp (retval, setting, l_setting))
            {
              fail = true;
              print_result("FAIL", setting, tag, expected_valid);
              fputs(": got non-matching ", stdout);
              print_setting(retval, false);
              putchar('\n');
            }
        }
      else
        {
          if (retval)
            {
              fail = true;
              print_result ("FAIL", setting, tag, expected_valid);
              fputs(": expected NULL, got ", stdout);
              print_setting (retval, false);
              putchar('\n');
            }
        }
    }
  else
    {
      fail = true;
      print_result("FAIL", setting, tag, expected_valid);
      printf(": %s\n", strsignal (sig));
    }

  if (verbose && !fail)
    {
      print_result("PASS", setting, tag, expected_valid);
      putchar('\n');
    }

  return fail;
}

static bool
test_one_valid(const struct valid_setting *tc,
               char *page, size_t pagesize, struct crypt_data *cd)
{
  /* Caution: tc->setting_len is _not_ always equal to strlen(tc->setting).
     Sometimes it is smaller.  */
  size_t l_setting = strlen(tc->setting) + 1;
  char *setting = page + pagesize - l_setting;
  memcpy(setting, tc->setting, l_setting);

  /* crypt_rn() using this setting, unmodified, is expected to
     succeed, unless the hash function is disabled.  */
  if (test_one_setting (setting, tc->setting_len, tc->tag, tc->enabled, cd))
    return true;

  /* Rechecking the hash with the full output should also succeed.
     In this subtest we expect to get the same _complete hash_
     back out, not just the same setting.  */
  if (tc->enabled)
    {
      size_t l_hash = strlen (cd->output);
      char *p = page + pagesize - (l_hash + 1);
      assert (l_hash + 1 <= CRYPT_OUTPUT_SIZE);
      memcpy (p, cd->output, l_hash + 1);

      if (test_one_setting (p, l_hash, tc->tag, true, cd))
        return true;

      /* When crypt() is called with a complete hashed passphrase as the
         setting string, the hashing method must not look at the hash
         component of the setting _at all_.  We test this by supplying a
         string with one extra character, an A, which _could_ be part of
         the hash component for all supported methods, but which is much
         too short by itself.  This should produce the same complete hash
         as the previous test.  (It has to be a character which _could_
         appear, because the generic crypt() machinery rejects setting
         strings containing invalid characters in any position.)

         Super special case: Don't do this subtest for sunmd5,
         because, due to a bug in its original implementation, the
         first character after the end of the salt _does_ affect the
         hash output.  We have to preserve this bug for compatibility
         with existing sunmd5 hashed passphrases.  */
      if (!INCLUDE_sunmd5 || strncmp(tc->setting, "$md5", 4))
        {
          p = page + pagesize - (l_hash + 1 + l_setting + 1);
          memcpy (p, cd->output, l_hash + 1);

          char *settingA = page + pagesize - (l_setting + 1);
          memcpy(settingA, tc->setting, l_setting - 1);
          settingA[l_setting - 1] = 'A';
          settingA[l_setting - 0] = '\0';
          if (test_one_setting (settingA, tc->setting_len, tc->tag, true, cd))
            return true;
          if (strcmp (cd->output, p))
            {
              print_result ("FAIL", settingA, tc->tag, true);
              /* Since cd->output and p are both hashed passphrases, not
                 handcrafted invalid setting strings, we can safely print
                 them with %s.  */
              printf (": expected %s, got %s\n", p, cd->output);
              return true;
            }
          else if (verbose)
            {
              print_result ("PASS", settingA, tc->tag, true);
              printf (": got %s, as expected\n", cd->output);
            }
        }

      /* Restore the original data at 'setting', as expected by code
         below.  */
      memcpy(setting, tc->setting, l_setting);
    }

  /* The rest of the subtests in this function are logically independent.  */
  bool failed = false;

  /* Replacing any one character of this setting with a ':', leaving
     the rest of the string intact, should cause crypt_rn to fail.  */
  for (size_t i = 0; i < l_setting - 1; i++)
    {
      char saved = setting[i];
      setting[i] = ':';
      failed |= test_one_setting(setting, tc->setting_len, tc->tag, false, cd);
      setting[i] = saved;
    }

  /* Chop off the last character of the setting string and test that.
     Then, replace the new last character of the setting string with a
     colon, and test that.  (This is different from the earlier test
     where we replaced each character in turn with a colon but kept
     the rest of the string intact, because the hashing method might
     be calling strlen() on the setting string.)  Repeat these two
     steps until we have just one character left, then stop.

     For instance, if the original setting string is
         $1$MJHnaAke$
     then we test
         $1$MJHnaAke
         $1$MJHnaAk:
         $1$MJHnaAk
         $1$MJHnaA:
         $1$MJHnaA
         ...
         $1
         $:

     ($1$MJHnaAke: would have been tested by the loop above.  All the
     single-character strings that can be a prefix of a setting string
     from valid_cases---"$", "_", "M"---are tested by invalid_cases,
     is ":".)

     Up till this point l_setting has been _one more than_
     strlen(setting), but in this loop it is more convenient to have
     it be equal to strlen(setting).  */
  l_setting -= 1;

  while (l_setting > 2)
    {
      memmove(setting + 1, setting, l_setting - 1);
      setting += 1;
      l_setting -= 1;
      failed |= test_one_setting(setting, MIN (l_setting, tc->setting_len),
                                 tc->tag,
                                 tc->enabled
                                 && tc->is_valid_trunc(tc, setting),
                                 cd);
      page[pagesize - 2] = ':';
      failed |= test_one_setting(setting, l_setting, tc->tag, false, cd);
    }

  return failed;
}

static bool
test_one_invalid(const struct invalid_setting *tc,
                 char *page, size_t pagesize, struct crypt_data *cd)
{
  size_t l_setting = strlen(tc->setting) + 1;
  char *setting = page + pagesize - l_setting;
  memcpy(setting, tc->setting, l_setting);
  return test_one_setting(setting, l_setting - 1, tc->tag, false, cd);
}

static bool
do_tests(char *page, size_t pagesize)
{
  bool failed = false;

  struct crypt_data cd;
  memset (&cd, 0, sizeof cd);

  for (size_t i = 0; i < ARRAY_SIZE (valid_cases); i++)
    failed |= test_one_valid (&valid_cases[i], page, pagesize, &cd);

  for (size_t i = 0; i < ARRAY_SIZE (invalid_cases); i++)
    failed |= test_one_invalid (&invalid_cases[i], page, pagesize, &cd);

  return failed;
}

int
main (int argc, char **argv)
{
  if (argc <= 1)
    ;
  else if (argc == 2
           && (!strcmp(argv[1], "-v")
               || !strcmp(argv[1], "--verbose")))
    verbose = true;
  else
    {
      fprintf(stderr, "usage: %s [-v | --verbose]\n", argv[0]);
      return 99;
    }

  if (setvbuf(stdout, 0, _IOLBF, 0) || setvbuf(stderr, 0, _IOLBF, 0))
    {
      perror ("setvbuf");
      return 99;
    }

  /* Set up a two-page region whose first page is read-write and
     whose second page is inaccessible.  */
  long pagesize_l = sysconf (_SC_PAGESIZE);
  if (pagesize_l < (long) CRYPT_OUTPUT_SIZE)
    {
      printf ("ERROR: pagesize of %ld is too small\n", pagesize_l);
      return 99;
    }

  size_t pagesize = (size_t) pagesize_l;
  char *page = mmap (0, pagesize * 2, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANON, -1, 0);
  if (page == MAP_FAILED)
    {
      perror ("mmap");
      return 99;
    }
  memset (page, 'x', pagesize * 2);
  if (mprotect (page + pagesize, pagesize, PROT_NONE))
    {
      perror ("mprotect");
      return 99;
    }

  struct sigaction sa, os, ob;
  sigfillset (&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sa.sa_handler = segv_handler;
  if (sigaction (SIGBUS, &sa, &ob) || sigaction (SIGSEGV, &sa, &os))
    {
      perror ("sigaction");
      return 1;
    }

  measure_settings();
  bool failed = do_tests (page, pagesize);

  sigaction (SIGBUS, &ob, 0);
  sigaction (SIGSEGV, &os, 0);

  return failed;
}

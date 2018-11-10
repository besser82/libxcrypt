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
#include <crypt.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static const char phrase[] = "values of β will give rise to dom!";

struct testcase
{
  const char *label;
  size_t plen;
  const char *setting;
};
static const struct testcase testcases[] =
{
  /* These strings are invalid regardless of the algorithm.  */
  { "*too short",                           1, "/"              },
  { "*invalid char :",                      1, ":"              },
  { "*invalid char ;",                      1, ";"              },
  { "*invalid char *",                      1, "*"              },
  { "*invalid char !",                      1, "!"              },
  { "*invalid char \\",                     1, "\\"             },
  { "*invalid white 1",                     1, " "              },
  { "*invalid white 2",                     1, "\t"             },
  { "*invalid white 3",                     1, "\r"             },
  { "*invalid white 4",                     1, "\n"             },
  { "*invalid white 5",                     1, "\f"             },
  { "*invalid ctrl 1",                      1, "\1"             },
  { "*invalid ctrl 2",                      1, "\177"           },
  { "*failure token 1",                     2, "*0"             },
  { "*failure token 2",                     2, "*1"             },
  { "*bcrypt invalid salt",                 3, "$2$"            },
  { "*unsupported algorithm",              13, "$un$upp0rt3d$"  },
  { "*empty string",                        1, "\0"             },

  /* Each of these is a valid setting string for some algorithm,
     from which we will derive many invalid setting strings.
     This is an expensive test, so where possible, the number of
     "rounds" of the hash function has been set abnormally low.  */
#if INCLUDE_descrypt
  { "DES (trad.)",                          2, "Mp" },
  { "*DES (trad.), 1st char invalid -",     2, "-p" },
  { "*DES (trad.), 2nd char invalid -",     2, "M-" },
  { "*DES (trad.), 1st char invalid :",     2, ":p" },
  { "*DES (trad.), 2nd char invalid :",     2, "M:" },
  { "*DES (trad.), 1st char invalid [",     2, "[p" },
  { "*DES (trad.), 2nd char invalid [",     2, "M[" },
  { "*DES (trad.), 1st char invalid {",     2, "{p" },
  { "*DES (trad.), 2nd char invalid {",     2, "M{" },
#endif
#if INCLUDE_bigcrypt
  { "DES (bigcrypt)",                       14, "Mp............" },
  { "*DES (bigcrypt), 1st char invalid -",  14, "-p............" },
  { "*DES (bigcrypt), 2nd char invalid -",  14, "M-............" },
  { "*DES (bigcrypt), 1st char invalid :",  14, ":p............" },
  { "*DES (bigcrypt), 2nd char invalid :",  14, "M:............" },
  { "*DES (bigcrypt), 1st char invalid [",  14, "[p............" },
  { "*DES (bigcrypt), 2nd char invalid [",  14, "M[............" },
  { "*DES (bigcrypt), 1st char invalid {",  14, "{p............" },
  { "*DES (bigcrypt), 2nd char invalid {",  14, "M{............" },
#endif
#if INCLUDE_bsdicrypt
  { "DES (BSDi)",                           9, "_J9..MJHn" },
  { "*DES (BSDi), 1st char invalid -",      9, "_-9..MJHn" },
  { "*DES (BSDi), 2nd char invalid -",      9, "_J-..MJHn" },
  { "*DES (BSDi), 3rd char invalid -",      9, "_J9-.MJHn" },
  { "*DES (BSDi), 4th char invalid -",      9, "_J9.-MJHn" },
  { "*DES (BSDi), 5th char invalid -",      9, "_J9..-JHn" },
  { "*DES (BSDi), 6th char invalid -",      9, "_J9..M-Hn" },
  { "*DES (BSDi), 7th char invalid -",      9, "_J9..MJ-n" },
  { "*DES (BSDi), 8th char invalid -",      9, "_J9..MJH-" },
  { "*DES (BSDi), 1st char invalid :",      9, "_:9..MJHn" },
  { "*DES (BSDi), 2nd char invalid :",      9, "_J:..MJHn" },
  { "*DES (BSDi), 3rd char invalid :",      9, "_J9:.MJHn" },
  { "*DES (BSDi), 4th char invalid :",      9, "_J9.:MJHn" },
  { "*DES (BSDi), 5th char invalid :",      9, "_J9..:JHn" },
  { "*DES (BSDi), 6th char invalid :",      9, "_J9..M:Hn" },
  { "*DES (BSDi), 7th char invalid :",      9, "_J9..MJ:n" },
  { "*DES (BSDi), 8th char invalid :",      9, "_J9..MJH:" },
  { "*DES (BSDi), 1st char invalid [",      9, "_[9..MJHn" },
  { "*DES (BSDi), 2nd char invalid [",      9, "_J[..MJHn" },
  { "*DES (BSDi), 3rd char invalid [",      9, "_J9[.MJHn" },
  { "*DES (BSDi), 4th char invalid [",      9, "_J9.[MJHn" },
  { "*DES (BSDi), 5th char invalid [",      9, "_J9..[JHn" },
  { "*DES (BSDi), 6th char invalid [",      9, "_J9..M[Hn" },
  { "*DES (BSDi), 7th char invalid [",      9, "_J9..MJ[n" },
  { "*DES (BSDi), 8th char invalid [",      9, "_J9..MJH[" },
  { "*DES (BSDi), 1st char invalid {",      9, "_{9..MJHn" },
  { "*DES (BSDi), 2nd char invalid {",      9, "_J{..MJHn" },
  { "*DES (BSDi), 3rd char invalid {",      9, "_J9{.MJHn" },
  { "*DES (BSDi), 4th char invalid {",      9, "_J9.{MJHn" },
  { "*DES (BSDi), 5th char invalid {",      9, "_J9..{JHn" },
  { "*DES (BSDi), 6th char invalid {",      9, "_J9..M{Hn" },
  { "*DES (BSDi), 7th char invalid {",      9, "_J9..MJ{n" },
  { "*DES (BSDi), 8th char invalid {",      9, "_J9..MJH{" },
#endif
#if INCLUDE_md5crypt
  { "MD5 (FreeBSD)",                       12, "$1$MJHnaAke$" },
  { "*MD5 (FreeBSD) invalid char",         12, "$1$:JHnaAke$" },
#endif
#if INCLUDE_sunmd5
  { "MD5 (Sun, plain)",                    14, "$md5$1xMeE.at$"            },
  { "*MD5 (Sun, plain) invalid char",      14, "$md5$:xMeE.at$"            },
  { "MD5 (Sun, rounds)",                   25, "$md5,rounds=123$1xMeE.at$" },
  { "*MD5 (Sun, rounds) invalid char",     25, "$md5,rounds=123$:xMeE.at$" },
  { "*MD5 (Sun, rounds) invalid rounds 1", 25, "$md5,rounds=:23$1xMeE.at$" },
  { "*MD5 (Sun, rounds) invalid rounds 2", 25, "$md5,rounds=12:$1xMeE.at$" },
  { "*MD5 (Sun, rounds) invalid rounds 3", 25, "$md5,rounds:123$1xMeE.at$" },
  { "*MD5 (Sun, rounds) invalid rounds 4", 22, "$md5,rounds=$1xMeE.at$"    },
  { "*MD5 (Sun, rounds) invalid rounds 5", 23, "$md5,rounds=0$1xMeE.at$"   },
  { "*MD5 (Sun, rounds) invalid rounds 6", 25, "$md5,rounds=012$1xMeE.at$" },
  { "*MD5 (Sun, rounds) invalid rounds 7", 32, "$md5,rounds=4294967295$1xMeE.at$" },
#endif
#if INCLUDE_nt
  { "NTHASH (bare)",                        3, "$3$"                           },
  { "NTHASH (fake salt)",                   3, "$3$__not_used__c809a450df09a3" },
#endif
#if INCLUDE_sha1crypt
  { "HMAC-SHA1",                           27, "$sha1$123$GGXpNqoJvglVTkGU$" },
  { "*HMAC-SHA1 invalid char",             27, "$sha1$123$:GXpNqoJvglVTkGU$" },
  { "*HMAC-SHA1 invalid rounds 1",         27, "$sha1$:23$GGXpNqoJvglVTkGU$" },
  { "*HMAC-SHA1 invalid rounds 2",         27, "$sha1$12:$GGXpNqoJvglVTkGU$" },
  { "*HMAC-SHA1 invalid rounds 3",         27, "$sha1$12:$GGXpNqoJvglVTkGU$" },
#endif
#if INCLUDE_sha256crypt
  { "SHA-256 (plain)",                     20, "$5$MJHnaAkegEVYHsFK$"             },
  { "*SHA-256 (plain) invalid char",       20, "$5$:JHnaAkegEVYHsFK$"             },
  { "SHA-256 (rounds)",                    32, "$5$rounds=1000$MJHnaAkegEVYHsFK$" },
  { "*SHA-256 (rounds) invalid rounds 1",  32, "$5$rounds=:000$MJHnaAkegEVYHsFK$" },
  { "*SHA-256 (rounds) invalid rounds 2",  32, "$5$rounds=100:$MJHnaAkegEVYHsFK$" },
  { "*SHA-256 (rounds) invalid rounds 3",  32, "$5$rounds:1000$MJHnaAkegEVYHsFK$" },
  { "*SHA-256 (rounds) invalid rounds 4",  28, "$5$rounds=$MJHnaAkegEVYHsFK$" },
  { "*SHA-256 (rounds) invalid rounds 5",  29, "$5$rounds=0$MJHnaAkegEVYHsFK$" },
  { "*SHA-256 (rounds) invalid rounds 6",  32, "$5$rounds=0100$MJHnaAkegEVYHsFK$" },
  { "*SHA-256 (rounds) invalid rounds 7",  38, "$5$rounds=4294967295$MJHnaAkegEVYHsFK$" },
#endif
#if INCLUDE_sha512crypt
  { "SHA-512 (plain)",                     20, "$6$MJHnaAkegEVYHsFK$"             },
  { "*SHA-512 (plain) invalid char",       20, "$6$:JHnaAkegEVYHsFK$"             },
  { "SHA-512 (rounds)",                    32, "$6$rounds=1000$MJHnaAkegEVYHsFK$" },
  { "*SHA-512 (rounds) invalid rounds 1",  32, "$6$rounds=:000$MJHnaAkegEVYHsFK$" },
  { "*SHA-512 (rounds) invalid rounds 2",  32, "$6$rounds=100:$MJHnaAkegEVYHsFK$" },
  { "*SHA-512 (rounds) invalid rounds 3",  32, "$6$rounds:1000$MJHnaAkegEVYHsFK$" },
  { "*SHA-512 (rounds) invalid rounds 4",  28, "$6$rounds=$MJHnaAkegEVYHsFK$" },
  { "*SHA-512 (rounds) invalid rounds 5",  29, "$6$rounds=0$MJHnaAkegEVYHsFK$" },
  { "*SHA-512 (rounds) invalid rounds 6",  32, "$6$rounds=0100$MJHnaAkegEVYHsFK$" },
  { "*SHA-512 (rounds) invalid rounds 6",  38, "$6$rounds=4294967295$MJHnaAkegEVYHsFK$" },
#endif
#if INCLUDE_bcrypt
  { "bcrypt (b04)",                        29, "$2b$04$UBVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (b04) invalid char",          29, "$2b$04$:BVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (b04) invalid rounds 1",      29, "$2b$:4$UBVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (b04) invalid rounds 2",      29, "$2b$0:$UBVLHeMpJ/QQCv3XqJx8zO" },
#endif
#if INCLUDE_bcrypt_a
  { "bcrypt (a04)",                        29, "$2a$04$UBVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (a04) invalid char",          29, "$2a$04$:BVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (a04) invalid rounds 1",      29, "$2a$:4$UBVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (a04) invalid rounds 2",      29, "$2a$0:$UBVLHeMpJ/QQCv3XqJx8zO" },
#endif
#if INCLUDE_bcrypt_x
  { "bcrypt (x04)",                        29, "$2x$04$UBVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (x04) invalid char",          29, "$2x$04$:BVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (x04) invalid rounds 1",      29, "$2x$:4$UBVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (x04) invalid rounds 2",      29, "$2x$0:$UBVLHeMpJ/QQCv3XqJx8zO" },
#endif
#if INCLUDE_bcrypt_y
  { "bcrypt (y04)",                        29, "$2y$04$UBVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (y04) invalid char",          29, "$2y$04$:BVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (y04) invalid rounds 1",      29, "$2y$:4$UBVLHeMpJ/QQCv3XqJx8zO" },
  { "*bcrypt (y04) invalid rounds 2",      29, "$2y$0:$UBVLHeMpJ/QQCv3XqJx8zO" },
#endif
#if INCLUDE_yescrypt
  { "yescrypt",                            30, "$y$j9T$PKXc3hCOSyMqdaEQArI62/$" },
  { "*yescrypt invalid char 1",            30, "$y$j9T$:KXc3hCOSyMqdaEQArI62/$" },
  { "*yescrypt invalid char 2",            18, "$y$j9T$PKXc:hCOS$" },
  { "*yescrypt invalid params 1",          30, "$y$:9T$PKXc3hCOSyMqdaEQArI62/$" },
  { "*yescrypt invalid params 2",          30, "$y$j:T$PKXc3hCOSyMqdaEQArI62/$" },
  { "*yescrypt invalid params 3",          30, "$y$j9:$PKXc3hCOSyMqdaEQArI62/$" },
  { "*yescrypt invalid params 4",          30, "$y$$9T$PKXc3hCOSyMqdaEQArI62/$" },
  { "*yescrypt invalid params 5",          30, "$y$j$:$PKXc3hCOSyMqdaEQArI62/$" },
  { "*yescrypt invalid params 6",          30, "$y$j9$$PKXc3hCOSyMqdaEQArI62/$" },
#endif
#if INCLUDE_scrypt
  { "scrypt",                              29, "$7$C6..../....SodiumChloride$" },
  { "*scrypt invalid char",                29, "$7$C6..../....:odiumChloride$" },
  { "*scrypt invalid params  1",           29, "$7$:6..../....SodiumChloride$" },
  { "*scrypt invalid params  2",           29, "$7$C:..../....SodiumChloride$" },
  { "*scrypt invalid params  3",           29, "$7$C6:.../....SodiumChloride$" },
  { "*scrypt invalid params  4",           29, "$7$C6.:../....SodiumChloride$" },
  { "*scrypt invalid params  5",           29, "$7$C6..:./....SodiumChloride$" },
  { "*scrypt invalid params  6",           29, "$7$C6...:/....SodiumChloride$" },
  { "*scrypt invalid params  7",           29, "$7$C6....:....SodiumChloride$" },
  { "*scrypt invalid params  8",           29, "$7$C6..../:...SodiumChloride$" },
  { "*scrypt invalid params  9",           29, "$7$C6..../.:..SodiumChloride$" },
  { "*scrypt invalid params 10",           29, "$7$C6..../..:.SodiumChloride$" },
  { "*scrypt invalid params 11",           29, "$7$C6..../...:SodiumChloride$" },
  { "*scrypt invalid params 12",           29, "$7$$:..../....SodiumChloride$" },
  { "*scrypt invalid params 13",           29, "$7$C$:.../....SodiumChloride$" },
  { "*scrypt invalid params 14",           29, "$7$C6.$:./....SodiumChloride$" },
  { "*scrypt invalid params 15",           29, "$7$C6..../.$:.SodiumChloride$" },
#endif
#if INCLUDE_gost_yescrypt
  { "gost-yescrypt",                       31, "$gy$j9T$PKXc3hCOSyMqdaEQArI62/$" },
  { "*gost-yescrypt invalid char 1",       31, "$gy$j9T$:KXc3hCOSyMqdaEQArI62/$" },
  { "*gost-yescrypt invalid char 2",       19, "$gy$j9T$PKXc:hCOS$" },
  { "*gost-yescrypt invalid params 1",     31, "$gy$:9T$PKXc3hCOSyMqdaEQArI62/$" },
  { "*gost-yescrypt invalid params 2",     31, "$gy$j:T$PKXc3hCOSyMqdaEQArI62/$" },
  { "*gost-yescrypt invalid params 3",     31, "$gy$j9:$PKXc3hCOSyMqdaEQArI62/$" },
  { "*gost-yescrypt invalid params 4",     31, "$gy$$9T$PKXc3hCOSyMqdaEQArI62/$" },
  { "*gost-yescrypt invalid params 5",     31, "$gy$j$:$PKXc3hCOSyMqdaEQArI62/$" },
  { "*gost-yescrypt invalid params 6",     31, "$gy$j9$$PKXc3hCOSyMqdaEQArI62/$" },
#endif
};

static bool
check_results (const char *label, const char *fn,
               const char *retval, const char *setting,
               bool expected_to_succeed)
{
  size_t l_setting = strlen (setting);
  if (expected_to_succeed)
    {
      if (retval[0] == '*' ||
          strncmp (retval, setting,
                   (setting[l_setting - 1] == '*') ? l_setting - 1 : l_setting))
        {
          printf ("FAIL: %s/%s/%s: expected success, got non-matching %s\n",
                  label, setting, fn, retval);
          return false;
        }
    }
  else
    {
      if (retval[0] != '*' ||
          (l_setting >= 2 && !strncmp (retval, setting, l_setting)))
        {
          printf ("FAIL: %s/%s/%s: expected failure, got %s\n",
                  label, setting, fn, retval);
          return false;
        }
    }
  return true;
}

static bool
check_crypt (const char *label, const char *fn,
             const char *retval, const char *setting,
             bool expected_to_succeed)
{
#if ENABLE_FAILURE_TOKENS
  /* crypt/crypt_r never return null when failure tokens are enabled */
  if (!retval)
    {
      printf ("FAIL: %s/%s/%s: returned NULL\n", label, setting, fn);
      return false;
    }
#else
  if (expected_to_succeed && !retval)
    {
      printf ("FAIL: %s/%s/%s: returned NULL\n", label, setting, fn);
      return false;
    }
  else if (!expected_to_succeed && retval)
    {
      printf ("FAIL: %s/%s/%s: returned %p, should be NULL\n",
              label, setting, fn, (const void *)retval);
      return false;
    }
  else if (!expected_to_succeed && !retval)
    return true;
#endif
  if (!check_results (label, fn, retval, setting,
                      expected_to_succeed))
    return false;
  return true;
}

static bool
check_crypt_rn (const char *label, const char *fn,
                const char *retval, const char *output,
                const char *setting, bool expected_to_succeed)
{
  bool ok = true;
  if (expected_to_succeed)
    {
      if (!retval)
        {
          printf ("FAIL: %s/%s/%s: returned NULL\n", label, setting, fn);
          ok = false;
        }
      else if (retval != output)
        {
          printf ("FAIL: %s/%s/%s: returned %p but output is %p\n",
                  label, setting, fn,
                  (const void *)retval, (const void *)output);
          ok = false;
        }
    }
  else
    {
      if (retval)
        {
          printf ("FAIL: %s/%s/%s: returned %p (output is %p), "
                  "should be NULL\n",
                  label, setting, fn,
                  (const void *)retval, (const void *)output);
          ok = false;
        }
    }
  if (!check_results (label, fn, output, setting,
                      expected_to_succeed))
    ok = false;
  return ok;
}

static bool
test_one_setting (const char *label, const char *setting,
                  struct crypt_data *cd, bool expected_to_succeed)
{
  bool ok = true;
  const char *retval;
  int cdsize = (int) sizeof (struct crypt_data);
#ifdef VERBOSE
  printf ("%s: testing %s (expect: %s)\n", label, setting,
          expected_to_succeed ? "succeed" : "fail");
#endif
  retval = crypt (phrase, setting);
  if (!check_crypt (label, "crypt", retval, setting, expected_to_succeed))
    ok = false;

  retval = crypt_r (phrase, setting, cd);
  if (!check_crypt (label, "crypt_r", retval, setting, expected_to_succeed))
    ok = false;

  retval = crypt_rn (phrase, setting, cd, cdsize);
  if (!check_crypt_rn (label, "crypt_rn", retval, cd->output,
                       setting, expected_to_succeed))
    ok = false;

  retval = crypt_ra (phrase, setting, (void **)&cd, &cdsize);
  if (!check_crypt_rn (label, "crypt_ra", retval, cd->output,
                       setting, expected_to_succeed))
    ok = false;
  return ok;
}

static bool
test_one_case (const struct testcase *t,
               char *page, size_t pagesize,
               struct crypt_data *cd)
{
  memset (page, 'a', pagesize);

  size_t l_setting = strlen (t->setting);
  assert (l_setting <= pagesize);
  if (t->label[0] == '*')
    {
      /* Hashing with this setting is expected to fail already.
         We still want to verify that we do not read past the end of
         the string.  */
      char *p = page + pagesize - (l_setting + 1);
      memcpy (p, t->setting, l_setting + 1);
      if (!test_one_setting (t->label + 1, p, cd, false))
        return false;
      printf ("PASS: %s\n", t->label + 1);
      return true;
    }
  else
    {
      /* Hashing with this setting is expected to succeed.  */
      char goodhash[CRYPT_OUTPUT_SIZE];
      char *result = crypt_rn (phrase, t->setting, cd,
                               sizeof (struct crypt_data));
      if (!result)
        {
          printf ("FAIL: %s: initial hash returned NULL/%s (%s)\n",
                  t->label, cd->output, strerror (errno));
          return false;
        }

      size_t l_hash = strlen (result);
      assert (l_hash + 1 <= CRYPT_OUTPUT_SIZE);

      memcpy (goodhash, result, l_hash + 1);

      char *p = page + pagesize - (l_hash + 1);
      memcpy (p, goodhash, l_hash + 1);

      /* Rechecking the hash with the full output should succeed.  */
      if (!test_one_setting (t->label, p, cd, true))
        return false;

      /* Recomputing the hash with its own prefix should produce a
         hash with the same prefix.  */
      p = page + pagesize - (t->plen + 1);
      memcpy (p, goodhash, t->plen);
      p[t->plen] = '\0';
      if (!test_one_setting (t->label, p, cd, true))
        return false;

      /* An invalid character after the prefix should not affect the
         result of the hash computation.  */
      p = page + pagesize - (t->plen + 2);
      memcpy (p, goodhash, t->plen);
      p[t->plen] = '*';
      p[t->plen+1] = '\0';
      if (!test_one_setting (t->label, p, cd, true))
        return false;

      /* However, an invalid character anywhere within the prefix should
         cause hashing to fail.  */
      size_t plen = t->plen;

      /* des_big only values the first two characters of the setting,
         but needs strlen(setting) >= 14.  */
      const char *des_big_label = "DES (bigcrypt)";
      if (!strcmp (t->label, des_big_label))
        {
          plen = 2;
        }
      for (size_t i = 1; i < plen; i++)
        {
          p = page + pagesize - (plen + 2 - i);
          memcpy (p, goodhash, plen - i);
          if (!test_one_setting (t->label, p, cd, false))
            return false;
        }
      printf ("PASS: %s\n", t->label);
      return true;
    }
}

int
main (void)
{
  /* Set up a two-page region whose first page is read-write and
     whose second page is inaccessible.  */
  size_t pagesize = (size_t) sysconf (_SC_PAGESIZE);
  char *page = mmap (0, pagesize * 2, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANON, -1, 0);
  if (page == MAP_FAILED)
    {
      perror ("mmap");
      return 1;
    }
  memset (page, 'x', pagesize * 2);
  if (mprotect (page + pagesize, pagesize, PROT_NONE))
    {
      perror ("mprotect");
      return 1;
    }

  struct crypt_data cd;
  memset (&cd, 0, sizeof cd);

  bool ok = true;
  for (size_t i = 0; i < ARRAY_SIZE (testcases); i++)
    if (!test_one_case (&testcases[i], page, pagesize, &cd))
      ok = false;

  return ok ? 0 : 1;
}

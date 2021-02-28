/* Benchmark hashing methods and set cost parameters appropriately.
 *
 * Written by Zack Weinberg <zackw at panix.com> in 2018.
 * To the extent possible under law, the named authors have waived all
 * copyright and related or neighboring rights to this work.
 *
 * See https://creativecommons.org/publicdomain/zero/1.0/ for further
 * details.
 */

#include "crypt-port.h"

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

enum hash_usage
{
  HU_PREFER, HU_ENABLED, HU_LEGACY, HU_DISABLED
};

static const char *const usage_keyword[] = {
  "preferred", "enabled", "legacy", "disabled"
};

enum hash_cost_type
{
  HCT_EXPON, HCT_LINEAR, HCT_FIXED
};

struct hash_method
{
  const char *name;
  const char *prefix;
  enum hash_cost_type hct;
  unsigned int minrounds;
  unsigned int maxrounds;
  enum hash_usage usage;
  unsigned int nrounds;
  double elapsed;
};

/* The 'usage', 'nrounds', and 'elapsed' fields of this table are
   written to during execution.  */
static struct hash_method hash_methods[] = {
  { "yescrypt",      "$y$",   HCT_EXPON,  1,    11,         HU_PREFER,   0, 0 },
  { "gost-yescrypt", "$gy$",  HCT_EXPON,  1,    11,         HU_ENABLED,  0, 0 },
  { "scrypt",        "$7$",   HCT_EXPON,  6,    11,         HU_ENABLED,  0, 0 },
  { "bcrypt",        "$2b$",  HCT_EXPON,  4,    31,         HU_ENABLED,  0, 0 },
  { "bcrypt_a",      "$2a$",  HCT_EXPON,  4,    31,         HU_LEGACY,   0, 0 },
  { "bcrypt_x",      "$2x$",  HCT_EXPON,  4,    31,         HU_LEGACY,   0, 0 },
  { "bcrypt_y",      "$2y$",  HCT_EXPON,  4,    31,         HU_LEGACY,   0, 0 },
  { "sha512crypt",   "$6$",   HCT_LINEAR, 1000, 999999999,  HU_ENABLED,  0, 0 },
  { "sha256crypt",   "$5$",   HCT_LINEAR, 1000, 999999999,  HU_ENABLED,  0, 0 },
  { "sha1crypt",     "$sha1", HCT_LINEAR, 4,    4294967295, HU_LEGACY,   0, 0 },
  { "sunmd5",        "$md5",  HCT_LINEAR, 4096, 4294963199, HU_LEGACY,   0, 0 },
  { "md5crypt",      "$1$",   HCT_FIXED,  0,    0,          HU_LEGACY,   0, 0 },
  { "bsdicrypt",     "_",     HCT_LINEAR, 1,    16777215,   HU_DISABLED, 0, 0 },
  { "bigcrypt",      "",      HCT_FIXED,  0,    0,          HU_DISABLED, 0, 0 },
  { "descrypt",      "",      HCT_FIXED,  0,    0,          HU_DISABLED, 0, 0 },
  { "nt",            "$3$",   HCT_FIXED,  0,    0,          HU_DISABLED, 0, 0 },
};

static const char *program_name;
static int verbosity = 0;

static double
time_crypt (struct hash_method *method, unsigned int nrounds)
{
  /* We use 32 bytes of zeroes for the randomness because some hash
     methods' gensalt routines use the randomness to perturb the
     rounds parameter as well, which makes linear approximation not
     work like it ought to.  */
  static const char rbytes[32] = { 0 };
  static const char phrase[] =
    "it has been 39 days since our last pie-related accident";

  char setting[CRYPT_GENSALT_OUTPUT_SIZE];
  if (crypt_gensalt_rn (method->prefix, nrounds, rbytes, (int) sizeof rbytes,
                        setting, (int) sizeof setting) != setting)
    {
      fprintf (stderr, "%s: crypt_gensalt_rn: %s\n",
               method->name, strerror (errno));
      return 0.0;
    }

  if (verbosity >= 3)
    fprintf (stderr, "# %s: setting %s\n", method->name, setting);

  struct crypt_data data;
  memset (&data, 0, sizeof data);

  /* Reduce jitter for small rounds parameters by repeating the
     crypt_rn call until we have consumed at least 10ms total.  */
  double elapsed = 0.0;
  unsigned int iterations = 0;
  do
    {
      struct timespec start, stop;

      if (clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &start))
        {
          fprintf (stderr, "%s: clock_gettime: %s\n",
                   method->name, strerror (errno));
          return 0.0;
        }

      if (crypt_rn (phrase, setting, &data, (int) sizeof data) == 0)
        {
          fprintf (stderr, "%s: crypt_rn: %s\n",
                   method->name, strerror (errno));
          return 0.0;
        }

      if (clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &stop))
        {
          fprintf (stderr, "%s: clock_gettime: %s\n",
                   method->name, strerror (errno));
          return 0.0;
        }

      /* explicit casts silence -Wconversion */
      elapsed += ((double)(stop.tv_sec - start.tv_sec)
                  + ((double)stop.tv_nsec) * 1e-9
                  - ((double)start.tv_nsec) * 1e-9) * 1000;
      iterations++;
    }
  while (elapsed < 10.0);
  elapsed /= iterations;

  if (verbosity >= 1)
    fprintf (stderr, "# %s: %6.2fms for %u rounds (%u iteration%s)\n",
             method->name, elapsed, nrounds, iterations,
             iterations == 1 ? "" : "s");

  return elapsed;
}

/* Given vectors X and Y, find scalars m and b that robustly fit a
   line through all of the points (x_i, y_i).  It is assumed that
   there are no duplicates among the x_i.  Since this function is only
   ever called with n <= 10 (see below), we can get away with the
   naive quadratic algorithm for computing the Thiel-Sen estimator.

   Simpler methods (basic successive approximation, ordinary least
   squares) were tried but found to converge too slowly, because the
   measurement for a small cost parameter (near minrounds) tends to be
   noisy and thus a poor estimate of the required cost parameter.  The
   primary design goal here is to minimize the number of approximation
   iterations using a large cost parameter, since that's what dominates
   runtime.  */

static int
compar_double(const void *a, const void *b)
{
  double x = *(const double *)a;
  double y = *(const double *)b;
  if (x < y) return -1;
  if (x > y) return 1;
  return 0;
}

static void
robust_linear_approx(const double *restrict xs,
                     const double *restrict ys,
                     size_t n,
                     double *restrict m_out,
                     double *restrict b_out)
{
  assert (1 <= n && n <= 10);
  double m, b;
  if (n == 1)
    {
      /* If we only have one point in the sample, make the line go
         through the origin.  */
      m = ys[0] / xs[0];
      b = 0;
    }
  else
    {
      double slopes[100];
      size_t nslopes = 0;
      for (size_t i = 0; i < n; i++)
        for (size_t j = i + 1; j < n; j++)
          slopes[nslopes++] = (ys[j] - ys[i]) / (xs[j] - xs[i]);
      qsort (slopes, nslopes, sizeof (double), compar_double);

      m = slopes[nslopes / 2];

      double resid[10];
      for (size_t i = 0; i < n; i++)
        resid[i] = ys[i] - m*xs[i];
      qsort (resid, n, sizeof (double), compar_double);
      b = resid[n / 2];
    }

  if (verbosity >= 2)
    {
      double tau = 0.0;
      if (n >= 2)
        {
          for (size_t i = 0; i < n; i++)
            for (size_t j = i + 1; j < n; j++)
              {
                double ri = ys[i] - (m * xs[i] + b);
                double rj = ys[j] - (m * xs[j] + b);
                double sr = (ri == rj) ? 0 : (ri < rj) ? -1 : 1;
                double sx = (xs[i] == xs[j]) ? 0 : (xs[i] < xs[j]) ? -1 : 1;
                tau += sr * sx;
              }
          tau = (tau * 2) / (double)(n * (n - 1));
        }
      fprintf (stderr,
               "# T-S (%zu point%s): y = %6.2f * x + %6.2f, resid. tau = %.4f\n",
               n, n == 1 ? "" : "s", m, b, tau);
    }

  *m_out = m;
  *b_out = b;
}

static void
tune_linear_cost (struct hash_method *method, double elapsed_target)
{
  /* One of the linear methods requires the number of rounds to be
     odd; rather than special case it, we use only odd numbers for
     all methods.  */
  unsigned int minrounds, maxrounds, nrounds;
  minrounds = method->minrounds;
  if (minrounds % 2 == 0)
    minrounds++;

  maxrounds = method->maxrounds;
  if (maxrounds % 2 == 0)
    maxrounds--;

  /* Start from near, but not actually at, the bottom.  */
  nrounds = 10001;
  if (nrounds < minrounds)
    nrounds = minrounds;
  if (nrounds > maxrounds)
    nrounds = maxrounds;

  /* Record up to the previous ten measurements in a circular
     buffer.  */
  size_t npoints = 0, ipoints = 0;
  double ns[10], es[10];
  double elapsed;
  unsigned int new_nrounds;

  for (;;)
    {
      elapsed = time_crypt (method, nrounds);
      if (elapsed < elapsed_target)
        minrounds = nrounds;
      else if (elapsed > 1.025 * elapsed_target)
        maxrounds = nrounds;
      else
        /* We're within 2.5%, that's good enough.  */
        break;

      /* If there is no remaining room for adjustment, stop.  */
      if (minrounds + 2 >= maxrounds)
        break;

      ns[ipoints] = nrounds;
      es[ipoints] = elapsed;
      ipoints = (ipoints + 1) % ARRAY_SIZE (ns);
      npoints = MIN (npoints + 1, ARRAY_SIZE (ns));

      /* Predicting nrounds as a function of elapsed, instead of the
         other way around, means we don't need to invert the result to
         pick the next value of nrounds.  */
      double m, b;
      robust_linear_approx (es, ns, npoints, &m, &b);

      new_nrounds = (unsigned int)(m * elapsed_target + b);
      new_nrounds |= 1;

      /* If the new estimate is the same as the value we just tried,
         go up or down by two, depending on whether we're below or
         above the target. */
      if (new_nrounds == nrounds)
        {
          if (elapsed < elapsed_target)
            new_nrounds += 2;
          else
            new_nrounds -= 2;
        }
      if (new_nrounds > maxrounds)
        new_nrounds = maxrounds;
      if (new_nrounds < minrounds)
        new_nrounds = minrounds;

      nrounds = new_nrounds;
    }

  method->nrounds = nrounds;
  method->elapsed = elapsed;
}

static void
tune_expon_cost (struct hash_method *method, double elapsed_target)
{
  unsigned int minrounds, maxrounds, nrounds;
  minrounds = method->minrounds;
  maxrounds = method->maxrounds;

  /* Start from the bottom.  */
  nrounds = minrounds;

  /* Record up to the previous ten measurements in a circular buffer.
     Log-transform the elapsed times so we can fit the cost-time
     relationship linearly.  (The base of the logarithm doesn't
     matter; it just changes the slope of the line, and that cancels
     back out when we predict the desired cost value.)  */
  size_t npoints = 0, ipoints = 0;
  double ns[10], es[10];
  double elapsed;
  double log_elapsed_target = log (elapsed_target);
  unsigned int new_nrounds;

  for (;;)
    {
      /* If we overshoot by too much the program may appear to hang, so
         report the number of rounds first to give the user an idea of
         what might be wrong.  */
      if (verbosity >= 1)
        fprintf (stderr, "# %s: trying %u rounds\n", method->name, nrounds);
      elapsed = time_crypt (method, nrounds);
      double log_elapsed = log (elapsed);
      if (log_elapsed < log_elapsed_target)
        minrounds = nrounds;
      else if (log_elapsed > 1.025 * log_elapsed_target)
        maxrounds = nrounds;
      else
        /* We're within 2.5%, that's good enough.  */
        break;

      /* If there is no remaining room for adjustment, stop.  */
      if (minrounds + 1 >= maxrounds)
        break;

      ns[ipoints] = nrounds;
      es[ipoints] = log (elapsed);
      ipoints = (ipoints + 1) % ARRAY_SIZE (ns);
      npoints = MIN (npoints + 1, ARRAY_SIZE (ns));

      if (npoints == 1)
        {
          /* Just go up by one; the prediction with a single point
             will be garbage, because we can't estimate the intercept.  */
          new_nrounds = nrounds + 1;
        }
      else
        {
          /* Predicting nrounds as a function of elapsed, instead of the
             other way around, means we don't need to invert the result to
             pick the next value of nrounds.  */
          double m, b;
          robust_linear_approx (es, ns, npoints, &m, &b);

          new_nrounds = (unsigned int)(m * log_elapsed_target + b);
        }

      /* If the new estimate is the same as the value we just tried,
         go up or down by one, depending on whether we're below or
         above the target. */
      if (new_nrounds == nrounds)
        {
          if (elapsed < elapsed_target)
            new_nrounds++;
          else
            new_nrounds--;
        }
      if (new_nrounds > maxrounds)
        new_nrounds = maxrounds;
      if (new_nrounds < minrounds)
        new_nrounds = minrounds;

      nrounds = new_nrounds;
    }

  method->elapsed = elapsed;
  method->nrounds = nrounds;
}

static void
tune_cost (struct hash_method *method, double elapsed_target, bool strict)
{
  if (method->usage == HU_LEGACY || method->usage == HU_DISABLED)
    {
      if (verbosity >= 1)
        fprintf (stderr, "# %s: %s, skipping\n",
                 method->name, usage_keyword[method->usage]);
      return;
    }
  if (method->hct == HCT_FIXED)
    {
      if (verbosity >= 1)
        fprintf (stderr, "# %s: fixed cost\n", method->name);
      method->nrounds = 0;
      method->elapsed = time_crypt (method, 0);
    }
  else if (method->hct == HCT_LINEAR)
    {
      if (verbosity >= 1)
        fprintf (stderr, "# %s: linear cost\n", method->name);
      tune_linear_cost (method, elapsed_target);
    }
  else /* HCT_EXPON */
    {
      if (verbosity >= 1)
        fprintf (stderr, "# %s: exponential cost\n", method->name);
      tune_expon_cost (method, elapsed_target);
    }

  if (method->elapsed < elapsed_target)
    method->usage = strict ? HU_DISABLED : HU_LEGACY;
}

static void
tune_all_costs (double elapsed_target, bool strict)
{
  size_t i;
  for (i = 0; i < ARRAY_SIZE (hash_methods); i++)
    tune_cost (&hash_methods[i], elapsed_target, strict);

  /* Make sure that at least one hashing method is still enabled, and
     one hashing method is preferred.  */
  static_assert (ARRAY_SIZE (hash_methods) <= INT_MAX,
                 "too many hash methods for 'int'");
  int first_enabled = -1;

  for (i = 0; i < ARRAY_SIZE (hash_methods); i++)
    if (hash_methods[i].usage == HU_PREFER)
      return;
    else if (hash_methods[i].usage == HU_ENABLED && first_enabled == -1)
      first_enabled = (int)i;

  /* If we get here, no method was preferred.
     Are there any enabled methods at all?  */
  if (first_enabled == -1)
    {
      fprintf (stderr, "%s: no enabled hashing method can take %6.2fms\n",
               program_name, elapsed_target);
      exit (1);
    }

  /* The hash_methods table is in descending order of cryptographic
     strength, so when no explicit selection was made, use the first
     method that's enabled as the preferred method.  */
  hash_methods[first_enabled].usage = HU_PREFER;
}

static void
write_config (void)
{
  fputs ("# crypt.conf generated by crypt-tune-costs.\n"
         "# Rounds settings are tuned for this computer.\n\n",
         stdout);
  for (size_t i = 0; i < ARRAY_SIZE (hash_methods); i++)
    if (hash_methods[i].nrounds != 0)
      printf ("%-12s%-12srounds=%u\t# %6.2fms\n",
              hash_methods[i].name,
              usage_keyword[hash_methods[i].usage],
              hash_methods[i].nrounds,
              hash_methods[i].elapsed);
    else
      printf ("%-12s%s\n",
              hash_methods[i].name,
              usage_keyword[hash_methods[i].usage]);

  if (fflush (stdout) || fclose (stdout))
    {
      fprintf (stderr, "%s: stdout: %s\n", program_name, strerror (errno));
      exit (1);
    }
}

static NORETURN PRINTF_FMT(1,0)
print_usage (const char *errmsg, ...)
{
  FILE *dest;
  if (errmsg)
    {
      va_list ap;
      fprintf (stderr, "%s: ", program_name);
      va_start (ap, errmsg);
      vfprintf (stderr, errmsg, ap);
      va_end (ap);
      fputc ('\n', stderr);
      dest = stderr;
    }
  else
    dest = stdout;

  fprintf (dest, "Usage: %s [OPTION]...\n", program_name);
  fputs ("Choose cost parameters for passphrase hashing.\n"
"Writes a tuned crypt.conf to stdout.\n"
"\n"
"  -t MS, --time=MS               Try to make each hashing method take MS\n"
"                                 milliseconds (default 250).\n"
"  -p METHOD, --preferred=METHOD  Use METHOD as the preferred method for\n"
"                                 hashing new passphrases.\n"
"  -e M,M,...; --enabled=M,M,...  Allow each method M both for hashing new\n"
"                                 passphrases and for authentication against\n"
"                                 existing hashes.\n"
"  -l M,M,...; --legacy=M,M,...   Allow each method M only for authentication\n"
"                                 against existing hashes, and don't bother\n"
"                                 choosing cost parameters for them.\n"
"  -d M,M,...; --disabled=M,M,... Don't allow each method M to be used at all.\n"
"  -s, --strict                   Disable methods that cannot be made to take\n"
"                                 the specified amount of time, instead of\n"
"                                 allowing them for authentication against\n"
"                                 existing hashes.\n"
"  -v, --verbose                  Report on the process of searching for\n"
"                                 appropriate cost parameters, to stderr.\n"
"                                 Repeat -v to increase verbosity level.\n"
"\n"
"  -h, --help                     Display this help message and exit.\n"
"  -V, --version                  Output version information and exit.\n"
"\n"
"For complete documentation, 'man crypt-tune-costs'.\n"
         , dest);

  fprintf (dest, "xcrypt homepage: %s\n", PACKAGE_URL);
  exit (errmsg ? 1 : 0);
}

static NORETURN
print_version (void)
{
  printf ("%s (%s) %s\n"
          "Homepage: %s\n"
          "This is free software: you are free to change and redistribute it.\n"
          "There is NO WARRANTY, to the extent permitted by law.\n",
          program_name, PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_URL);
  exit (0);
}

static void
parse_time (char *text, double *value_p)
{
  char *endp;
  double result;

  errno = 0;
  result = strtod (text, &endp);
  if (endp == text || *endp != '\0')
    print_usage ("malformed argument for '--time' (must be a decimal number)");
  if (errno || result <= 0 || result >= 10 * 1000 || result != result)
    print_usage ("argument for '--time' out of range (> 0, < 10,000 ms)");

  *value_p = result;
}

static void
parse_hash_usage (char *text, enum hash_usage usage)
{
  if (!strcmp (text, "all"))
    {
      for (size_t i = 0; i < ARRAY_SIZE (hash_methods); i++)
        hash_methods[i].usage = usage;
    }
  else
    for (char *tok = strtok (text, ","); tok; tok = strtok (0, ","))
      {
        bool found = false;
        for (size_t i = 0; i < ARRAY_SIZE (hash_methods); i++)
          if (!strcmp (tok, hash_methods[i].name))
            {
              found = true;
              hash_methods[i].usage = usage;
              break;
            }
        if (!found)
          print_usage ("unrecognized hash method name '%s'", tok);
      }
}

/* Macro subroutines of parse_command_line.  */

#define LONG_OPTION(name, action)                               \
  do {                                                          \
    if (!strcmp (argv[i] + 2, name))                            \
      {                                                         \
        action;                                                 \
        goto next_arg;                                          \
      }                                                         \
  } while (0)

#define LONG_OPTION_WITH_ARG(name, parse_arg, ...)              \
  do {                                                          \
    if (!strncmp (argv[i] + 2, name, sizeof name - 1))          \
      {                                                         \
        char *optarg = argv[i] + 2 + sizeof name - 1;           \
        if (optarg[0] == '=' && optarg[1] != '\0')              \
          {                                                     \
            parse_arg (optarg + 1, __VA_ARGS__);                \
            goto next_arg;                                      \
          }                                                     \
        else if (optarg[0] == '\0' && i + 1 < argc)             \
          {                                                     \
            i++;                                                \
            parse_arg (argv[i], __VA_ARGS__);                   \
            goto next_arg;                                      \
          }                                                     \
        else if ((optarg[0] == '=' && optarg[1] == '\0') ||     \
                 (optarg[0] == '\0' && i + 1 >= argc))          \
          {                                                     \
            print_usage ("'--%s' requires an argument", name);  \
          }                                                     \
        else                                                    \
          print_usage ("unrecognized option '%s'", argv[i]);    \
      }                                                         \
  } while (0)

#define SHORT_OPTION(letter, action)                            \
  do {                                                          \
    if (argv[i][j] == letter)                                   \
      {                                                         \
        action;                                                 \
        goto next_char;                                         \
      }                                                         \
  } while (0)

#define SHORT_OPTION_WITH_ARG(letter, parse_arg, ...)           \
  do {                                                          \
    if (argv[i][j] == letter)                                   \
      {                                                         \
        if (argv[i][j+1] != '\0')                               \
          {                                                     \
            parse_arg (argv[i] + j + 1, __VA_ARGS__);           \
            goto next_arg;                                      \
          }                                                     \
        else if (i + 1 < argc)                                  \
          {                                                     \
            i++;                                                \
            parse_arg (argv[i], __VA_ARGS__);                   \
            goto next_arg;                                      \
          }                                                     \
        else                                                    \
          print_usage ("'-%c' requires an argument", letter);   \
      }                                                         \
  } while (0)

static void
parse_command_line (int argc, char **argv,
                    double *elapsed_target_p, bool *strict_p)
{
  for (int i = 1; i < argc; i++)
    {
      if (argv[i][0] != '-' || argv[i][1] == '\0')
        print_usage ("no non-option arguments are accepted");

      if (argv[i][1] == '-')
        {
          LONG_OPTION ("strict",  (*strict_p = true));
          LONG_OPTION ("verbose", (verbosity++));
          LONG_OPTION ("version", (print_version ()));
          LONG_OPTION ("help",    (print_usage (0)));

          LONG_OPTION_WITH_ARG ("time", parse_time, elapsed_target_p);
          LONG_OPTION_WITH_ARG ("preferred", parse_hash_usage, HU_PREFER);
          LONG_OPTION_WITH_ARG ("enabled", parse_hash_usage, HU_ENABLED);
          LONG_OPTION_WITH_ARG ("legacy", parse_hash_usage, HU_LEGACY);
          LONG_OPTION_WITH_ARG ("disabled", parse_hash_usage, HU_DISABLED);

          print_usage ("unrecognized option '%s'", argv[i]);
        }
      else
        for (int j = 1; argv[i][j]; j++)
          {
            SHORT_OPTION ('s', (*strict_p = true));
            SHORT_OPTION ('v', (verbosity++));
            SHORT_OPTION ('V', (print_version ()));
            SHORT_OPTION ('h', (print_usage (0)));

            SHORT_OPTION_WITH_ARG ('t', parse_time, elapsed_target_p);
            SHORT_OPTION_WITH_ARG ('p', parse_hash_usage, HU_PREFER);
            SHORT_OPTION_WITH_ARG ('e', parse_hash_usage, HU_ENABLED);
            SHORT_OPTION_WITH_ARG ('l', parse_hash_usage, HU_LEGACY);
            SHORT_OPTION_WITH_ARG ('d', parse_hash_usage, HU_DISABLED);

            print_usage ("unrecognized option '-%c'", argv[i][j]);

          next_char:;
          }
    next_arg:;
    }

  /* Sanity check the effects of the various method-configuration options.  */
  int n_preferred = 0;
  int n_enabled = 0;
  for (size_t i = 0; i < ARRAY_SIZE (hash_methods); i++)
    {
      if (hash_methods[i].usage == HU_PREFER)
        {
          n_preferred++;
          n_enabled++;
        }
      else if (hash_methods[i].usage == HU_ENABLED)
        n_enabled++;
    }
  if (n_enabled == 0)
    print_usage ("no hashing methods are enabled");
  if (n_preferred > 1)
    print_usage ("only one hashing method can be preferred");
}
#undef LONG_OPTION
#undef LONG_OPTION_WITH_ARG
#undef SHORT_OPTION
#undef SHORT_OPTION_WITH_ARG

int
main (int argc, char **argv)
{
  if (argc > 0)
    {
      program_name = strrchr (argv[0], '/');
      if (program_name)
        program_name += 1;
      else
        program_name = argv[0];
    }
  if (program_name[0] == 0)
    program_name = "crypt-tune-costs";

  double elapsed_target = 250.0; /* milliseconds */
  bool strict = false;
  parse_command_line (argc, argv, &elapsed_target, &strict);
  tune_all_costs (elapsed_target, strict);
  write_config ();
  return 0;
}

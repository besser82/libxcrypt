/*
 * Written by Solar Designer <solar at openwall.com> in 2000-2014.
 * No copyright is claimed, and the software is hereby placed in the public
 * domain.  In case this attempt to disclaim copyright and place the software
 * in the public domain is deemed null and void, then the software is
 * Copyright (c) 2000-2014 Solar Designer and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * See crypt_blowfish.c for more information.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include <pthread.h>

#define CRYPT_OUTPUT_SIZE		(7 + 22 + 31 + 1)
#define CRYPT_GENSALT_OUTPUT_SIZE	(7 + 22 + 1)

#include "crypt.h"

static const char *tests[][3] = {
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
		"U*U"},
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
		"U*U*"},
	{"$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
		"U*U*U"},
	{"$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
		"0123456789abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		"chars after 72 are ignored"},
	{"$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e",
		"\xa3"},
	{"$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e",
		"\xff\xff\xa3"},
	{"$2y$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e",
		"\xff\xff\xa3"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.nqd1wy.pTMdcvrRWxyiGL2eMz.2a85.",
		"\xff\xff\xa3"},
	{"$2b$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e",
		"\xff\xff\xa3"},
	{"$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq",
		"\xa3"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq",
		"\xa3"},
	{"$2b$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq",
		"\xa3"},
	{"$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi",
		"1\xa3" "345"},
	{"$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi",
		"\xff\xa3" "345"},
	{"$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi",
		"\xff\xa3" "34" "\xff\xff\xff\xa3" "345"},
	{"$2y$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi",
		"\xff\xa3" "34" "\xff\xff\xff\xa3" "345"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.ZC1JEJ8Z4gPfpe1JOr/oyPXTWl9EFd.",
		"\xff\xa3" "34" "\xff\xff\xff\xa3" "345"},
	{"$2y$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e",
		"\xff\xa3" "345"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e",
		"\xff\xa3" "345"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS",
		"\xa3" "ab"},
	{"$2x$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS",
		"\xa3" "ab"},
	{"$2y$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS",
		"\xa3" "ab"},
	{"$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS",
		"\xd1\x91"},
	{"$2x$05$6bNw2HLQYeqHYyBfLMsv/O9LIGgn8OMzuDoHfof8AQimSGfcSWxnS",
		"\xd0\xc1\xd2\xcf\xcc\xd8"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6",
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"chars after 72 are ignored as usual"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy",
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe",
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"},
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
		""},
	{"*0", "", "$2a$03$CCCCCCCCCCCCCCCCCCCCC."},
	{"*0", "", "$2a$32$CCCCCCCCCCCCCCCCCCCCC."},
	{"*0", "", "$2c$05$CCCCCCCCCCCCCCCCCCCCC."},
	{"*0", "", "$2z$05$CCCCCCCCCCCCCCCCCCCCC."},
	{"*0", "", "$2`$05$CCCCCCCCCCCCCCCCCCCCC."},
	{"*0", "", "$2{$05$CCCCCCCCCCCCCCCCCCCCC."},
	{"*1", "", "*0"},
	{NULL}
};

#define which				tests[0]

static volatile sig_atomic_t running;

static void handle_timer(int signum)
{
	(void) signum;
	running = 0;
}

static void *run(void *arg)
{
	unsigned long count = 0;
	int i = 0;
	void *data = NULL;
	int size = 0x12345678;

	do {
		const char *hash = tests[i][0];
		const char *key = tests[i][1];
		const char *setting = tests[i][2];

		if (!tests[++i][0])
			i = 0;

		if (setting && strlen(hash) < 30) /* not for benchmark */
			continue;

		if (strcmp(crypt_ra(key, hash, &data, &size), hash)) {
			printf("%d: FAILED (crypt_ra/%d/%lu)\n",
				(int)((char *)arg - (char *)0), i, count);
			free(data);
			return NULL;
		}
		count++;
	} while (running);

	free(data);
	return count + (char *)0;
}

int main(void)
{
	struct itimerval it;
	struct tms buf;
	clock_t clk_tck, start_real, start_virtual, end_real, end_virtual;
	unsigned long count;
#if 0 /* used only by disabled test below */
	void *data;
	int size;
#endif
	char *setting1, *setting2;
	int i;
#ifdef TEST_THREADS
	pthread_t t[TEST_THREADS];
	void *t_retval;
#endif

#if 0
	data = NULL;
	size = 0x12345678;
#endif
	for (i = 0; tests[i][0]; i++) {
		const char *hash = tests[i][0];
		const char *key = tests[i][1];
		const char *setting = tests[i][2];
		const char *p;
		int ok = !setting || strlen(hash) >= 30;
		char s_buf[30];
#if 0 /* used only by disabled test below */
		int o_size;
                char o_buf[61];
#endif
		if (!setting) {
			memcpy(s_buf, hash, sizeof(s_buf) - 1);
			s_buf[sizeof(s_buf) - 1] = 0;
			setting = s_buf;
		}

		__set_errno(0);
		p = crypt(key, setting);
		if ((!ok && !errno) || strcmp(p, hash)) {
			printf("FAILED (crypt/%d)\n", i);
			return 1;
		}

		if (ok && strcmp(crypt(key, hash), hash)) {
			printf("FAILED (crypt/%d)\n", i);
			return 1;
		}

#if 0 /* This test doesn't work right now due to conflicting expectations */
		for (o_size = -1; o_size <= (int)sizeof(o_buf); o_size++) {
			int ok_n = ok && o_size == (int)sizeof(o_buf);
			const char *x = "abc";
			strcpy(o_buf, x);
			if (o_size >= 3) {
				x = "*0";
				if (setting[0] == '*' && setting[1] == '0')
					x = "*1";
			}
			__set_errno(0);
			p = crypt_rn(key, setting, o_buf, o_size);
			if ((ok_n && (!p || strcmp(p, hash))) ||
			    (!ok_n && (!errno || p || strcmp(o_buf, x)))) {
				printf("FAILED (crypt_rn/%d)\n", i);
				return 1;
			}
		}

		__set_errno(0);
		p = crypt_ra(key, setting, &data, &size);
		if ((ok && (!p || strcmp(p, hash))) ||
		    (!ok && (!errno || p || strcmp((char *)data, hash)))) {
			printf("FAILED (crypt_ra/%d)\n", i);
			return 1;
		}
#endif
	}

	setting1 = crypt_gensalt(which[0], 12, "CCCCCCCCCCCCCCCCCCCCC", 21);
	if (!setting1 || strncmp(setting1, "$2a$12$", 7)) {
          printf("FAILED (crypt_gensalt) w=%s s1=%s\n", which[0], setting1);
          return 1;
	}

	setting2 = crypt_gensalt_ra(setting1, 12, "CCCCCCCCCCCCCCCCCCCCC", 21);
	if (strcmp(setting1, setting2)) {
		puts("FAILED (crypt_gensalt_ra/1)\n");
		return 1;
	}

	setting1 = crypt_gensalt_ra(setting2, 12, "DCCCCCCCCCCCCCCCCCCCC", 21);
	if (!strcmp(setting1, setting2)) {
		puts("FAILED (crypt_gensalt_ra/2)\n");
		return 1;
	}

	free(setting1);
	free(setting2);
#if 0
	free(data);
#endif

#if defined(_SC_CLK_TCK) || !defined(CLK_TCK)
	clk_tck = sysconf(_SC_CLK_TCK);
#else
	clk_tck = CLK_TCK;
#endif

	running = 1;
	signal(SIGALRM, handle_timer);

	memset(&it, 0, sizeof(it));
	it.it_value.tv_sec = 5;
	setitimer(ITIMER_REAL, &it, NULL);

	start_real = times(&buf);
	start_virtual = buf.tms_utime + buf.tms_stime;

	count = (char *)run((char *)0) - (char *)0;

	end_real = times(&buf);
	end_virtual = buf.tms_utime + buf.tms_stime;
	if (end_virtual == start_virtual) end_virtual++;

	printf("%.1f c/s real, %.1f c/s virtual\n",
		(float)count * clk_tck / (end_real - start_real),
		(float)count * clk_tck / (end_virtual - start_virtual));

#ifdef TEST_THREADS
	running = 1;
	it.it_value.tv_sec = 60;
	setitimer(ITIMER_REAL, &it, NULL);
	start_real = times(&buf);

	for (i = 0; i < TEST_THREADS; i++)
	if (pthread_create(&t[i], NULL, run, i + (char *)0)) {
		perror("pthread_create");
		return 1;
	}

	for (i = 0; i < TEST_THREADS; i++) {
		if (pthread_join(t[i], &t_retval)) {
			perror("pthread_join");
			continue;
		}
		if (!t_retval) continue;
		count = (char *)t_retval - (char *)0;
		end_real = times(&buf);
		printf("%d: %.1f c/s real\n", i,
			(float)count * clk_tck / (end_real - start_real));
	}
#endif

	return 0;
}

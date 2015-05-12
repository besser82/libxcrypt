
/*
 * Written by Solar Designer and placed in the public domain.
 * See crypt_blowfish.c for more information.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/times.h>

#include "xcrypt.h"
#include "xcrypt-plugin.h"

static struct {
	char *hash;
	char *pw;
} tests[] = {
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
		"U*U"},
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
		"U*U*"},
	{"$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
		"U*U*U"},
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
		""},
	{"$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
		"0123456789abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
	{NULL, NULL}
};

#define which				tests[0]

static volatile sig_atomic_t running;

static void handle_timer(int signum __attribute__((unused)))
{
	running = 0;
}

static void *run(void *arg)
{
        unsigned long count = 0;
        int i = 0;
        struct crypt_data data;
        int size = sizeof (data);

        do {
                if (strcmp(__crypt_r(tests[i].pw, tests[i].hash, (char *)&data, size),
                    tests[i].hash)) {
                        printf("%ld: FAILED (__crypt_r/%d/%lu)\n",
                                (long)((char *)arg - (char *)0), i, count);
                        return NULL;
                }
                if (!tests[++i].hash) i = 0;
               count++;
        } while (running);

        return count + (char *)0;
}



int main(void)
{
	struct itimerval it;
	struct tms buf;
	clock_t start_real, start_virtual, end_real, end_virtual;
	unsigned long count;
	struct crypt_data data;
	int size;
	char *setting1, *setting2;
	int i;
        pthread_t t[TEST_THREADS];
        void *t_retval;

#if 0
	for (i = 0; tests[i].hash; i++)
	if (strcmp(__crypt(tests[i].pw, tests[i].hash), tests[i].hash)) {
		printf("FAILED (__crypt/%d)\n", i);
		return 1;
	}
#endif

	size = sizeof (data);
	for (i = 0; tests[i].hash; i++)
	if (strcmp(__crypt_r(tests[i].pw, tests[i].hash, (char *)&data, size),
	    tests[i].hash)) {
		printf("FAILED (__crypt_r/%d)\n", i);
		return 1;
	}

        char output1[CRYPT_GENSALT_OUTPUT_SIZE];
	setting1 = __crypt_gensalt_r (12, (char *)&data, size,
				    output1, sizeof (output1));
	if (!setting1 || strncmp(setting1, "$2a$12$", 7)) {
		puts("FAILED (__crypt_gensalt_r/1)\n");
		return 1;
	}

        char output2[CRYPT_GENSALT_OUTPUT_SIZE];
	setting2 = __crypt_gensalt_r (12, (char *)&data, size, output2,
					sizeof (output2));
	if (strcmp(setting1, setting2)) {
		puts("FAILED (__crypt_gensalt_r/2)\n");
		return 1;
	}

	char output3[CRYPT_GENSALT_OUTPUT_SIZE];
	char *data2 = (char *)&data;
	setting1 = __crypt_gensalt_r (12, &data2[4], size, output3,
					sizeof (output3));
	if (!strcmp(setting1, setting2)) {
		puts("FAILED (__crypt_gensalt_r/3)\n");
		return 1;
	}

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
	       (float)count * sysconf (_SC_CLK_TCK) / (end_real - start_real),
	       (float)count * sysconf (_SC_CLK_TCK) /
	       (end_virtual - start_virtual));

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
                        (float)count * sysconf (_SC_CLK_TCK) / (end_real - start_real));
        }

	return 0;
}

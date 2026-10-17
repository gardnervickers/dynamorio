/* **********************************************************
 * Copyright (c) 2026 Google, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * The app for client.itimer_threads (see itimer_threads.dll.c, whose client
 * runs DR timers of its own on all three itimers): periodic app timers on all
 * three while several threads spin and call getitimer, and one also re-arms
 * ITIMER_VIRTUAL and ITIMER_PROF, so that DR's itimer locks are busy while
 * alarms keep arriving in every thread.  Each value read must be one the app's
 * own timer can have, and ITIMER_REAL, which no thread re-arms, must deliver
 * about as many signals as natively.
 */

#include "tools.h"
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#define NUM_THREADS 8
#define RUN_MS 1500
#define TICK_SLACK_US 10000

static const long period_us[3] = { 2500, 2700, 3300 }; /* REAL, VIRTUAL, PROF */
static const char *const name[3] = { "ITIMER_REAL", "ITIMER_VIRTUAL", "ITIMER_PROF" };

static volatile long count[3];
static volatile long bad_values[3];
static volatile int stop;

static const int sig[3] = { SIGALRM, SIGVTALRM, SIGPROF };

static int
sig_to_which(int signum)
{
    return signum == SIGALRM ? ITIMER_REAL
                             : (signum == SIGVTALRM ? ITIMER_VIRTUAL : ITIMER_PROF);
}

static void
handler(int signum, siginfo_t *info, void *ucxt)
{
    __atomic_add_fetch(&count[sig_to_which(signum)], 1, __ATOMIC_RELAXED);
}

static int64_t
now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static void
periodic(int which, struct itimerval *val)
{
    val->it_interval.tv_sec = 0;
    val->it_interval.tv_usec = period_us[which];
    val->it_value = val->it_interval;
}

/* A value the app's periodic timer can have: its own interval, and a remaining
 * time of at most one interval (the kernel samples the CPU-time timers at ticks,
 * so it can report a little more for those).
 */
static void
check_value(int which, const struct itimerval *val)
{
    int64_t value = (int64_t)val->it_value.tv_sec * 1000000 + val->it_value.tv_usec;
    int64_t max = period_us[which] + (which == ITIMER_REAL ? 0 : TICK_SLACK_US);
    if (val->it_interval.tv_sec != 0 || val->it_interval.tv_usec != period_us[which] ||
        value < 0 || value > max) {
        if (__atomic_add_fetch(&bad_values[which], 1, __ATOMIC_RELAXED) <= 3) {
            print("%s: bad value interval=%ld.%06ld value=%ld.%06ld\n", name[which],
                  (long)val->it_interval.tv_sec, (long)val->it_interval.tv_usec,
                  (long)val->it_value.tv_sec, (long)val->it_value.tv_usec);
        }
    }
}

static void *
thread_func(void *arg)
{
    int idx = (int)(intptr_t)arg;
    uint32_t rnd = 2463534242u * (uint32_t)(idx + 1);
    while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE)) {
        rnd ^= rnd << 13;
        rnd ^= rnd >> 17;
        rnd ^= rnd << 5;
        for (volatile uint32_t i = rnd % 2000; i > 0; i--)
            ;
        int which = (int)(rnd % 3);
        struct itimerval val;
        if (idx == 0 && which != ITIMER_REAL && (rnd >> 8) % 4 == 0) {
            struct itimerval old;
            periodic(which, &val);
            if (setitimer(which, &val, &old) != 0)
                perror("setitimer");
            check_value(which, &old);
        } else {
            if (getitimer(which, &val) != 0)
                perror("getitimer");
            check_value(which, &val);
        }
    }
    return NULL;
}

int
main(int argc, char *argv[])
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = handler;
    act.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&act.sa_mask);
    for (int which = 0; which < 3; which++) {
        if (sigaction(sig[which], &act, NULL) != 0)
            perror("sigaction");
    }

    pthread_t thread[NUM_THREADS];
    int64_t start = now_us();
    for (int which = 0; which < 3; which++) {
        struct itimerval val;
        periodic(which, &val);
        if (setitimer(which, &val, NULL) != 0)
            perror("setitimer");
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&thread[i], NULL, thread_func, (void *)(intptr_t)i) != 0) {
            print("pthread_create failed\n");
            return 1;
        }
    }
    struct timespec ts = { RUN_MS / 1000, (RUN_MS % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0)
        ;
    __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(thread[i], NULL);
    struct itimerval zero;
    memset(&zero, 0, sizeof(zero));
    for (int which = 0; which < 3; which++)
        setitimer(which, &zero, NULL);
    int64_t elapsed = now_us() - start;

    /* Natively ITIMER_REAL delivers elapsed/period signals (a few fewer if the
     * kernel merges expiries while one is pending).  A DR timer's expiry passed
     * to the app adds some; an app timer re-armed from stale state loses many.
     * Under DR the app's expiries are also late under load (see the known
     * deviation itimer-mux in api/a64_prop_signal.c), so the lower bound is loose.
     */
    long expect = (long)(elapsed / period_us[ITIMER_REAL]);
    long got = count[ITIMER_REAL];
    if (got < expect / 4 || got > expect + expect / 10 + 10) {
        print("%s: %ld signals in %ld us, expected about %ld\n", name[ITIMER_REAL], got,
              (long)elapsed, expect);
    } else
        print("%s: signal count ok\n", name[ITIMER_REAL]);
    for (int which = ITIMER_VIRTUAL; which <= ITIMER_PROF; which++) {
        if (count[which] == 0)
            print("%s: no signals\n", name[which]);
        else
            print("%s: signals delivered\n", name[which]);
    }
    if (bad_values[0] + bad_values[1] + bad_values[2] == 0)
        print("values ok\n");
    return 0;
}

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
 * The app for client.itimer_threads (see itimer_threads.dll.c, whose client runs
 * DR timers of its own on all three itimers, so that DR multiplexes every one of
 * them, and suspends all other threads whenever the app calls getppid).
 *
 * - Single-thread cases: invalid values and which, unreadable new and
 *   unwritable old values (which DR, emulating the syscall, faults on in its own
 *   copy), disarming with an interval (which ITIMER_REAL drops), and alarm's
 *   result.
 * - Contention: periodic app timers on all three while several threads spin and
 *   call getitimer, some into a buffer whose page another thread keeps
 *   write-protecting, one re-arms ITIMER_VIRTUAL and ITIMER_PROF, and one keeps
 *   having the client suspend all the others; so DR's itimer locks are busy
 *   while alarms keep arriving in every thread.  Each value read must be one the
 *   app's own timer can have, and ITIMER_REAL, which no thread re-arms, must
 *   deliver about as many signals as natively.
 * - Concurrent setters: several threads set each timer to intervals no other set
 *   uses, arming and disarming the CPU-time timers in turn.  The prior values
 *   must chain all the sets from the initial timer to the final one in one order
 *   that keeps each thread's own, as if the sets ran one at a time.
 * - Disarmed: once the app disarms all three, no app signal may arrive while the
 *   client's timers keep running.
 */

#include "tools.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define NUM_THREADS 8
#define RUN_MS 1500
#define TICK_SLACK_US 10000

#define NUM_SETTERS 4
#define SETS_PER_SETTER 150
#define NUM_IDS (1 + NUM_SETTERS * SETS_PER_SETTER)

static const long period_us[3] = { 2500, 2700, 3300 }; /* REAL, VIRTUAL, PROF */
static const char *const name[3] = { "ITIMER_REAL", "ITIMER_VIRTUAL", "ITIMER_PROF" };

static long count[3];
static long bad_values[3];
static long bad_errors;
static int stop;

static const int sig[3] = { SIGALRM, SIGVTALRM, SIGPROF };

/* A page that one thread keeps write-protecting while others getitimer into it. */
static char *toggle_page;

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

static long
load_count(int which)
{
    return __atomic_load_n(&count[which], __ATOMIC_RELAXED);
}

static int64_t
now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int64_t
tv_us(const struct timeval *tv)
{
    return (int64_t)tv->tv_sec * 1000000 + tv->tv_usec;
}

static void
set_tv(struct timeval *tv, int64_t us)
{
    tv->tv_sec = (time_t)(us / 1000000);
    tv->tv_usec = (suseconds_t)(us % 1000000);
}

static void
periodic(int which, struct itimerval *val)
{
    val->it_interval.tv_sec = 0;
    val->it_interval.tv_usec = period_us[which];
    val->it_value = val->it_interval;
}

/* Spins for about us microseconds of wall time, using CPU time for the CPU-time
 * timers.
 */
static void
spin_us(int64_t us)
{
    int64_t end = now_us() + us;
    while (now_us() < end) {
        for (volatile int i = 0; i < 1000; i++)
            ;
    }
}

static uint32_t
next_rand(uint32_t *rnd)
{
    *rnd ^= *rnd << 13;
    *rnd ^= *rnd >> 17;
    *rnd ^= *rnd << 5;
    return *rnd;
}

static void
spin_rand(uint32_t *rnd)
{
    for (volatile uint32_t i = next_rand(rnd) % 2000; i > 0; i--)
        ;
}

/***************************************************************************
 * Failure cases
 */

static int failures;

static void
expect_error(const char *what, int rc, int err)
{
    if (rc != -1 || errno != err) {
        print("%s: got %d errno %d, expected errno %d\n", what, rc, rc == 0 ? 0 : errno,
              err);
        failures++;
    }
}

static void
expect_timer(const char *what, int which, int64_t interval, int64_t min_value,
             int64_t max_value)
{
    struct itimerval cur;
    if (getitimer(which, &cur) != 0) {
        print("%s: getitimer failed\n", what);
        failures++;
        return;
    }
    if (tv_us(&cur.it_interval) != interval || tv_us(&cur.it_value) < min_value ||
        tv_us(&cur.it_value) > max_value) {
        print("%s: %s is interval=%ld value=%ld\n", what, name[which],
              (long)tv_us(&cur.it_interval), (long)tv_us(&cur.it_value));
        failures++;
    }
}

static void
test_failures(void)
{
    struct itimerval val, zero;
    memset(&zero, 0, sizeof(zero));
    long page_size = sysconf(_SC_PAGESIZE);
    char *ro = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *unmapped = mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ro == MAP_FAILED || unmapped == MAP_FAILED || munmap(unmapped, page_size) != 0) {
        print("mmap failed\n");
        return;
    }

    /* Invalid values and which: no timer changes. */
    periodic(ITIMER_VIRTUAL, &val);
    val.it_value.tv_usec = 1000000;
    expect_error("setitimer bad usec", setitimer(ITIMER_VIRTUAL, &val, NULL), EINVAL);
    expect_timer("after bad usec", ITIMER_VIRTUAL, 0, 0, 0);
    periodic(ITIMER_VIRTUAL, &val);
    expect_error("setitimer bad which", setitimer(3, &val, NULL), EINVAL);
    expect_error("getitimer bad which", getitimer(-1, &val), EINVAL);

    /* An unreadable new value fails without changing the timer. */
    expect_error("setitimer unreadable new",
                 setitimer(ITIMER_VIRTUAL, (struct itimerval *)unmapped, NULL), EFAULT);
    expect_timer("after unreadable new", ITIMER_VIRTUAL, 0, 0, 0);

    /* An unwritable old value fails after setting the timer. */
    periodic(ITIMER_VIRTUAL, &val);
    expect_error("setitimer unwritable old",
                 setitimer(ITIMER_VIRTUAL, &val, (struct itimerval *)ro), EFAULT);
    expect_timer("after unwritable old", ITIMER_VIRTUAL, period_us[ITIMER_VIRTUAL], 1,
                 period_us[ITIMER_VIRTUAL] + TICK_SLACK_US);
    expect_error("getitimer unwritable",
                 getitimer(ITIMER_VIRTUAL, (struct itimerval *)ro), EFAULT);
    expect_error("getitimer unmapped",
                 getitimer(ITIMER_VIRTUAL, (struct itimerval *)unmapped), EFAULT);
    if (setitimer(ITIMER_VIRTUAL, &zero, NULL) != 0)
        perror("setitimer");

    /* Disarming with an interval: Linux drops ITIMER_REAL's interval but keeps
     * those of the CPU-time timers.
     */
    struct itimerval old;
    val.it_interval.tv_sec = 0;
    val.it_interval.tv_usec = 3000;
    val.it_value.tv_sec = 5;
    val.it_value.tv_usec = 0;
    if (setitimer(ITIMER_REAL, &val, NULL) != 0)
        perror("setitimer");
    val.it_interval.tv_usec = 4000;
    val.it_value.tv_sec = 0;
    if (setitimer(ITIMER_REAL, &val, &old) != 0)
        perror("setitimer");
    if (tv_us(&old.it_interval) != 3000 || tv_us(&old.it_value) < 4000000 ||
        tv_us(&old.it_value) > 5000000) {
        print("disarming ITIMER_REAL: prior interval=%ld value=%ld\n",
              (long)tv_us(&old.it_interval), (long)tv_us(&old.it_value));
        failures++;
    }
    expect_timer("after disarming with an interval", ITIMER_REAL, 0, 0, 0);
    if (setitimer(ITIMER_REAL, &zero, &old) != 0)
        perror("setitimer");
    if (tv_us(&old.it_interval) != 0 || tv_us(&old.it_value) != 0) {
        print("disarmed ITIMER_REAL: prior interval=%ld value=%ld\n",
              (long)tv_us(&old.it_interval), (long)tv_us(&old.it_value));
        failures++;
    }
    for (int which = ITIMER_VIRTUAL; which <= ITIMER_PROF; which++) {
        val.it_value.tv_sec = 0;
        if (setitimer(which, &val, NULL) != 0)
            perror("setitimer");
        expect_timer("after disarming with an interval", which, 4000, 0, 0);
        if (setitimer(which, &zero, &old) != 0)
            perror("setitimer");
        if (tv_us(&old.it_interval) != 4000 || tv_us(&old.it_value) != 0) {
            print("disarmed %s: prior interval=%ld value=%ld\n", name[which],
                  (long)tv_us(&old.it_interval), (long)tv_us(&old.it_value));
            failures++;
        }
    }

    /* alarm (a syscall of its own on x86, setitimer elsewhere) returns the app's
     * prior timer rounded to the nearest second, and clears the interval.
     */
    val.it_interval.tv_sec = 1;
    val.it_interval.tv_usec = 0;
    val.it_value.tv_sec = 5;
    val.it_value.tv_usec = 700000;
    if (setitimer(ITIMER_REAL, &val, NULL) != 0)
        perror("setitimer");
    unsigned int left = alarm(0);
    if (left != 6) {
        print("alarm returned %u, expected 6\n", left);
        failures++;
    }
    expect_timer("after alarm(0)", ITIMER_REAL, 0, 0, 0);
    left = alarm(30);
    if (left != 0) {
        print("alarm returned %u, expected 0\n", left);
        failures++;
    }
    expect_timer("after alarm(30)", ITIMER_REAL, 0, 29000000, 30000000);
    left = alarm(0);
    if (left != 30) {
        print("alarm returned %u, expected 30\n", left);
        failures++;
    }

    munmap(ro, page_size);
    if (failures == 0)
        print("failure cases ok\n");
}

/***************************************************************************
 * Contention
 */

/* A value the app's periodic timer can have: its own interval, and a remaining
 * time of at most one interval (the kernel samples the CPU-time timers at ticks,
 * so it can report a little more for those).
 */
static void
check_value(int which, const struct itimerval *val)
{
    int64_t value = tv_us(&val->it_value);
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
        spin_rand(&rnd);
        int which = (int)(rnd % 3);
        struct itimerval val;
        if (idx == 0 && which != ITIMER_REAL && (rnd >> 8) % 4 == 0) {
            struct itimerval old;
            periodic(which, &val);
            if (setitimer(which, &val, &old) != 0)
                perror("setitimer");
            check_value(which, &old);
        } else if ((idx == 1 || idx == 2) && (rnd >> 8) % 2 == 0) {
            /* Into the page another thread keeps write-protecting. */
            struct itimerval *buf = (struct itimerval *)(toggle_page + idx * 64);
            if (getitimer(which, buf) == 0)
                check_value(which, buf);
            else if (errno != EFAULT) {
                if (__atomic_add_fetch(&bad_errors, 1, __ATOMIC_RELAXED) <= 3)
                    print("getitimer: unexpected errno %d\n", errno);
            }
        } else {
            if (getitimer(which, &val) != 0)
                perror("getitimer");
            check_value(which, &val);
        }
    }
    return NULL;
}

static void *
toggle_func(void *arg)
{
    long page_size = sysconf(_SC_PAGESIZE);
    uint32_t rnd = 88172645u;
    int writable = 1;
    while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE)) {
        spin_rand(&rnd);
        writable = !writable;
        if (mprotect(toggle_page, page_size, PROT_READ | (writable ? PROT_WRITE : 0)) !=
            0)
            perror("mprotect");
    }
    return NULL;
}

static int stop_suspend;

/* The client suspends all other threads on each getppid. */
static void *
suspend_func(void *arg)
{
    while (!__atomic_load_n(&stop_suspend, __ATOMIC_ACQUIRE)) {
        getppid();
        spin_us(1000);
    }
    return NULL;
}

static void
test_contention(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    toggle_page =
        mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (toggle_page == MAP_FAILED) {
        print("mmap failed\n");
        return;
    }
    pthread_t thread[NUM_THREADS], toggler;
    int64_t start = now_us();
    long start_count = load_count(ITIMER_REAL);
    for (int which = 0; which < 3; which++) {
        struct itimerval val;
        periodic(which, &val);
        if (setitimer(which, &val, NULL) != 0)
            perror("setitimer");
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&thread[i], NULL, thread_func, (void *)(intptr_t)i) != 0) {
            print("pthread_create failed\n");
            exit(1);
        }
    }
    if (pthread_create(&toggler, NULL, toggle_func, NULL) != 0) {
        print("pthread_create failed\n");
        exit(1);
    }
    struct timespec ts = { RUN_MS / 1000, (RUN_MS % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0)
        ;
    __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(thread[i], NULL);
    pthread_join(toggler, NULL);
    struct itimerval zero;
    memset(&zero, 0, sizeof(zero));
    for (int which = 0; which < 3; which++)
        setitimer(which, &zero, NULL);
    int64_t elapsed = now_us() - start;
    munmap(toggle_page, page_size);

    /* Natively ITIMER_REAL delivers elapsed/period signals (a few fewer if the
     * kernel merges expiries while one is pending).  A DR timer's expiry passed
     * to the app adds some; an app timer re-armed from stale state loses many.
     * Under DR the app's expiries are also late under load (see the known
     * deviation itimer-mux in api/a64_prop_signal.c), so the lower bound is loose.
     */
    long expect = (long)(elapsed / period_us[ITIMER_REAL]);
    long got = load_count(ITIMER_REAL) - start_count;
    if (got < expect / 4 || got > expect + expect / 10 + 10) {
        print("%s: %ld signals in %ld us, expected about %ld\n", name[ITIMER_REAL], got,
              (long)elapsed, expect);
    } else
        print("%s: signal count ok\n", name[ITIMER_REAL]);
    for (int which = ITIMER_VIRTUAL; which <= ITIMER_PROF; which++) {
        if (load_count(which) == 0)
            print("%s: no signals\n", name[which]);
        else
            print("%s: signals delivered\n", name[which]);
    }
    if (bad_values[0] + bad_values[1] + bad_values[2] == 0)
        print("values ok\n");
    if (bad_errors == 0)
        print("faulting buffer ok\n");
}

/***************************************************************************
 * Concurrent setters
 */

/* Set number id (0 for the initial one; then SETS_PER_SETTER per setter thread,
 * in its order) installs this interval, unique to it, and arms the timer with it
 * if id_armed().  ITIMER_REAL is always armed, as Linux drops a disarmed
 * ITIMER_REAL's interval (see test_failures()).
 */
static int64_t
id_interval(int id)
{
    return 4000 + 10 * id;
}

static int
id_armed(int which, int id)
{
    return which == ITIMER_REAL || id == 0 || ((id - 1) % SETS_PER_SETTER) % 2 == 0;
}

static int
interval_id(int64_t interval)
{
    if (interval < id_interval(0) || (interval - id_interval(0)) % 10 != 0 ||
        interval > id_interval(NUM_IDS - 1))
        return -1;
    return (int)((interval - id_interval(0)) / 10);
}

static void
id_timer(int which, int id, struct itimerval *val)
{
    set_tv(&val->it_interval, id_interval(id));
    set_tv(&val->it_value, id_armed(which, id) ? id_interval(id) : 0);
}

typedef struct {
    int64_t old_interval;
    int64_t old_value;
} set_result_t;

static set_result_t results[3][NUM_IDS];

static void *
setter_func(void *arg)
{
    int idx = (int)(intptr_t)arg;
    uint32_t rnd = 1234567u * (uint32_t)(idx + 1);
    for (int k = 0; k < SETS_PER_SETTER; k++) {
        for (int which = 0; which < 3; which++) {
            int id = 1 + idx * SETS_PER_SETTER + k;
            struct itimerval val, old;
            spin_rand(&rnd);
            id_timer(which, id, &val);
            if (setitimer(which, &val, &old) != 0) {
                perror("setitimer");
                old.it_interval.tv_sec = -1;
            }
            results[which][id].old_interval = tv_us(&old.it_interval);
            results[which][id].old_value = tv_us(&old.it_value);
        }
    }
    return NULL;
}

/* Checks that the sets of which ran as if one at a time: each set's prior timer
 * links it to the set before it, and following those links from the initial
 * timer must visit every set exactly once, each setter's in its own order, and
 * end at the timer the kernel has now.
 */
static void
check_setters(int which)
{
    static int next[NUM_IDS], pos[NUM_IDS];
    int bad = 0;
    for (int id = 0; id < NUM_IDS; id++) {
        next[id] = -1;
        pos[id] = -1;
    }
    for (int id = 1; id < NUM_IDS; id++) {
        set_result_t *res = &results[which][id];
        int old_id = interval_id(res->old_interval);
        if (old_id < 0 || old_id == id || next[old_id] != -1) {
            if (bad++ < 3) {
                print("%s: set %d got prior interval %ld (set %d), %s\n", name[which], id,
                      (long)res->old_interval, old_id,
                      old_id < 0 || old_id == id ? "not another set's"
                                                 : "also another set's prior");
            }
            continue;
        }
        next[old_id] = id;
        /* An armed periodic timer has some time left, at most an interval
         * (and some for the CPU-time timers: see check_value()); the kernel
         * can truncate a CPU-time timer's last microsecond to 0.
         */
        int64_t max = id_interval(old_id) + (which == ITIMER_REAL ? 0 : TICK_SLACK_US);
        int64_t min = which == ITIMER_REAL ? 1 : 0;
        if (id_armed(which, old_id) ? (res->old_value < min || res->old_value > max)
                                    : res->old_value != 0) {
            if (bad++ < 3) {
                print("%s: set %d got prior value %ld from %s set %d\n", name[which], id,
                      (long)res->old_value,
                      id_armed(which, old_id) ? "arming" : "disarming", old_id);
            }
        }
    }
    int last = 0, count = 0;
    pos[0] = 0;
    while (next[last] != -1 && pos[next[last]] == -1) {
        last = next[last];
        pos[last] = ++count;
    }
    if (count != NUM_IDS - 1) {
        print("%s: the sets from the initial timer on are only %d of %d\n", name[which],
              count, NUM_IDS - 1);
        bad++;
    }
    struct itimerval cur;
    if (getitimer(which, &cur) != 0)
        perror("getitimer");
    int final_id = interval_id(tv_us(&cur.it_interval));
    if (final_id != last) {
        print("%s: the timer is set %d's, but the last set is %d\n", name[which],
              final_id, last);
        bad++;
    }
    for (int t = 0; t < NUM_SETTERS; t++) {
        for (int k = 1; k < SETS_PER_SETTER; k++) {
            int id = 1 + t * SETS_PER_SETTER + k;
            if (pos[id] != -1 && pos[id - 1] != -1 && pos[id] < pos[id - 1]) {
                if (bad++ < 3) {
                    print("%s: setter %d's set %d came before its set %d\n", name[which],
                          t, id, id - 1);
                }
            }
        }
    }
    if (bad == 0)
        print("%s: setters ok\n", name[which]);
}

static void
test_setters(void)
{
    pthread_t thread[NUM_SETTERS];
    for (int which = 0; which < 3; which++) {
        struct itimerval val;
        id_timer(which, 0, &val);
        if (setitimer(which, &val, NULL) != 0)
            perror("setitimer");
    }
    for (int i = 0; i < NUM_SETTERS; i++) {
        if (pthread_create(&thread[i], NULL, setter_func, (void *)(intptr_t)i) != 0) {
            print("pthread_create failed\n");
            exit(1);
        }
    }
    for (int i = 0; i < NUM_SETTERS; i++)
        pthread_join(thread[i], NULL);
    for (int which = 0; which < 3; which++)
        check_setters(which);
}

/***************************************************************************
 * Disarmed
 */

static void
test_disarmed(void)
{
    struct itimerval zero;
    memset(&zero, 0, sizeof(zero));
    for (int which = 0; which < 3; which++) {
        if (setitimer(which, &zero, NULL) != 0)
            perror("setitimer");
    }
    /* Let a signal on its way at the disarm arrive. */
    spin_us(100000);
    long before[3];
    for (int which = 0; which < 3; which++)
        before[which] = load_count(which);
    /* The client's timers keep firing meanwhile, using our CPU time for the
     * CPU-time ones.
     */
    spin_us(300000);
    int bad = 0;
    for (int which = 0; which < 3; which++) {
        long after = load_count(which);
        struct itimerval cur;
        if (getitimer(which, &cur) != 0)
            perror("getitimer");
        if (after != before[which] || tv_us(&cur.it_interval) != 0 ||
            tv_us(&cur.it_value) != 0) {
            print("%s: disarmed but %ld signals arrived and interval=%ld value=%ld\n",
                  name[which], after - before[which], (long)tv_us(&cur.it_interval),
                  (long)tv_us(&cur.it_value));
            bad++;
        }
    }
    if (bad == 0)
        print("disarmed timers quiet\n");
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

    test_failures();

    pthread_t suspender;
    if (pthread_create(&suspender, NULL, suspend_func, NULL) != 0) {
        print("pthread_create failed\n");
        return 1;
    }
    test_contention();
    test_setters();
    __atomic_store_n(&stop_suspend, 1, __ATOMIC_RELEASE);
    pthread_join(suspender, NULL);

    test_disarmed();
    return 0;
}

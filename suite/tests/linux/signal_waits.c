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

/* Timed waits interrupted by a signal whose handler returns, with the signal's
 * timer tuned to arrive around the wait's syscall entry (as in signal_racesys,
 * which escapes its handler with siglongjmp instead).  Each wait checks that its
 * result is one that a signal arriving at some point around the syscall can give
 * natively: the handler ran first and the wait then ran normally, or the wait failed
 * with EINTR having done what the kernel does then (nanosleep fills in its
 * remaining time).  A signal the wait missed would show up as a timeout.  The waits
 * with a temporary mask also check that the thread's mask is the original one
 * after they return.  Meanwhile another thread runs and unmaps code, so that under
 * DR its flushes interrupt the waits with DR's own signal, which DR then issues
 * again, sometimes just as the app's signal arrives.
 */

#include "tools.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define ITERS 1000
#define MAX_REPORTED 5
/* Long enough that a wait running out its timeout means it missed the signal. */
#define LONG_TIMEOUT_MS 2000
#define SLEEP_NS 200000
/* A sleep long enough for DR's own signals to interrupt it, with the app's
 * signal anywhere in it: some arrive as DR issues it again.
 */
#define LONG_SLEEP_NS 20000000
#define LONG_SLEEP_ITERS 100

enum {
    W_NANOSLEEP, /* glibc's, which is SYS_clock_nanosleep */
    W_SYS_NANOSLEEP,
    W_PPOLL,
    W_PPOLL_MASK,
    W_EPOLL_MASK,
    W_PSELECT_MASK,
    W_FUTEX,
    W_LONG_SLEEP, /* SYS_nanosleep */
    W_NUM
};
static const char *const names[W_NUM] = {
    "nanosleep",       "SYS_nanosleep",         "ppoll",
    "ppoll with mask", "epoll_pwait with mask", "pselect with mask",
    "futex wait",      "long SYS_nanosleep",
};

#define IS_SLEEP(which) \
    ((which) == W_NANOSLEEP || (which) == W_SYS_NANOSLEEP || (which) == W_LONG_SLEEP)

static timer_t timer;
static volatile int flusher_stop;
static int pipefd[2];
static int epfd;
static volatile int handled;
/* Whether the handler waits too: a wait we reissue under DR in the handler must
 * not change the interrupted one.
 */
static volatile int handler_waits;
static volatile int futex_word;

static void
handler(int sig, siginfo_t *info, void *ucxt)
{
    char c = 1;
    int saved = errno;
    handled = 1;
    if (handler_waits) {
        /* Waits that reuse DR's per-thread buffers for a sleep's timeout and a
         * temporary mask: this one blocks SIGUSR2.
         */
        struct timespec ts = { 0, 1000 }, zero = { 0, 0 };
        sigset_t mask;
        nanosleep(&ts, NULL);
        sigprocmask(SIG_BLOCK, NULL, &mask);
        sigaddset(&mask, SIGUSR2);
        ppoll(NULL, 0, &zero, &mask);
    }
    /* End a wait that the handler ran ahead of, as the signal would have. */
    if (write(pipefd[1], &c, 1) != 1)
        print("write failed\n");
    futex_word = 1;
    errno = saved;
}

static uint64_t
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void
drain(void)
{
    char buf[64];
    while (read(pipefd[0], buf, sizeof(buf)) > 0)
        ;
}

/* Returns 1 if the signal came before the wait started, -1 if it came during the
 * wait or after it, and 0 on an invalid result.
 */
static int
try_wait(int which, uint64_t delay_ns, const sigset_t *orig_mask, int *reported)
{
    struct itimerspec spec = { { 0, 0 }, { 0, (long)delay_ns } };
    long sleep_ns = which == W_LONG_SLEEP ? LONG_SLEEP_NS : SLEEP_NS;
    struct timespec req = { 0, sleep_ns };
    struct timespec rem = { 12345, 0 }; /* Must not change on success. */
    struct timespec long_ts = { LONG_TIMEOUT_MS / 1000, 0 };
    struct pollfd pfd = { pipefd[0], POLLIN, 0 };
    struct epoll_event ev;
    sigset_t tmp_mask = *orig_mask, cur_mask;
    fd_set rfds;
    int ret, err, handled_at_return, valid = 1, before;
    uint64_t start, elapsed;

    /* A temporary mask that differs from the thread's. */
    sigaddset(&tmp_mask, SIGUSR2);
    FD_ZERO(&rfds);
    FD_SET(pipefd[0], &rfds);
    handled = 0;
    futex_word = 0;
    if (timer_settime(timer, 0, &spec, NULL) != 0) {
        perror("timer_settime");
        exit(1);
    }
    start = now_ns();
    switch (which) {
    case W_NANOSLEEP: ret = nanosleep(&req, &rem); break;
    case W_SYS_NANOSLEEP:
    case W_LONG_SLEEP: ret = syscall(SYS_nanosleep, &req, &rem); break;
    case W_PPOLL: ret = ppoll(&pfd, 1, &long_ts, NULL); break;
    case W_PPOLL_MASK: ret = ppoll(&pfd, 1, &long_ts, &tmp_mask); break;
    case W_EPOLL_MASK: ret = epoll_pwait(epfd, &ev, 1, LONG_TIMEOUT_MS, &tmp_mask); break;
    case W_PSELECT_MASK:
        ret = pselect(pipefd[0] + 1, &rfds, NULL, NULL, &long_ts, &tmp_mask);
        break;
    case W_FUTEX:
        ret = syscall(SYS_futex, &futex_word, FUTEX_WAIT_PRIVATE, 0, &long_ts, NULL, 0);
        break;
    default: ret = -1; break;
    }
    err = errno;
    handled_at_return = handled;
    elapsed = now_ns() - start;
    /* Wait for a signal that came after the wait. */
    while (!handled) {
        if (now_ns() - start > 5000000000ULL) {
            print("%s: signal never arrived\n", names[which]);
            exit(1);
        }
        sched_yield();
    }
    sigprocmask(SIG_BLOCK, NULL, &cur_mask);
    if (sigismember(&cur_mask, SIGUSR2) != sigismember(orig_mask, SIGUSR2) ||
        sigismember(&cur_mask, SIGUSR1) != sigismember(orig_mask, SIGUSR1))
        valid = 0;
    if (which == W_FUTEX && ret == -1 && err == EAGAIN) {
        /* The handler changed the word before the wait checked it. */
        before = 1;
        if (!handled_at_return)
            valid = 0;
    } else if (ret == -1) {
        /* The signal interrupted the wait: its handler ran before the return. */
        before = -1;
        if (err != EINTR || !handled_at_return)
            valid = 0;
        /* The remaining time can include the timer's slack. */
        if (IS_SLEEP(which) &&
            (rem.tv_sec != 0 || rem.tv_nsec < 0 || rem.tv_nsec > sleep_ns + 1000000))
            valid = 0;
    } else if (IS_SLEEP(which)) {
        /* Slept the whole time, after the handler or before the signal. */
        before = handled_at_return ? 1 : -1;
        if (ret != 0 || rem.tv_sec != 12345 || elapsed < (uint64_t)sleep_ns)
            valid = 0;
    } else {
        /* Only the handler makes the pipe readable: it ran before the wait.  A
         * futex wait cannot succeed: nothing wakes it.
         */
        before = 1;
        if (which == W_FUTEX || ret != 1 || !handled_at_return)
            valid = 0;
    }
    if (elapsed >= (uint64_t)LONG_TIMEOUT_MS * 1000000 / 2)
        valid = 0;
    if (!valid && (*reported)++ < MAX_REPORTED) {
        print("%s: invalid result ret=%d errno=%d handled=%d rem=%ld.%09ld "
              "elapsed=%lluns delay=%lluns\n",
              names[which], ret, ret == -1 ? err : 0, handled_at_return,
              (long)rem.tv_sec, rem.tv_nsec, (unsigned long long)elapsed,
              (unsigned long long)delay_ns);
    }
    drain();
    return valid ? before : 0;
}

static void
test_wait(int which, int flags)
{
    struct sigaction act;
    sigset_t orig_mask;
    uint64_t delay = 1000;
    int i, r, reported = 0;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = handler;
    act.sa_flags = SA_SIGINFO | flags;
    handler_waits = (flags & SA_RESTART) != 0;
    if (sigaction(SIGUSR1, &act, NULL) != 0) {
        perror("sigaction");
        exit(1);
    }
    sigprocmask(SIG_BLOCK, NULL, &orig_mask);
    for (i = 0; i < (which == W_LONG_SLEEP ? LONG_SLEEP_ITERS : ITERS); i++) {
        if (which == W_LONG_SLEEP)
            delay = 1 + (uint64_t)(i * 7919 % 20000) * (LONG_SLEEP_NS / 20000);
        r = try_wait(which, delay, &orig_mask, &reported);
        if (r == 0 && reported >= MAX_REPORTED)
            break;
        /* Aim the signal at the wait's syscall entry. */
        if (r > 0)
            delay = delay + delay / 4 + 1;
        else
            delay = delay - delay / 4;
        if (delay < 1)
            delay = 1;
        if (delay > 5000000)
            delay = 5000000;
    }
    print("%s%s: %s\n", names[which], (flags & SA_RESTART) != 0 ? " (SA_RESTART)" : "",
          reported == 0 ? "ok" : "FAILED");
}

static timer_t wake_timer, watchdog_timer;
static volatile int woken, watchdog_fired;

static void
wake_handler(int sig)
{
    if (sig == SIGALRM)
        watchdog_fired = 1;
    else
        woken = 1;
}

static timer_t
new_timer(int sig)
{
    struct sigevent sevp;
    timer_t t;
    memset(&sevp, 0, sizeof(sevp));
    sevp.sigev_notify = SIGEV_THREAD_ID;
    sevp.sigev_signo = sig;
    sevp._sigev_un._tid = syscall(SYS_gettid);
    if (timer_create(CLOCK_MONOTONIC, &sevp, &t) != 0) {
        perror("timer_create");
        exit(1);
    }
    return t;
}

static void
arm(timer_t t, uint64_t ns)
{
    struct itimerspec spec = { { 0, 0 },
                               { (time_t)(ns / 1000000000), (long)(ns % 1000000000) } };
    if (timer_settime(t, 0, &spec, NULL) != 0) {
        perror("timer_settime");
        exit(1);
    }
}

/* sigsuspend() with SIGUSR1 aimed at its syscall entry, and SIGUSR2, which it
 * unblocks, sent shortly after to end it if SIGUSR1 came first.  Under DR a
 * sigsuspend restarted after the SIGUSR1 handler must still unblock SIGUSR2,
 * though that handler (with SA_RESTART) does a ppoll whose temporary mask blocks
 * it: a watchdog SIGALRM ending the sigsuspend instead is a failure.
 */
static void
test_sigsuspend(int flags)
{
    struct sigaction act;
    sigset_t orig_mask, mask, usr2;
    struct timespec two_s = { 2, 0 };
    uint64_t delay = 1000;
    int i, reported = 0;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = handler;
    act.sa_flags = SA_SIGINFO | flags;
    handler_waits = (flags & SA_RESTART) != 0;
    sigaction(SIGUSR1, &act, NULL);
    signal(SIGUSR2, wake_handler);
    signal(SIGALRM, wake_handler);
    sigemptyset(&usr2);
    sigaddset(&usr2, SIGUSR2);
    sigprocmask(SIG_BLOCK, &usr2, &orig_mask);
    sigprocmask(SIG_BLOCK, NULL, &mask);
    sigdelset(&mask, SIGUSR2);
    for (i = 0; i < ITERS; i++) {
        int ret, err, before;
        handled = 0;
        woken = 0;
        watchdog_fired = 0;
        arm(watchdog_timer, 1000000000);
        arm(timer, delay);
        arm(wake_timer, delay + 1000000);
        ret = sigsuspend(&mask);
        err = errno;
        before = woken;
        arm(watchdog_timer, 0);
        /* Wait for both signals, taking SIGUSR2 if it is still pending. */
        while (!handled)
            sched_yield();
        if (!woken && sigtimedwait(&usr2, NULL, &two_s) == SIGUSR2)
            woken = 1;
        drain();
        if (ret != -1 || err != EINTR || watchdog_fired || !woken) {
            if (reported++ < MAX_REPORTED) {
                print("sigsuspend: invalid result ret=%d errno=%d watchdog=%d woken=%d "
                      "delay=%lluns\n",
                      ret, ret == -1 ? err : 0, watchdog_fired, woken,
                      (unsigned long long)delay);
            } else
                break;
        }
        /* Aim SIGUSR1 at the syscall entry: SIGUSR2 ended it if SIGUSR1 came first. */
        if (before)
            delay = delay + delay / 4 + 1;
        else
            delay = delay - delay / 4;
        if (delay < 1)
            delay = 1;
        if (delay > 5000000)
            delay = 5000000;
    }
    sigprocmask(SIG_SETMASK, &orig_mask, NULL);
    print("sigsuspend%s: %s\n", (flags & SA_RESTART) != 0 ? " (SA_RESTART)" : "",
          reported == 0 ? "ok" : "FAILED");
}

/* A sleep's remaining time under DR, which may interrupt the sleep itself: an
 * unwritable or NULL rem is not written on success, and rem == req gets what is
 * left after an app signal.
 */
static void
test_rem(void)
{
    struct sigaction act;
    int i, bad = 0;
    for (i = 0; i < 100; i++) {
        struct timespec ts = { 0, 2000000 };
        if (syscall(SYS_nanosleep, &ts, (void *)8) != 0)
            bad++;
        if (syscall(SYS_nanosleep, &ts, NULL) != 0)
            bad++;
    }
    print("sleeps with an unwritable or NULL rem: %s\n", bad == 0 ? "ok" : "FAILED");
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = handler;
    act.sa_flags = SA_SIGINFO;
    handler_waits = 0;
    sigaction(SIGUSR1, &act, NULL);
    bad = 0;
    for (i = 0; i < 50; i++) {
        struct timespec ts = { 0, 50000000 };
        handled = 0;
        arm(timer, 10000000);
        long r = syscall(SYS_nanosleep, &ts, &ts);
        if (!(r == -1 && errno == EINTR && handled && ts.tv_sec == 0 && ts.tv_nsec > 0 &&
              ts.tv_nsec < 50000000))
            bad++;
        drain();
    }
    print("sleep with rem == req: %s\n", bad == 0 ? "ok" : "FAILED");
}

/* Runs fresh code and unmaps it, again and again. */
static void *
flusher(void *arg)
{
    sigset_t all;
    struct timespec pause = { 0, 200000 };
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, NULL);
    while (!flusher_stop) {
        void *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (code == MAP_FAILED) {
            perror("mmap");
            exit(1);
        }
#if defined(AARCH64)
        *(uint32_t *)code = 0xd65f03c0; /* ret */
#elif defined(X86)
        *(unsigned char *)code = 0xc3; /* ret */
#endif
        __builtin___clear_cache((char *)code, (char *)code + 4);
        ((void (*)(void))code)();
        munmap(code, 4096);
        nanosleep(&pause, NULL);
    }
    return NULL;
}

int
main(int argc, const char *argv[])
{
    pthread_t flusher_thread;
    struct sigevent sevp;
    struct epoll_event ev;
    int which;

    if (pipe2(pipefd, O_NONBLOCK) != 0) {
        perror("pipe2");
        return 1;
    }
    epfd = epoll_create1(0);
    ev.events = EPOLLIN;
    ev.data.fd = pipefd[0];
    if (epfd < 0 || epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) != 0) {
        perror("epoll");
        return 1;
    }
    memset(&sevp, 0, sizeof(sevp));
    /* To this thread, not the flusher. */
    sevp.sigev_notify = SIGEV_THREAD_ID;
    sevp.sigev_signo = SIGUSR1;
    sevp._sigev_un._tid = syscall(SYS_gettid);
    if (timer_create(CLOCK_MONOTONIC, &sevp, &timer) != 0) {
        perror("timer_create");
        return 1;
    }
    /* "noflush" runs without the flusher thread; a number picks one wait. */
    int no_flush = 0, only = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "noflush") == 0)
            no_flush = 1;
        else
            only = atoi(argv[i]);
    }
    wake_timer = new_timer(SIGUSR2);
    watchdog_timer = new_timer(SIGALRM);
    if (!no_flush)
        pthread_create(&flusher_thread, NULL, flusher, NULL);
    for (which = 0; which < W_NUM; which++) {
        if (only >= 0 && only != which)
            continue;
        test_wait(which, 0);
        test_wait(which, SA_RESTART);
    }
    if (only < 0 || only == W_NUM) {
        test_sigsuspend(0);
        test_sigsuspend(SA_RESTART);
    }
    if (only < 0 || only == W_NUM + 1)
        test_rem();
    flusher_stop = 1;
    if (!no_flush)
        pthread_join(flusher_thread, NULL);
    print("all done\n");
    return 0;
}

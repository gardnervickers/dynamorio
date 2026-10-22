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

/* PSTATE.DIT across asynchronous signals.  The app sets DIT and issues
 * syscalls DR does not intercept (getuid, getppid) in a loop while an itimer
 * and a POSIX timer fire every few hundred microseconds; its handler leaves the
 * context alone.  Natively the interrupted context of every signal has DIT set,
 * and so does the app after every sigreturn.  Under DR such a syscall goes from
 * d_r_dispatch through fcache_enter into do_syscall, and a signal that arrives
 * on that way (after fcache_enter's check for pending signals, before the
 * syscall instruction) is treated as interrupting the syscall: its frame must
 * keep the interrupted DIT, which our mcontext does not hold.
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef HWCAP_DIT
#    define HWCAP_DIT (1 << 24)
#endif
#define PSTATE_DIT (1ULL << 24)

/* Iterations of the syscall loop, and a time limit for a slow machine. */
#define ITERS 400000
#define MAX_SECONDS 20
/* Natively we see thousands of signals; under DR on a loaded machine fewer. */
#define MIN_SIGNALS 20

static volatile int signals, frames_without_dit, handler_without_dit;

static inline uint64_t
read_dit(void)
{
    uint64_t v;
    __asm__ __volatile__("mrs %0, s3_3_c4_c2_5" : "=r"(v)); /* mrs %0, dit */
    return v & PSTATE_DIT;
}

static inline void
set_dit(void)
{
    /* msr dit, #1: encoded, as assemblers accept the name only for armv8.4-a. */
    __asm__ __volatile__(".inst 0xd503415f" ::: "memory");
}

static void
handler(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    signals++;
    if ((uc->uc_mcontext.pstate & PSTATE_DIT) == 0)
        frames_without_dit++;
    /* The kernel does not change DIT on signal entry. */
    if (read_dit() == 0)
        handler_without_dit++;
}

static double
now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int
main(void)
{
    if ((getauxval(AT_HWCAP) & HWCAP_DIT) == 0) {
        /* Nothing to test: print what a passing run prints. */
        printf("DIT kept across signals\n");
        return 0;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) != 0 || sigaction(SIGRTMIN, &sa, NULL) != 0) {
        perror("sigaction");
        return 1;
    }
    timer_t timer;
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    if (timer_create(CLOCK_MONOTONIC, &sev, &timer) != 0) {
        perror("timer_create");
        return 1;
    }
    /* Before the first signal can arrive: every frame must have DIT set. */
    set_dit();
    struct itimerspec its = { { 0, 170000 }, { 0, 170000 } };
    struct itimerval itv = { { 0, 230 }, { 0, 230 } };
    if (timer_settime(timer, 0, &its, NULL) != 0 ||
        setitimer(ITIMER_REAL, &itv, NULL) != 0) {
        perror("timer setup");
        return 1;
    }

    int lost_after_syscall = 0;
    double start = now();
    for (int i = 0; i < ITERS; i++) {
        syscall((i & 1) ? SYS_getuid : SYS_getppid);
        if (read_dit() == 0) {
            lost_after_syscall++;
            set_dit();
        }
        if ((i & 0xfff) == 0 && now() - start > MAX_SECONDS)
            break;
    }
    int lost = read_dit() == 0;

    memset(&itv, 0, sizeof(itv));
    memset(&its, 0, sizeof(its));
    setitimer(ITIMER_REAL, &itv, NULL);
    timer_settime(timer, 0, &its, NULL);
    timer_delete(timer);

    if (signals < MIN_SIGNALS)
        printf("only %d signals arrived\n", signals);
    if (frames_without_dit > 0 || handler_without_dit > 0 || lost_after_syscall > 0 ||
        lost) {
        printf("DIT lost: %d of %d frames, %d handlers, %d times after a syscall%s\n",
               frames_without_dit, signals, handler_without_dit, lost_after_syscall,
               lost ? ", at the end" : "");
    } else
        printf("DIT kept across signals\n");
    if (getenv("A64_DIT_SIGNAL_VERBOSE") != NULL)
        fprintf(stderr, "%d signals\n", signals);
    return 0;
}

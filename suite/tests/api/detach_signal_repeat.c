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

/* Detaches repeatedly while threads keep sending themselves a signal whose
 * handler runs on a sigaltstack of SIGSTKSZ.  It tests two detach races:
 *
 * - A thread's handler returns through rt_sigreturn, which DR rewrites to come
 *   back to DR.  If the detach finds the thread at that sigreturn's syscall
 *   instruction it must not treat it as a native syscall to restart there: the
 *   thread would reissue the rewritten sigreturn after its DR state is gone.
 * - A signal can enter DR's handler just before the detach reinstates the app's
 *   handlers and only be delivered natively once the detach has finished.  DR
 *   must then deliver it from the frame it is on: a copy of the frame does not
 *   fit on such a small sigaltstack (i#6814) and is fatal.
 *
 * Repeating the detach with many signals in flight makes both likely.
 *
 * DR's debug build needs more of a native thread's sigaltstack in its own handler,
 * before it delivers the signal, than SIGSTKSZ leaves (about 20K below the kernel's
 * frame on AArch64), so it gets a larger sigaltstack and only a release build
 * tests that we do not copy the frame.
 */

/* As tools.h does: SIGSTKSZ is then sysconf(_SC_SIGSTKSZ), as for C++ apps. */
#define _GNU_SOURCE 1
#include "configure.h"
#include "dr_api.h"
#include "tools.h"
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NUM_THREADS 8
#define NUM_ROUNDS 5
#ifdef DEBUG
#    define ALT_STACK_SIZE (64 * 1024)
#else
#    define ALT_STACK_SIZE SIGSTKSZ
#endif

static atomic_int round_exit;
static atomic_int threads_ready;
static atomic_long handled;

static void
handle_signal(int sig, siginfo_t *info, void *ucxt)
{
    atomic_fetch_add(&handled, 1);
}

static void *
thread_func(void *arg)
{
    size_t size = ALT_STACK_SIZE;
    stack_t ss;
    ss.ss_sp = malloc(size);
    ss.ss_size = size;
    ss.ss_flags = 0;
    if (ss.ss_sp == NULL || sigaltstack(&ss, NULL) != 0) {
        print("sigaltstack failed\n");
        exit(1);
    }
    atomic_fetch_add(&threads_ready, 1);
    while (!atomic_load(&round_exit))
        pthread_kill(pthread_self(), SIGUSR2);
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, NULL);
    free(ss.ss_sp);
    return NULL;
}

static void
sleep_ms(int ms)
{
    struct timespec ts = { 0, ms * 1000 * 1000 };
    nanosleep(&ts, NULL);
}

int
main(void)
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = handle_signal;
    act.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGUSR2, &act, NULL) != 0) {
        print("sigaction failed\n");
        return 1;
    }
    /* Set DETACH_SIGNAL_REPEAT_VERBOSE to see which phase a failure is in. */
    bool verbose = getenv("DETACH_SIGNAL_REPEAT_VERBOSE") != NULL;
    for (int round = 0; round < NUM_ROUNDS; round++) {
        pthread_t threads[NUM_THREADS];
        atomic_store(&round_exit, 0);
        atomic_store(&threads_ready, 0);
        for (int i = 0; i < NUM_THREADS; i++) {
            if (pthread_create(&threads[i], NULL, thread_func, NULL) != 0) {
                print("pthread_create failed\n");
                return 1;
            }
        }
        while (atomic_load(&threads_ready) < NUM_THREADS)
            sleep_ms(1);
        if (verbose)
            print("round %d: attaching\n", round);
        dr_app_setup();
        dr_app_start();
        if (verbose)
            print("round %d: attached\n", round);
        sleep_ms(20);
        if (verbose)
            print("round %d: detaching\n", round);
        dr_app_stop_and_cleanup();
        if (verbose)
            print("round %d: detached\n", round);
        /* Keep the signals coming while late deliveries drain. */
        sleep_ms(10);
        atomic_store(&round_exit, 1);
        for (int i = 0; i < NUM_THREADS; i++)
            pthread_join(threads[i], NULL);
    }
    print("signals handled: %s\n", atomic_load(&handled) > 0 ? "some" : "none");
    print("all done\n");
    return 0;
}

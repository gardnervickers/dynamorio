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


/* Detaches repeatedly while threads keep sending themselves two real-time signals
 * each, some of them late enough in a detach to be delivered natively.  One has a
 * one-shot (SA_RESETHAND) handler on the sigaltstack that re-arms itself, for its
 * thread alone, so after each detach the action must still be that handler.  The
 * other has a handler without SA_ONSTACK, which we deliver from a copied frame.
 * Half of the threads have an SS_AUTODISARM sigaltstack.
 */

#define _GNU_SOURCE 1
#include "configure.h"
#include "dr_api.h"
#include "tools.h"
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef SS_AUTODISARM
#    define SS_AUTODISARM (1U << 31)
#endif

#define NUM_THREADS 4
#define NUM_ROUNDS 5
#define ALT_STACK_SIZE (64 * 1024)

static atomic_int attached;
static atomic_int round_exit;
static atomic_int threads_ready;

static void
install(int sig, void (*handler)(int, siginfo_t *, void *), int flags)
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = handler;
    act.sa_flags = SA_SIGINFO | flags;
    sigemptyset(&act.sa_mask);
    if (sigaction(sig, &act, NULL) != 0) {
        print("sigaction failed\n");
        exit(1);
    }
}

static void *
current_handler(int sig)
{
    struct sigaction old;
    if (sigaction(sig, NULL, &old) != 0)
        return NULL;
    return (void *)old.sa_handler;
}

static void
sleep_ms(int ms)
{
    struct timespec ts = { 0, ms * 1000 * 1000 };
    nanosleep(&ts, NULL);
}

static void
handle_rearm(int sig, siginfo_t *info, void *ucxt)
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = handle_rearm;
    act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    sigemptyset(&act.sa_mask);
    sigaction(sig, &act, NULL);
}

static void
handle_plain(int sig, siginfo_t *info, void *ucxt)
{
}

static void *
thread_func(void *arg)
{
    int i = (int)(ptr_int_t)arg;
    stack_t ss;
    ss.ss_sp = malloc(ALT_STACK_SIZE);
    ss.ss_size = ALT_STACK_SIZE;
    ss.ss_flags = (i % 2 == 1) ? SS_AUTODISARM : 0;
    if (ss.ss_sp == NULL || sigaltstack(&ss, NULL) != 0) {
        print("sigaltstack failed\n");
        exit(1);
    }
    atomic_fetch_add(&threads_ready, 1);
    /* Not during the attach: a handler re-arming itself natively races with our
     * reading the app's actions there.
     */
    while (!atomic_load(&attached))
        sleep_ms(1);
    while (!atomic_load(&round_exit)) {
        pthread_kill(pthread_self(), SIGRTMIN + 2 * i);
        pthread_kill(pthread_self(), SIGRTMIN + 2 * i + 1);
    }
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, NULL);
    free(ss.ss_sp);
    return NULL;
}

static void
run_rounds(void)
{
    bool lost_handler = false;
    for (int i = 0; i < NUM_THREADS; i++) {
        install(SIGRTMIN + 2 * i, handle_rearm, SA_ONSTACK | SA_RESETHAND);
        install(SIGRTMIN + 2 * i + 1, handle_plain, 0);
    }
    for (int round = 0; round < NUM_ROUNDS; round++) {
        pthread_t threads[NUM_THREADS];
        atomic_store(&attached, 0);
        atomic_store(&round_exit, 0);
        atomic_store(&threads_ready, 0);
        for (int i = 0; i < NUM_THREADS; i++) {
            if (pthread_create(&threads[i], NULL, thread_func, (void *)(ptr_int_t)i) !=
                0) {
                print("pthread_create failed\n");
                exit(1);
            }
        }
        while (atomic_load(&threads_ready) < NUM_THREADS)
            sleep_ms(1);
        dr_app_setup();
        dr_app_start();
        atomic_store(&attached, 1);
        sleep_ms(20);
        dr_app_stop_and_cleanup();
        /* Keep the signals coming while late deliveries drain. */
        sleep_ms(10);
        atomic_store(&round_exit, 1);
        for (int i = 0; i < NUM_THREADS; i++)
            pthread_join(threads[i], NULL);
        for (int i = 0; i < NUM_THREADS; i++) {
            if (current_handler(SIGRTMIN + 2 * i) != (void *)handle_rearm)
                lost_handler = true;
        }
    }
    print("%s\n", lost_handler ? "a re-armed one-shot handler was lost" : "ok");
}

int
main(void)
{
    run_rounds();
    print("all done\n");
    return 0;
}

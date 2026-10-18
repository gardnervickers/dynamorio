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

/* PSTATE.DIT of a thread that is not the one detaching.  A sideline thread sets
 * DIT and checks it after every iteration of a loop of syscalls while the main
 * thread attaches and detaches static DR around it.  Each syscall takes the
 * sideline through d_r_dispatch, where it waits for the pending detach at a safe
 * spot with the context we saved there, which has only NZCV of PSTATE.  Detach
 * writes the sideline's translated context back into its suspended frame: the
 * app's DIT must be kept from that frame.
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "dr_api.h"

#ifndef HWCAP_DIT
#    define HWCAP_DIT (1 << 24)
#endif
#define PSTATE_DIT (1ULL << 24)

#define CYCLES 12

/* Shared with the sideline thread: sideline_ready publishes its DIT setup
 * (release/acquire), sideline_exit and iters need no ordering (relaxed), and
 * lost is read after the join.
 */
static int sideline_exit, sideline_ready, iters;
static int lost;

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
sleep_us(long us)
{
    struct timespec ts = { 0, us * 1000 };
    nanosleep(&ts, NULL);
}

static void *
sideline(void *arg)
{
    set_dit();
    __atomic_store_n(&sideline_ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&sideline_exit, __ATOMIC_RELAXED)) {
        syscall(SYS_getppid);
        __atomic_fetch_add(&iters, 1, __ATOMIC_RELAXED);
        if (read_dit() == 0) {
            lost++;
            set_dit();
        }
    }
    return NULL;
}

int
main(void)
{
    if ((getauxval(AT_HWCAP) & HWCAP_DIT) == 0) {
        /* Nothing to test: print what a passing run prints. */
        printf("DIT kept\n");
        return 0;
    }
    int total_lost = 0, cycles_lost = 0;
    for (int c = 0; c < CYCLES; c++) {
        pthread_t thread;
        /* Set before the thread exists: pthread_create() orders these. */
        sideline_exit = 0;
        sideline_ready = 0;
        lost = 0;
        if (pthread_create(&thread, NULL, sideline, NULL) != 0) {
            perror("pthread_create");
            return 1;
        }
        dr_app_setup();
        while (!__atomic_load_n(&sideline_ready, __ATOMIC_ACQUIRE))
            sleep_us(100);
        dr_app_start();
        sleep_us(20000);
        dr_app_stop_and_cleanup();
        /* Native again: the sideline checks the DIT the detach left it. */
        int at_detach = __atomic_load_n(&iters, __ATOMIC_RELAXED);
        while (__atomic_load_n(&iters, __ATOMIC_RELAXED) < at_detach + 100)
            sleep_us(100);
        __atomic_store_n(&sideline_exit, 1, __ATOMIC_RELAXED);
        pthread_join(thread, NULL);
        total_lost += lost;
        cycles_lost += lost > 0;
    }
    if (total_lost > 0)
        printf("DIT lost %d times, in %d of %d detaches\n", total_lost, cycles_lost,
               CYCLES);
    else
        printf("DIT kept\n");
    return 0;
}

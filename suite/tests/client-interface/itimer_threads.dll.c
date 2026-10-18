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
 * A client with a 1ms DR timer on each of the three itimers, alongside the app's
 * own (see itimer_threads.c), so that DR multiplexes every one of them and
 * re-arms the kernel's timer by hand on most alarms.  It checks that each timer
 * keeps firing for the whole run, not just at its start.  It also suspends all
 * other threads whenever the app calls getppid, so that suspensions and alarms
 * meet threads in DR's itimer code.
 */

#include "dr_api.h"
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/time.h>

static const char *const name[3] = { "real", "virtual", "prof" };

static uint64 start_ms;
static uint fired[3];
static uint64 first_ms[3];
static uint64 last_ms[3];
static uint suspensions;

static void
fire(int which)
{
    uint64 now = dr_get_milliseconds();
    uint64 expected = 0;
    __atomic_compare_exchange_n(&first_ms[which], &expected, now, false, __ATOMIC_RELAXED,
                                __ATOMIC_RELAXED);
    __atomic_store_n(&last_ms[which], now, __ATOMIC_RELAXED);
    __atomic_add_fetch(&fired[which], 1, __ATOMIC_RELAXED);
}

static void
event_real(void *drcontext, dr_mcontext_t *mcontext)
{
    fire(ITIMER_REAL);
}

static void
event_virtual(void *drcontext, dr_mcontext_t *mcontext)
{
    fire(ITIMER_VIRTUAL);
}

static void
event_prof(void *drcontext, dr_mcontext_t *mcontext)
{
    fire(ITIMER_PROF);
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return sysnum == SYS_getppid;
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    if (sysnum != SYS_getppid)
        return true;
    void **drcontexts;
    uint num;
    if (dr_suspend_all_other_threads_ex(&drcontexts, &num, NULL, DR_SUSPEND_NATIVE)) {
        __atomic_add_fetch(&suspensions, 1, __ATOMIC_RELAXED);
        if (!dr_resume_all_other_threads(drcontexts, num))
            dr_fprintf(STDERR, "failed to resume threads\n");
    }
    return true;
}

static void
event_exit(void)
{
    uint64 run_ms = dr_get_milliseconds() - start_ms;
    bool ok = true;
    for (int which = 0; which < 3; which++) {
        uint count = __atomic_load_n(&fired[which], __ATOMIC_RELAXED);
        uint64 first = __atomic_load_n(&first_ms[which], __ATOMIC_RELAXED);
        uint64 last = __atomic_load_n(&last_ms[which], __ATOMIC_RELAXED);
        /* Each timer must have fired many times, from early in the run to late
         * in it.
         */
        if (count < 20 || last - first < run_ms / 2) {
            dr_fprintf(STDERR,
                       "client %s timer: %u callbacks from %llu to %llu ms of %llu\n",
                       name[which], count, (unsigned long long)(first - start_ms),
                       (unsigned long long)(last - start_ms), (unsigned long long)run_ms);
            ok = false;
        }
    }
    if (ok)
        dr_fprintf(STDERR, "client timers kept firing\n");
    if (__atomic_load_n(&suspensions, __ATOMIC_RELAXED) > 0)
        dr_fprintf(STDERR, "client suspended threads\n");
    else
        dr_fprintf(STDERR, "client never suspended threads\n");
}

DR_EXPORT
void
dr_init(client_id_t id)
{
    start_ms = dr_get_milliseconds();
    dr_register_exit_event(event_exit);
    dr_register_filter_syscall_event(event_filter_syscall);
    dr_register_pre_syscall_event(event_pre_syscall);
    if (!dr_set_itimer(ITIMER_REAL, 1, event_real) ||
        !dr_set_itimer(ITIMER_VIRTUAL, 1, event_virtual) ||
        !dr_set_itimer(ITIMER_PROF, 1, event_prof))
        dr_fprintf(STDERR, "unable to set timer callback\n");
}

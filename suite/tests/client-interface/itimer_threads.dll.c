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
 * re-arms the kernel's timer by hand on most alarms.
 */

#include "dr_api.h"
#include <sys/time.h>

static volatile int fired[3];

static void
event_real(void *drcontext, dr_mcontext_t *mcontext)
{
    fired[ITIMER_REAL] = 1;
}

static void
event_virtual(void *drcontext, dr_mcontext_t *mcontext)
{
    fired[ITIMER_VIRTUAL] = 1;
}

static void
event_prof(void *drcontext, dr_mcontext_t *mcontext)
{
    fired[ITIMER_PROF] = 1;
}

static void
event_exit(void)
{
    if (fired[ITIMER_REAL] && fired[ITIMER_VIRTUAL] && fired[ITIMER_PROF])
        dr_fprintf(STDERR, "client timers fired\n");
    else {
        dr_fprintf(STDERR, "client timers fired: real=%d virtual=%d prof=%d\n",
                   fired[ITIMER_REAL], fired[ITIMER_VIRTUAL], fired[ITIMER_PROF]);
    }
}

DR_EXPORT
void
dr_init(client_id_t id)
{
    dr_register_exit_event(event_exit);
    if (!dr_set_itimer(ITIMER_REAL, 1, event_real) ||
        !dr_set_itimer(ITIMER_VIRTUAL, 1, event_virtual) ||
        !dr_set_itimer(ITIMER_PROF, 1, event_prof))
        dr_fprintf(STDERR, "unable to set timer callback\n");
}

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
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* A signal that arrives during a clean call's callee is queued: it must still be
 * delivered once the callee returns, although the app then runs a loop that is
 * linked in the code cache and never returns to DR by itself.  The client
 * instruments each probe below with a clean call in which a SIGUSR1 arrives, once
 * the loop has run long enough to be linked (see the client).  Each loop is bounded
 * so that a lost signal fails the test instead of hanging it.
 */

#include "tools.h"
#include <signal.h>
#include <ucontext.h>

#define MAX_VISITS 50000000

static volatile sig_atomic_t handled;

static void
handler(int sig, siginfo_t *info, ucontext_t *ucxt)
{
    if (sig == SIGUSR1)
        handled++;
}

/* The callee sends the signal itself: it makes calls, so the clean call has an
 * out-of-line context switch.
 */
EXPORT NOINLINE void
probe_out_of_line(void)
{
    __asm__ __volatile__("" ::: "memory");
}

/* The callee is a leaf, which spins while a client thread sends the signal: the
 * clean call saves only a few registers, inline.
 */
EXPORT NOINLINE void
probe_inline(void)
{
    __asm__ __volatile__("" ::: "memory");
}

static void
run(const char *name, void (*probe)(void))
{
    int visits;
    handled = 0;
    for (visits = 0; handled == 0 && visits < MAX_VISITS; visits++)
        probe();
    /* A lost signal is delivered once the bounded loop exits to DR, so judge it by
     * the visits instead.
     */
    print("%s: %s\n", name,
          visits < MAX_VISITS ? "delivered in the loop" : "lost after the clean call");
}

int
main(int argc, char *argv[])
{
    intercept_signal(SIGUSR1, handler, false);
    run("out-of-line", probe_out_of_line);
    run("inline", probe_inline);
    print("all done\n");
    return 0;
}

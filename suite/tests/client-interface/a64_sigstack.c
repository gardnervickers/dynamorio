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
 * The app for client.a64_sigstack (see a64_sigstack.dll.c): faults in the
 * code cache, which DR translates on its signal stack, and resumes after the
 * faulting load.
 */

#include "tools.h"
#include <signal.h>
#include <ucontext.h>

#define FAULTS 100

static volatile int faults;

static void
handle_segv(int sig, siginfo_t *info, ucontext_t *uc)
{
    faults++;
    uc->uc_mcontext.pc += 4; /* Past the load. */
}

static long __attribute__((noinline))
fault_once(long x)
{
    long v;
    __asm__ volatile("add %0, %1, #1\n\t"
                     "mov x9, #0\n\t"
                     "ldr %0, [x9]\n\t" /* Faults: the handler skips it. */
                     "add %0, %0, #2\n\t"
                     : "=&r"(v)
                     : "r"(x)
                     : "x9", "memory");
    return v;
}

int
main(void)
{
    long sum = 0;
    intercept_signal(SIGSEGV, handle_segv, false);
    for (int i = 0; i < FAULTS; i++)
        sum += fault_once(i);
    print("faults: %d, sum: %ld\n", faults, sum);
    return 0;
}

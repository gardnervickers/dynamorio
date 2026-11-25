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

/* dr_redirect_entry(): a clean call that resumes at a block's code cache entry
 * without going through the dispatcher.  The client (redirect_entry.dll.c) takes
 * over the blocks at the probes below once arm() has named a scenario:
 *
 * - probe_state: with every general-purpose register, the flags and the SIMD
 *   registers holding distinct values, entered directly and from another
 *   fragment (probe_from); the probe then stores them all.
 * - probe_plain: the cases in which DR must refuse an entry, and a registered
 *   kernel transfer event, which is not one of them.
 * - probe_spin, spin, spin_from and probe_read: a signal arrives after DR has
 *   returned an entry and before the thread is in the fragment.  It must be
 *   delivered at once although the destination is a loop that is linked in the
 *   code cache, or a block that would block in a system call.
 *
 * Every wait is for an event or bounded by a count: a lost signal fails the test
 * instead of hanging it.
 */

#include "tools.h"
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

/* Must match the client. */
enum {
    MODE_NONE,
    MODE_STATE,
    MODE_FRAGMENT_STATE,
    MODE_NO_FRAGMENT,
    MODE_PENDING_SIGNAL,
    MODE_KERNEL_XFER,
    MODE_SIGNAL_ROUTINE,
    MODE_SIGNAL_FRAGMENT,
    MODE_SIGNAL_BLOCKING,
    MODE_PENDING_FLUSH,
    MODE_SYNCH,
    MODE_REPORT,
};

/* The loops are linked well before this many visits. */
#define WARM_VISITS 8192
#define MAX_VISITS 50000000
/* Bounds a blocking read whose signal was lost. */
#define CONTAINMENT_SECONDS 60

/* The register image that redirect_state_* loads and probe_state stores, in
 * 8-byte words: x0-x30, SP, NZCV, FPSR, FPCR, a pad, then q0-q31.
 */
enum {
    IMAGE_SP = 31,
    IMAGE_NZCV,
    IMAGE_FPSR,
    IMAGE_FPCR,
    IMAGE_SIMD = 36,
    IMAGE_WORDS = 100
};

static volatile sig_atomic_t handled, timed_out;
static int wake_pipe[2] = { -1, -1 };

static void
handler(int sig, siginfo_t *info, ucontext_t *ucxt)
{
    if (sig == SIGUSR1) {
        handled++;
        if (wake_pipe[1] != -1 && write(wake_pipe[1], "S", 1) != 1)
            timed_out = 1;
    } else if (sig == SIGALRM)
        timed_out = 1;
}

/* Tells the client which scenario the next probe runs. */
EXPORT NOINLINE void
arm(long mode)
{
    __asm__ __volatile__("" ::: "memory");
}

EXPORT NOINLINE void
probe_plain(void)
{
    __asm__ __volatile__("" ::: "memory");
}

EXPORT NOINLINE void
probe_spin(void)
{
    __asm__ __volatile__("" ::: "memory");
}

/* Never called: it has no fragment. */
EXPORT NOINLINE void
never_run(void)
{
    __asm__ __volatile__("" ::: "memory");
}

/* The code the flushes are for. */
EXPORT NOINLINE void
flush_target(void)
{
    __asm__ __volatile__("" ::: "memory");
}

/* Its block flushes flush_target() from another thread. */
EXPORT NOINLINE void
flush_marker(void)
{
    __asm__ __volatile__("" ::: "memory");
}

/* Returns whether the signal ended the loop. */
EXPORT NOINLINE int
spin(long limit)
{
    long visits;
    for (visits = 0; handled == 0 && visits < limit; visits++)
        probe_spin();
    return visits < limit;
}

/* The client redirects its entry to spin(), with the same argument. */
EXPORT NOINLINE int
spin_from(long limit)
{
    __asm__ __volatile__("" ::: "memory");
    return -1;
}

/* read(fd, buf, count), with the system call number in the block. */
ssize_t
probe_read(int fd, void *buf, size_t count);

int
redirect_state_direct(uint64_t *in, uint64_t *out);
int
redirect_state_from(uint64_t *in, uint64_t *out);

/* clang-format off */
__asm__(
    ".text\n"
    ".globl probe_read\n"
    ".type probe_read, %function\n"
    "probe_read:\n"
    "mov x8, #63\n"
    "svc #0\n"
    "ret\n"
    ".size probe_read, .-probe_read\n"

    /* Loads the image at x0 into the registers, then reaches \target by a
     * conditional branch, which always ends a block.  The frame holds the image
     * that probe_state stores (800 bytes), x19-x30 (800), d8-d15 (896) and the
     * out pointer (960).
     */
    ".macro redirect_state name, target\n"
    ".globl \\name\n"
    ".type \\name, %function\n"
    "\\name:\n"
    "mov x9, sp\n"
    "str x9, [x0, #248]\n"
    "sub sp, sp, #976\n"
    ".irp n,19,20,21,22,23,24,25,26,27,28,29,30\n"
    "str x\\n, [sp, #(800 + 8 * (\\n - 19))]\n"
    ".endr\n"
    ".irp n,8,9,10,11,12,13,14,15\n"
    "str d\\n, [sp, #(896 + 8 * (\\n - 8))]\n"
    ".endr\n"
    "str x1, [sp, #960]\n"
    ".irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,"
    "28,29,30,31\n"
    "ldr q\\n, [x0, #(288 + 16 * \\n)]\n"
    ".endr\n"
    "ldr x1, [x0, #256]\n"
    "msr nzcv, x1\n"
    "ldr x1, [x0, #264]\n"
    "msr fpsr, x1\n"
    "ldr x1, [x0, #272]\n"
    "msr fpcr, x1\n"
    ".irp n,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,"
    "29,30\n"
    "ldr x\\n, [x0, #(8 * \\n)]\n"
    ".endr\n"
    "ldr x0, [x0]\n"
    "cbnz x0, \\target\n"
    "brk #1\n"
    ".size \\name, .-\\name\n"
    ".endm\n"
    "redirect_state redirect_state_direct, probe_state\n"
    "redirect_state redirect_state_from, probe_from\n"

    ".globl probe_state\n"
    ".type probe_state, %function\n"
    "probe_state:\n"
    ".irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,"
    "29,30\n"
    "str x\\n, [sp, #(8 * \\n)]\n"
    ".endr\n"
    "add x0, sp, #976\n"
    "str x0, [sp, #248]\n"
    "mrs x0, nzcv\n"
    "str x0, [sp, #256]\n"
    "mrs x0, fpsr\n"
    "str x0, [sp, #264]\n"
    "mrs x0, fpcr\n"
    "str x0, [sp, #272]\n"
    ".irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,"
    "29,30,31\n"
    "str q\\n, [sp, #(288 + 16 * \\n)]\n"
    ".endr\n"
    "msr fpcr, xzr\n"
    "msr fpsr, xzr\n"
    "ldr x1, [sp, #960]\n"
    "mov x2, #0\n"
    "1:\n"
    "ldr x3, [sp, x2, lsl #3]\n"
    "str x3, [x1, x2, lsl #3]\n"
    "add x2, x2, #1\n"
    "cmp x2, #100\n"
    "b.ne 1b\n"
    "mov w0, #0\n"
    "2:\n"
    ".irp n,19,20,21,22,23,24,25,26,27,28,29,30\n"
    "ldr x\\n, [sp, #(800 + 8 * (\\n - 19))]\n"
    ".endr\n"
    ".irp n,8,9,10,11,12,13,14,15\n"
    "ldr d\\n, [sp, #(896 + 8 * (\\n - 8))]\n"
    ".endr\n"
    "add sp, sp, #976\n"
    "ret\n"
    ".size probe_state, .-probe_state\n"

    /* Reached only if the client did not redirect it to probe_state. */
    ".globl probe_from\n"
    ".type probe_from, %function\n"
    "probe_from:\n"
    "msr fpcr, xzr\n"
    "msr fpsr, xzr\n"
    "mov w0, #1\n"
    "b 2b\n"
    ".size probe_from, .-probe_from\n");
/* clang-format on */

static void
run_state(const char *name, int (*enter)(uint64_t *, uint64_t *), long mode)
{
    uint64_t in[IMAGE_WORDS], out[IMAGE_WORDS];
    int i;
    for (i = 0; i <= 30; i++)
        in[i] = UINT64_C(0x5eed000000000100) * (i + 1) + i;
    in[IMAGE_SP] = 0;            /* Filled in by the entry routine. */
    in[IMAGE_NZCV] = 0x60000000; /* Z and C. */
    in[IMAGE_FPSR] = 0x0800001f; /* QC and the cumulative exception flags. */
    in[IMAGE_FPCR] = 0x00400000; /* Round towards plus infinity. */
    in[IMAGE_FPCR + 1] = 0;
    for (i = IMAGE_SIMD; i < IMAGE_WORDS; i++)
        in[i] = UINT64_C(0xa5a5000000000000) + UINT64_C(0x0101010101) * i;
    memset(out, 0, sizeof(out));
    arm(mode);
    if (enter(in, out) != 0) {
        print("%s: not redirected\n", name);
        return;
    }
    out[IMAGE_FPCR + 1] = 0;
    for (i = 0; i < IMAGE_WORDS; i++) {
        if (in[i] != out[i]) {
            print("%s: word %d is 0x%016llx, expected 0x%016llx\n", name, i,
                  (unsigned long long)out[i], (unsigned long long)in[i]);
            return;
        }
    }
    print("%s: registers, flags and SIMD preserved\n", name);
}

/* Runs probe_plain for a scenario that the client reports by itself. */
static void
run_plain(long mode)
{
    arm(mode);
    probe_plain();
}

static void *
flusher(void *arg)
{
    flush_marker();
    return NULL;
}

int
main(int argc, char *argv[])
{
    pthread_t thread;
    char byte = 0;
    intercept_signal(SIGUSR1, handler, false);
    intercept_signal(SIGALRM, handler, false);

    run_state("state", redirect_state_direct, MODE_STATE);
    run_state("fragment to fragment", redirect_state_from, MODE_FRAGMENT_STATE);

    run_plain(MODE_NO_FRAGMENT);

    handled = 0;
    run_plain(MODE_PENDING_SIGNAL);
    print("pending signal: %s\n", handled == 1 ? "delivered" : "not delivered once");

    run_plain(MODE_KERNEL_XFER);
    arm(MODE_REPORT);

    /* Link the loop, then take the signal in it. */
    handled = 0;
    spin(WARM_VISITS);
    arm(MODE_SIGNAL_ROUTINE);
    print("signal after the entry, routine: %s\n",
          spin(MAX_VISITS) ? "delivered in the loop" : "lost");

    handled = 0;
    spin(WARM_VISITS);
    arm(MODE_SIGNAL_FRAGMENT);
    print("signal after the entry, fragment to fragment: %s\n",
          spin_from(MAX_VISITS) == 1 ? "delivered in the loop" : "lost");

    /* The handler's byte is the only thing to read: a lost signal leaves the
     * read blocked until the alarm.
     */
    handled = 0;
    if (pipe(wake_pipe) != 0)
        print("pipe failed\n");
    alarm(CONTAINMENT_SECONDS);
    arm(MODE_SIGNAL_BLOCKING);
    if (probe_read(wake_pipe[0], &byte, 1) != 1)
        byte = 0;
    alarm(0);
    print("signal after the entry, blocking destination: %s\n",
          byte == 'S' && handled == 1 && timed_out == 0
              ? "delivered before the system call"
              : "lost");
    close(wake_pipe[0]);
    close(wake_pipe[1]);
    wake_pipe[1] = -1;

    flush_target();
    run_plain(MODE_PENDING_FLUSH);

    flush_target();
    if (pthread_create(&thread, NULL, flusher, NULL) != 0)
        print("pthread_create failed\n");
    run_plain(MODE_SYNCH);
    pthread_join(thread, NULL);
    arm(MODE_REPORT);

    print("all done\n");
    return 0;
}

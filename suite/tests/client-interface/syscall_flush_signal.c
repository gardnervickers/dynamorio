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

/* A thread blocked in an ignorable system call that runs inside the code cache,
 * in a block that -shared_ignorable_syscall_bbs makes a shared fragment, while
 * another thread flushes that block and then signals it.  Each round checks that
 * the signal is delivered once, that the read is interrupted (EINTR) or
 * restarted and completed (SA_RESTART), and that every register the system call
 * preserves still holds its value.  The rounds cover both of the client's
 * synchronous flushes: dr_flush_region(), which suspends every thread, and
 * dr_unlink_flush_region(), which leaves the blocked thread where it is and
 * frees the fragment once that thread has left the cache.
 *
 * The second thread acts only on events: the first thread blocked in read()
 * (from its /proc syscall file), the flush done (the marker returns), and the
 * handler run.  Each poll is bounded by a count.
 */

#include "tools.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define MAX_POLLS 20000000

/* Must match the client. */
enum { FLUSH_SYNCHALL, FLUSH_UNLINK };

/* The register image of blocking_read(): x0-x30, then NZCV. */
enum { IMAGE_NZCV = 31, IMAGE_WORDS = 32 };

static volatile sig_atomic_t handled;
static volatile pid_t reader_tid, handler_tid;
static int data_pipe[2];

typedef struct {
    int flush;
    bool restart;
    bool failed;
} round_t;

static void
handler(int sig, siginfo_t *info, void *ucxt)
{
    handler_tid = syscall(SYS_gettid);
    handled++;
}

/* Its block flushes blocking_svc's from the calling thread. */
EXPORT NOINLINE void
flush_marker(long kind)
{
    __asm__ __volatile__("" ::: "memory");
}

/* read(fd, buf, 1) with the registers that a system call preserves loaded from
 * in; stores every register and the flags to out afterwards and returns the
 * system call's raw result.  The read's own block starts at blocking_svc.
 */
long
blocking_read(int fd, void *buf, uint64_t *in, uint64_t *out);

/* clang-format off */
__asm__(
    ".text\n"
    ".globl blocking_read\n"
    ".type blocking_read, %function\n"
    "blocking_read:\n"
    /* The frame: the stored image (256 bytes), x19-x30 (256) and out (352). */
    "sub sp, sp, #368\n"
    ".irp n,19,20,21,22,23,24,25,26,27,28,29,30\n"
    "str x\\n, [sp, #(256 + 8 * (\\n - 19))]\n"
    ".endr\n"
    "str x3, [sp, #352]\n"
    "mov x9, x2\n"
    "ldr x8, [x9, #248]\n"
    "msr nzcv, x8\n"
    ".irp n,3,4,5,6,7,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30\n"
    "ldr x\\n, [x9, #(8 * \\n)]\n"
    ".endr\n"
    "mov x2, #1\n"
    "ldr x9, [x9, #72]\n"
    /* A conditional branch always ends a block. */
    "cbnz x9, blocking_svc\n"
    "brk #1\n"
    ".globl blocking_svc\n"
    ".type blocking_svc, %function\n"
    "blocking_svc:\n"
    "mov x8, #63\n"
    "svc #0\n"
    ".irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,"
    "29,30\n"
    "str x\\n, [sp, #(8 * \\n)]\n"
    ".endr\n"
    "mrs x0, nzcv\n"
    "str x0, [sp, #248]\n"
    "ldr x1, [sp, #352]\n"
    "mov x2, #0\n"
    "1:\n"
    "ldr x3, [sp, x2, lsl #3]\n"
    "str x3, [x1, x2, lsl #3]\n"
    "add x2, x2, #1\n"
    "cmp x2, #32\n"
    "b.ne 1b\n"
    "ldr x0, [sp]\n"
    ".irp n,19,20,21,22,23,24,25,26,27,28,29,30\n"
    "ldr x\\n, [sp, #(256 + 8 * (\\n - 19))]\n"
    ".endr\n"
    "add sp, sp, #368\n"
    "ret\n"
    ".size blocking_svc, .-blocking_svc\n"
    ".size blocking_read, .-blocking_read\n");
/* clang-format on */

/* Waits until the reader is blocked in read(data_pipe[0]). */
static bool
wait_until_blocked(void)
{
    char path[64], line[128];
    long polls;
    snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", (int)reader_tid);
    for (polls = 0; polls < MAX_POLLS; polls++) {
        int fd = open(path, O_RDONLY);
        ssize_t len = fd == -1 ? -1 : read(fd, line, sizeof(line) - 1);
        if (fd != -1)
            close(fd);
        if (len > 0) {
            long number = -1;
            unsigned long arg0 = ~0UL;
            line[len] = '\0';
            if (sscanf(line, "%ld %lx", &number, &arg0) == 2 && number == SYS_read &&
                arg0 == (unsigned long)data_pipe[0])
                return true;
        }
        sched_yield();
    }
    return false;
}

static void *
second_thread(void *arg)
{
    round_t *round = (round_t *)arg;
    long polls;
    for (polls = 0; reader_tid == 0 && polls < MAX_POLLS; polls++)
        sched_yield();
    if (!wait_until_blocked())
        round->failed = true;
    flush_marker(round->flush);
    /* A flush that suspended the reader made it issue the read again. */
    if (!wait_until_blocked())
        round->failed = true;
    if (syscall(SYS_tgkill, getpid(), reader_tid, SIGUSR1) != 0)
        round->failed = true;
    for (polls = 0; handled == 0 && polls < MAX_POLLS; polls++)
        sched_yield();
    if (handled == 0)
        round->failed = true;
    if (round->restart) {
        /* The restarted read needs a byte. */
        if (!wait_until_blocked() || write(data_pipe[1], "W", 1) != 1)
            round->failed = true;
    }
    return NULL;
}

static void
run(int flush, bool restart)
{
    const char *name = flush == FLUSH_SYNCHALL ? "synchall flush" : "unlink flush";
    round_t round = { flush, restart, false };
    struct sigaction act;
    uint64_t in[IMAGE_WORDS], out[IMAGE_WORDS];
    pthread_t thread;
    char byte = 0;
    long result;
    bool same = true;
    int i;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = handler;
    act.sa_flags = SA_SIGINFO | (restart ? SA_RESTART : 0);
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGUSR1, &act, NULL) != 0 || pipe(data_pipe) != 0)
        print("setup failed\n");
    for (i = 0; i < IMAGE_WORDS; i++)
        in[i] = UINT64_C(0x5eed000000000100) * (i + 1) + i;
    in[IMAGE_NZCV] = 0x60000000; /* Z and C. */
    memset(out, 0, sizeof(out));
    handled = 0;
    handler_tid = 0;
    reader_tid = 0;
    if (pthread_create(&thread, NULL, second_thread, &round) != 0)
        print("pthread_create failed\n");
    reader_tid = syscall(SYS_gettid);
    result = blocking_read(data_pipe[0], &byte, in, out);
    pthread_join(thread, NULL);
    /* The system call owns x0; x1, x2 and x8 are its arguments and number. */
    in[0] = (uint64_t)result;
    in[1] = (uint64_t)&byte;
    in[2] = 1;
    in[8] = SYS_read;
    for (i = 0; i < IMAGE_WORDS; i++) {
        if (in[i] != out[i]) {
            print("%s: word %d is 0x%016llx, expected 0x%016llx\n", name, i,
                  (unsigned long long)out[i], (unsigned long long)in[i]);
            same = false;
        }
    }
    print("%s, %s: %s, %s, %s%s\n", name, restart ? "SA_RESTART" : "no SA_RESTART",
          handled == 1 && handler_tid == reader_tid
              ? "signal delivered once to the reader"
              : "signal not delivered once",
          restart ? (result == 1 && byte == 'W' ? "read restarted and completed"
                                                : "read not completed")
                  : (result == -EINTR ? "read interrupted" : "read not interrupted"),
          same ? "registers preserved" : "registers changed",
          round.failed ? ", second thread failed" : "");
    close(data_pipe[0]);
    close(data_pipe[1]);
}

int
main(int argc, char *argv[])
{
    run(FLUSH_SYNCHALL, false);
    run(FLUSH_SYNCHALL, true);
    run(FLUSH_UNLINK, false);
    run(FLUSH_UNLINK, true);
    print("all done\n");
    return 0;
}

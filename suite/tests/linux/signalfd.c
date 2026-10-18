/* **********************************************************
 * Copyright (c) 2013-2017 Google, Inc.  All rights reserved.
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

#include "tools.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/signalfd.h>
#include <sys/file.h>
#include <signal.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>

/* The kernel's sigset_t, which signalfd4's size argument must match. */
#define SIGSET_SIZE (_NSIG / 8)

static void
signal_handler(int sig)
{
    /* We shouldn't get here: all signals in this app should go to the signalfd files */
    print("Error: in handler for signal %d\n", sig);
}

static void
test_signalfd(int sig)
{
    int ret, sigfd, sigfd2;
    sigset_t mask;
    struct signalfd_siginfo siginfo;

    intercept_signal(sig, (handler_3_t)signal_handler, false);

    sigemptyset(&mask);
    sigaddset(&mask, sig);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    sigfd = signalfd(-1, &mask, 0);
    if (sigfd < 0) {
        print("signalfd failed: %m");
        exit(1);
    }

    /* Test 2nd fd mapped to same signal */
    sigfd2 = signalfd(-1, &mask, 0);
    if (sigfd2 < 0) {
        print("signalfd failed: %m");
        exit(1);
    }

    print("about to send signal %d\n", sig);
    ret = kill(getpid(), sig);
    if (ret < 0) {
        print("kill failed: %m");
        exit(1);
    }
    if (sig >= 32) {
        /* Real-time: we can send 2 at once */
        print("about to send 2nd signal %d\n", sig);
        ret = kill(getpid(), sig);
        if (ret < 0) {
            print("kill failed: %m");
            exit(1);
        }
    }

    print("about to read from 1st fd for signal %d\n", sig);
    ret = read(sigfd, &siginfo, sizeof(siginfo));
    if (ret <= 0)
        print("ret: %d\n", ret);
    else {
        print("successful read: signal = %d, source is %s\n", siginfo.ssi_signo,
              siginfo.ssi_pid == getpid() ? "this process" : "another process");
    }

    if (sig < 32) {
        /* Non-real-time: have to send 2nd after 1st consumed */
        print("about to send 2nd signal %d\n", sig);
        ret = kill(getpid(), sig);
        if (ret < 0) {
            print("kill failed: %m");
            exit(1);
        }
    }
    print("about to read from 2nd fd for signal %d\n", sig);
    ret = read(sigfd2, &siginfo, sizeof(siginfo));
    if (ret <= 0)
        print("ret: %d\n", ret);
    else {
        print("successful read: signal = %d, source is %s\n", siginfo.ssi_signo,
              siginfo.ssi_pid == getpid() ? "this process" : "another process");
    }

    /* Undo everything */
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
    close(sigfd);
    close(sigfd2);
    intercept_signal(sig, (handler_3_t)NULL, false);
}

/* Blocks sig with a handler that reports the error of running, and returns the
 * prior mask.
 */
static void
block_signal(int sig, sigset_t *orig_mask)
{
    sigset_t mask;
    intercept_signal(sig, (handler_3_t)signal_handler, false);
    sigemptyset(&mask);
    sigaddset(&mask, sig);
    sigprocmask(SIG_BLOCK, &mask, orig_mask);
}

static void
restore_signal(int sig, const sigset_t *orig_mask)
{
    sigprocmask(SIG_SETMASK, orig_mask, NULL);
    intercept_signal(sig, (handler_3_t)NULL, false);
}

static int
new_signalfd(int sig, int flags)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, sig);
    int fd = signalfd(-1, &mask, flags);
    if (fd < 0) {
        print("signalfd failed: %m");
        exit(1);
    }
    return fd;
}

static void
send_signal(int sig)
{
    if (kill(getpid(), sig) < 0) {
        print("kill failed: %m");
        exit(1);
    }
}

static int
is_readable(int fd, int timeout_ms)
{
    struct pollfd pfd = { fd, POLLIN, 0 };
    return poll(&pfd, 1, timeout_ms) == 1;
}

/* Reads one record from fd, returning its signal number or -1. */
static int
read_signal(int fd)
{
    struct signalfd_siginfo siginfo;
    if (!is_readable(fd, 5000))
        return -1;
    if (read(fd, &siginfo, sizeof(siginfo)) != sizeof(siginfo))
        return -1;
    return siginfo.ssi_signo;
}

/* Returns whether sig is pending, taking it. */
static int
take_pending(int sig)
{
    sigset_t mask;
    struct timespec zero = { 0, 0 };
    sigemptyset(&mask);
    sigaddset(&mask, sig);
    return sigtimedwait(&mask, NULL, &zero) == sig;
}

/* Takes every pending instance of sig. */
static void
drain_pending(int sig)
{
    while (take_pending(sig))
        ;
}

/* Every fd for a signalfd works until it is closed. */
static void
test_aliases(int sig)
{
    sigset_t orig_mask;
    block_signal(sig, &orig_mask);
    int fd1 = new_signalfd(sig, 0);
    int fd2 = new_signalfd(sig, SFD_CLOEXEC);
    int fd3 = dup(fd1);
    int fd4 = fcntl(fd2, F_DUPFD_CLOEXEC, 0);
    int fd5 = dup3(fd1, fd4 + 1, O_CLOEXEC);
    close(fd1);
    send_signal(sig);
    print("signal %d: read from 2nd fd after closing 1st: %d\n", sig, read_signal(fd2));
    close(fd2);
    send_signal(sig);
    print("signal %d: read from dup: %d\n", sig, read_signal(fd3));
    close(fd3);
    send_signal(sig);
    print("signal %d: read from F_DUPFD_CLOEXEC dup: %d\n", sig, read_signal(fd4));
    close(fd4);
    send_signal(sig);
    print("signal %d: read from dup3: %d\n", sig, read_signal(fd5));
    close(fd5);
    restore_signal(sig, &orig_mask);
}

/* Closing a signalfd leaves signals it did not read pending. */
static void
test_unread_close(int sig)
{
    sigset_t orig_mask;
    block_signal(sig, &orig_mask);
    int fd = new_signalfd(sig, 0);
    send_signal(sig);
    close(fd);
    print("signal %d: pending after closing its fd unread: %s\n", sig,
          take_pending(sig) ? "yes" : "no");
    restore_signal(sig, &orig_mask);
}

/* A signalfd sees a signal that was pending before it was created. */
static void
test_pending_before(int sig)
{
    sigset_t orig_mask;
    block_signal(sig, &orig_mask);
    send_signal(sig);
    int fd = new_signalfd(sig, 0);
    print("signal %d: read of one pending before the fd: %d\n", sig, read_signal(fd));
    close(fd);
    restore_signal(sig, &orig_mask);
}

/* Queues sig to this thread with value. */
static void
queue_signal(int sig, int value)
{
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    si.si_signo = sig;
    si.si_code = SI_QUEUE;
    si.si_pid = getpid();
    si.si_uid = getuid();
    si.si_value.sival_int = value;
    if (syscall(SYS_rt_tgsigqueueinfo, getpid(), syscall(SYS_gettid), sig, &si) != 0) {
        print("rt_tgsigqueueinfo failed: %m");
        exit(1);
    }
}

/* Many signals unread: none blocks the sender, and what reaches the fd comes in
 * order from the first one sent, with any still pending after it.  (Natively the
 * standard signal is pending once, holding the first value; under DR the fd can
 * hold more records.)
 */
static void
test_saturation(int sig)
{
    sigset_t orig_mask, mask;
    struct signalfd_siginfo rec;
    siginfo_t si;
    struct timespec zero = { 0, 0 };
    int i, first = -1, last = -1, in_order = 1;
    block_signal(sig, &orig_mask);
    int fd = new_signalfd(sig, 0);
    for (i = 0; i < 1000; i++)
        queue_signal(sig, i);
    while (is_readable(fd, 0) && read(fd, &rec, sizeof(rec)) == sizeof(rec)) {
        if ((int)rec.ssi_signo != sig || rec.ssi_int <= last)
            in_order = 0;
        if (first < 0)
            first = rec.ssi_int;
        last = rec.ssi_int;
    }
    sigemptyset(&mask);
    sigaddset(&mask, sig);
    while (sigtimedwait(&mask, &si, &zero) == sig) {
        if (si.si_value.sival_int <= last)
            in_order = 0;
        last = si.si_value.sival_int;
    }
    print("signal %d: 1000 queued: first read %d, all in order: %s\n", sig, first,
          in_order ? "yes" : "no");
    close(fd);
    restore_signal(sig, &orig_mask);
}

static volatile pid_t main_tid;
static volatile int race_go;

static void *
close_thread(void *arg)
{
    while (!race_go)
        ;
    close(*(int *)arg);
    return NULL;
}

static void *
send_thread(void *arg)
{
    int sig = *(int *)arg;
    while (!race_go)
        ;
    for (int i = 0; i < 20; i++)
        syscall(SYS_tgkill, getpid(), main_tid, sig);
    return NULL;
}

/* A signalfd closed by one thread while another sends this thread its signal: the
 * signal ends up pending here every time.
 */
static void
test_cross_thread_close(int sig)
{
    sigset_t orig_mask;
    pthread_t closer, sender;
    int i, every_time = 1;
    main_tid = syscall(SYS_gettid);
    block_signal(sig, &orig_mask);
    for (i = 0; i < 50; i++) {
        int fd = new_signalfd(sig, 0);
        int s = sig;
        race_go = 0;
        pthread_create(&closer, NULL, close_thread, &fd);
        pthread_create(&sender, NULL, send_thread, &s);
        race_go = 1;
        pthread_join(sender, NULL);
        pthread_join(closer, NULL);
        if (!take_pending(sig))
            every_time = 0;
        drain_pending(sig);
    }
    print("signal %d: pending after a close racing sends, every time: %s\n", sig,
          every_time ? "yes" : "no");
    restore_signal(sig, &orig_mask);
}

/* A blocked signal the app ignores stays pending for a signalfd, in a mask that
 * also has a signal DR holds itself.
 */
static void
test_ignored_member(void)
{
    sigset_t mask, orig_mask;
    signal(SIGUSR2, SIG_IGN);
    intercept_signal(SIGSEGV, (handler_3_t)signal_handler, false);
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGSEGV);
    sigprocmask(SIG_BLOCK, &mask, &orig_mask);
    int fd = signalfd(-1, &mask, 0);
    send_signal(SIGUSR2);
    print("ignored signal %d: read: %d\n", SIGUSR2, read_signal(fd));
    close(fd);
    sigprocmask(SIG_SETMASK, &orig_mask, NULL);
    signal(SIGUSR2, SIG_DFL);
    intercept_signal(SIGSEGV, (handler_3_t)NULL, false);
}

static void
print_result(const char *what, long res)
{
    print("%s: %s\n", what,
          res >= 0 ? "ok"
                   : (errno == EINVAL ? "EINVAL" : (errno == EFAULT ? "EFAULT" : "error")));
}

/* Changing the mask of an existing signalfd, and invalid arguments. */
static void
test_update(int sig, int sig2)
{
    sigset_t orig_mask, mask;
    block_signal(sig, &orig_mask);
    intercept_signal(sig2, (handler_3_t)signal_handler, false);
    sigemptyset(&mask);
    sigaddset(&mask, sig2);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    int fd = new_signalfd(sig, SFD_NONBLOCK);
    print("signal %d: update to signal %d returns the fd: %s\n", sig, sig2,
          signalfd(fd, &mask, 0) == fd ? "yes" : "no");
    send_signal(sig2);
    print("signal %d: read after the update: %d\n", sig2, read_signal(fd));
    send_signal(sig);
    print("signal %d: readable after the update: %s\n", sig,
          is_readable(fd, 100) ? "yes" : "no");
    print("signal %d: still pending: %s\n", sig, take_pending(sig) ? "yes" : "no");
    print_result("update with a NULL mask",
                 syscall(SYS_signalfd4, fd, NULL, SIGSET_SIZE, 0));
    print_result("update with a bad size", syscall(SYS_signalfd4, fd, &mask, 4, 0));
    print_result("update with bad flags",
                 syscall(SYS_signalfd4, fd, &mask, SIGSET_SIZE, 0x1000));
    print_result("create with bad flags",
                 syscall(SYS_signalfd4, -1, &mask, SIGSET_SIZE, 0x1000));
    close(fd);
    sigprocmask(SIG_SETMASK, &orig_mask, NULL);
    intercept_signal(sig, (handler_3_t)NULL, false);
    intercept_signal(sig2, (handler_3_t)NULL, false);
}

/* Under DR, a mask mixing signals DR holds itself (SIGSEGV) with ones the kernel
 * holds (SIGUSR2) is a real signalfd for the latter only: the SIGSEGV waits
 * pending instead of reaching the fd.  Either way it is not lost.
 */
static void
test_mixed_mask(void)
{
    sigset_t mask, orig_mask;
    intercept_signal(SIGUSR2, (handler_3_t)signal_handler, false);
    intercept_signal(SIGSEGV, (handler_3_t)signal_handler, false);
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGSEGV);
    sigprocmask(SIG_BLOCK, &mask, &orig_mask);
    int fd = signalfd(-1, &mask, SFD_NONBLOCK);
    send_signal(SIGUSR2);
    print("mixed mask: read of signal %d: %d\n", SIGUSR2, read_signal(fd));
    send_signal(SIGSEGV);
    int got = is_readable(fd, 100) ? read_signal(fd) == SIGSEGV : take_pending(SIGSEGV);
    print("mixed mask: signal %d read or still pending: %s\n", SIGSEGV,
          got ? "yes" : "no");
    close(fd);
    drain_pending(SIGSEGV);
    sigprocmask(SIG_SETMASK, &orig_mask, NULL);
    intercept_signal(SIGUSR2, (handler_3_t)NULL, false);
    intercept_signal(SIGSEGV, (handler_3_t)NULL, false);
}

/* Changing a signalfd's mask from old_sig to {new_sig, also_old ? old_sig}, where
 * one of the two is a signal DR holds itself.  Natively it works.  DR refuses with
 * EINVAL a change between a pipe and a real signalfd, and the fd must then still
 * work for old_sig.  Either way the result must not be an fd that misses the
 * signals it reports success for.
 */
static void
test_update_kind(int old_sig, int new_sig, int also_old)
{
    sigset_t orig_mask, mask;
    int ok;
    block_signal(old_sig, &orig_mask);
    intercept_signal(new_sig, (handler_3_t)signal_handler, false);
    sigemptyset(&mask);
    sigaddset(&mask, new_sig);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    if (also_old)
        sigaddset(&mask, old_sig);
    int fd = new_signalfd(old_sig, SFD_NONBLOCK);
    int res = signalfd(fd, &mask, 0);
    if (res == fd) {
        /* A signal DR holds itself may wait pending instead of reaching a real fd
         * that also has signals the kernel holds.
         */
        send_signal(new_sig);
        ok = is_readable(fd, 100) ? read_signal(fd) == new_sig : take_pending(new_sig);
        if (also_old) {
            send_signal(old_sig);
            ok = ok && (is_readable(fd, 100) ? read_signal(fd) == old_sig
                                             : take_pending(old_sig));
        }
    } else {
        ok = res == -1 && errno == EINVAL;
        send_signal(old_sig);
        ok = ok && read_signal(fd) == old_sig;
    }
    print("update of a signal %d fd to signal %d%s: %s\n", old_sig, new_sig,
          also_old ? " too" : " instead", ok ? "ok" : "broken");
    close(fd);
    drain_pending(old_sig);
    drain_pending(new_sig);
    sigprocmask(SIG_SETMASK, &orig_mask, NULL);
    intercept_signal(old_sig, (handler_3_t)NULL, false);
    intercept_signal(new_sig, (handler_3_t)NULL, false);
}

int
main(void)
{
    test_signalfd(SIGXCPU);
    test_signalfd(SIGUSR1);
    test_signalfd(SIGSEGV);
    test_signalfd(44);
    /* SIGSEGV and SIGBUS are signals DR holds itself; SIGUSR1 and SIGUSR2 are left
     * pending in the kernel.
     */
    test_aliases(SIGSEGV);
    test_aliases(SIGUSR1);
    test_unread_close(SIGSEGV);
    test_unread_close(SIGUSR1);
    test_pending_before(SIGSEGV);
    test_pending_before(SIGUSR1);
    test_saturation(SIGSEGV);
    test_cross_thread_close(SIGSEGV);
    test_ignored_member();
    test_update(SIGSEGV, SIGBUS);
    test_update(SIGUSR1, SIGUSR2);
    test_mixed_mask();
    test_update_kind(SIGSEGV, SIGUSR1, 1); /* pipe to mixed */
    test_update_kind(SIGSEGV, SIGUSR1, 0); /* pipe to kernel-held */
    test_update_kind(SIGUSR1, SIGSEGV, 1); /* real to mixed: stays real */
    test_update_kind(SIGUSR1, SIGSEGV, 0); /* real to held by DR */
    test_update_kind(SIGSEGV, SIGBUS, 0);  /* pipe to pipe */
    return 0;
}

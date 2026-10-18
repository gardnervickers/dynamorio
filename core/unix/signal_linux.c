/* **********************************************************
 * Copyright (c) 2011-2021 Google, Inc.  All rights reserved.
 * Copyright (c) 2000-2010 VMware, Inc.  All rights reserved.
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

/* Copyright (c) 2003-2007 Determina Corp. */
/* Copyright (c) 2001-2003 Massachusetts Institute of Technology */
/* Copyright (c) 2000-2001 Hewlett-Packard Company */

/*
 * signal_linux.c - Linux-specific signal code
 */

#include "signal_private.h" /* pulls in globals.h for us, in right order */

#ifndef LINUX
#    error Linux-only
#endif

#include "arch.h"
#include "../hashtable.h"
#include "include/syscall.h"

#include <errno.h>
#undef errno

/* important reference files:
 *   /usr/include/asm/signal.h
 *   /usr/include/asm/siginfo.h
 *   /usr/include/asm/ucontext.h
 *   /usr/include/asm/sigcontext.h
 *   /usr/include/sys/ucontext.h (see notes below...asm one is more useful)
 *   /usr/include/bits/sigaction.h
 *   /usr/src/linux/kernel/signal.c
 *   /usr/src/linux/arch/i386/kernel/signal.c
 *   /usr/src/linux/include/asm-i386/signal.h
 *   /usr/src/linux/include/asm-i386/sigcontext.h
 *   /usr/src/linux/include/asm-i386/ucontext.h
 *   /usr/src/linux/include/linux/signal.h
 *   /usr/src/linux/include/linux/sched.h (sas_ss_flags, on_sig_stack)
 * ditto with x86_64, plus:
 *   /usr/src/linux/arch/x86_64/ia32/ia32_signal.c
 */

int default_action[] = {
    /* nothing    0 */ DEFAULT_IGNORE,
    /* SIGHUP     1 */ DEFAULT_TERMINATE,
    /* SIGINT     2 */ DEFAULT_TERMINATE,
    /* SIGQUIT    3 */ DEFAULT_TERMINATE_CORE,
    /* SIGILL     4 */ DEFAULT_TERMINATE_CORE,
    /* SIGTRAP    5 */ DEFAULT_TERMINATE_CORE,
    /* SIGABRT/SIGIOT 6 */ DEFAULT_TERMINATE_CORE,
    /* SIGBUS     7 */ DEFAULT_TERMINATE, /* should be CORE */
    /* SIGFPE     8 */ DEFAULT_TERMINATE_CORE,
    /* SIGKILL    9 */ DEFAULT_TERMINATE,
    /* SIGUSR1   10 */ DEFAULT_TERMINATE,
    /* SIGSEGV   11 */ DEFAULT_TERMINATE_CORE,
    /* SIGUSR2   12 */ DEFAULT_TERMINATE,
    /* SIGPIPE   13 */ DEFAULT_TERMINATE,
    /* SIGALRM   14 */ DEFAULT_TERMINATE,
    /* SIGTERM   15 */ DEFAULT_TERMINATE,
    /* SIGSTKFLT 16 */ DEFAULT_TERMINATE,
    /* SIGCHLD   17 */ DEFAULT_IGNORE,
    /* SIGCONT   18 */ DEFAULT_CONTINUE,
    /* SIGSTOP   19 */ DEFAULT_STOP,
    /* SIGTSTP   20 */ DEFAULT_STOP,
    /* SIGTTIN   21 */ DEFAULT_STOP,
    /* SIGTTOU   22 */ DEFAULT_STOP,
    /* SIGURG    23 */ DEFAULT_IGNORE,
    /* SIGXCPU   24 */ DEFAULT_TERMINATE,
    /* SIGXFSZ   25 */ DEFAULT_TERMINATE,
    /* SIGVTALRM 26 */ DEFAULT_TERMINATE,
    /* SIGPROF   27 */ DEFAULT_TERMINATE,
    /* SIGWINCH  28 */ DEFAULT_IGNORE,
    /* SIGIO/SIGPOLL/SIGLOST 29 */ DEFAULT_TERMINATE,
    /* SIGPWR    30 */ DEFAULT_TERMINATE,
    /* SIGSYS/SIGUNUSED 31 */ DEFAULT_TERMINATE,

    /* ASSUMPTION: all real-time have default of terminate...XXX: ok? */
    /* 32 */ DEFAULT_TERMINATE,
    /* 33 */ DEFAULT_TERMINATE,
    /* 34 */ DEFAULT_TERMINATE,
    /* 35 */ DEFAULT_TERMINATE,
    /* 36 */ DEFAULT_TERMINATE,
    /* 37 */ DEFAULT_TERMINATE,
    /* 38 */ DEFAULT_TERMINATE,
    /* 39 */ DEFAULT_TERMINATE,
    /* 40 */ DEFAULT_TERMINATE,
    /* 41 */ DEFAULT_TERMINATE,
    /* 42 */ DEFAULT_TERMINATE,
    /* 43 */ DEFAULT_TERMINATE,
    /* 44 */ DEFAULT_TERMINATE,
    /* 45 */ DEFAULT_TERMINATE,
    /* 46 */ DEFAULT_TERMINATE,
    /* 47 */ DEFAULT_TERMINATE,
    /* 48 */ DEFAULT_TERMINATE,
    /* 49 */ DEFAULT_TERMINATE,
    /* 50 */ DEFAULT_TERMINATE,
    /* 51 */ DEFAULT_TERMINATE,
    /* 52 */ DEFAULT_TERMINATE,
    /* 53 */ DEFAULT_TERMINATE,
    /* 54 */ DEFAULT_TERMINATE,
    /* 55 */ DEFAULT_TERMINATE,
    /* 56 */ DEFAULT_TERMINATE,
    /* 57 */ DEFAULT_TERMINATE,
    /* 58 */ DEFAULT_TERMINATE,
    /* 59 */ DEFAULT_TERMINATE,
    /* 60 */ DEFAULT_TERMINATE,
    /* 61 */ DEFAULT_TERMINATE,
    /* 62 */ DEFAULT_TERMINATE,
    /* 63 */ DEFAULT_TERMINATE,
    /* 64 */ DEFAULT_TERMINATE,
};

bool can_always_delay[] = {
    /* nothing    0 */ true,
    /* SIGHUP     1 */ true,
    /* SIGINT     2 */ true,
    /* SIGQUIT    3 */ true,
    /* SIGILL     4 */ false,
    /* SIGTRAP    5 */ false,
    /* SIGABRT/SIGIOT 6 */ false,
    /* SIGBUS     7 */ false,
    /* SIGFPE     8 */ false,
    /* SIGKILL    9 */ true,
    /* SIGUSR1   10 */ true,
    /* SIGSEGV   11 */ false,
    /* SIGUSR2   12 */ true,
    /* SIGPIPE   13 */ false,
    /* SIGALRM   14 */ true,
    /* SIGTERM   15 */ true,
    /* SIGSTKFLT 16 */ false,
    /* SIGCHLD   17 */ true,
    /* SIGCONT   18 */ true,
    /* SIGSTOP   19 */ true,
    /* SIGTSTP   20 */ true,
    /* SIGTTIN   21 */ true,
    /* SIGTTOU   22 */ true,
    /* SIGURG    23 */ true,
    /* SIGXCPU   24 */ false,
    /* SIGXFSZ   25 */ true,
    /* SIGVTALRM 26 */ true,
    /* SIGPROF   27 */ true,
    /* SIGWINCH  28 */ true,
    /* SIGIO/SIGPOLL/SIGLOST 29 */ true,
    /* SIGPWR    30 */ true,
    /* SIGSYS/SIGUNUSED 31 */ false,

    /* ASSUMPTION: all real-time can be delayed */
    /* 32 */ true,
    /* 33 */ true,
    /* 34 */ true,
    /* 35 */ true,
    /* 36 */ true,
    /* 37 */ true,
    /* 38 */ true,
    /* 39 */ true,
    /* 40 */ true,
    /* 41 */ true,
    /* 42 */ true,
    /* 43 */ true,
    /* 44 */ true,
    /* 45 */ true,
    /* 46 */ true,
    /* 47 */ true,
    /* 48 */ true,
    /* 49 */ true,
    /* 50 */ true,
    /* 51 */ true,
    /* 52 */ true,
    /* 53 */ true,
    /* 54 */ true,
    /* 55 */ true,
    /* 56 */ true,
    /* 57 */ true,
    /* 58 */ true,
    /* 59 */ true,
    /* 60 */ true,
    /* 61 */ true,
    /* 62 */ true,
    /* 63 */ true,
    /* 64 */ true,
};

bool
sysnum_is_not_restartable(int sysnum)
{
    /* Check the list of non-restartable syscalls.
     * Since we only check the number, we're inaccurate!
     * We err on the side of thinking more things are non-restartable
     * than actually are, as this is only really used for inserting
     * nops to ensure post-syscall points are safe spots, and too many
     * nops is better than too few.
     * We're missing:
     * + SYS_read from an inotify file descriptor.
     * We're overly aggressive on:
     * + Socket interfaces: supposed to restart if no timeout has been set.
     */
    return (
#ifdef SYS_pause
        sysnum == SYS_pause ||
#endif
        sysnum == SYS_rt_sigsuspend || sysnum == SYS_rt_sigtimedwait ||
        IF_X86_64(sysnum == SYS_epoll_wait_old ||)
#ifdef SYS_epoll_wait
                sysnum == SYS_epoll_wait ||
#endif
        sysnum == SYS_epoll_pwait ||
#ifdef SYS_poll
        sysnum == SYS_poll ||
#endif
        sysnum == SYS_ppoll || IF_X86(sysnum == SYS_select ||) sysnum == SYS_pselect6 ||
#ifdef X64
        sysnum == SYS_msgrcv || sysnum == SYS_msgsnd || sysnum == SYS_semop ||
        sysnum == SYS_semtimedop ||
        /* XXX: these should be restarted if there's no timeout */
        sysnum == SYS_accept || sysnum == SYS_accept4 || sysnum == SYS_recvfrom ||
        sysnum == SYS_recvmsg || sysnum == SYS_recvmmsg || sysnum == SYS_connect ||
        sysnum == SYS_sendto || sysnum == SYS_sendmmsg || sysnum == SYS_sendfile ||
#elif !defined(ARM)
        /* XXX: some should be restarted if there's no timeout */
        sysnum == SYS_ipc ||
#endif
        sysnum == SYS_clock_nanosleep || sysnum == SYS_nanosleep ||
        sysnum == SYS_io_getevents);
}

/***************************************************************************
 * SIGNALFD
 */

/* Strategy: a real signalfd is a read-only file, so we can't write to one to
 * emulate signal delivery.  We also can't block signals we care about (and
 * for clients we don't want to block anything).  Thus we must emulate
 * signalfd via a pipe.  The kernel's pipe buffer should easily hold
 * even a big queue of RT signals.  Xref i#1138.
 *
 * With -intercept_all_signals only a signalfd for signals we cannot leave pending
 * in the kernel is a pipe (see signal_signalfd_route()); without it, every one is.
 *
 * Although signals are per-thread, fds are global, and one thread
 * could use a signalfd to see signals on another thread.
 *
 * Thus we have:
 * + global data struct "sigfd_pipe_t" stores pipe write fd and refcount
 * + global hashtable mapping each app fd for the pipe to sigfd_pipe_t
 * + thread has array of pointers to sigfd_pipe_t, one per signum
 * + on SYS_close, we decrement refcount
 * + on SYS_dup*, we add a new hashtable entry
 *
 * Our signal handler writes to a pipe without taking a lock.  A pipe is never
 * freed while the process runs (a thread may still hold a pointer to it).  Its
 * state word (sigfd_pipe_t.state) holds a closed bit and the number of handlers
 * writing to it, changed only by compare-and-swap: a handler writes only after
 * counting itself in while the bit is clear (sigfd_pipe_enter()).  The last close
 * sets the bit under the table lock and queues the pipe (retiring_pipes); after
 * dropping the lock, signalfd_finish_closes() waits for the count to drop to zero,
 * then reads the records left in the pipe through our own nonblocking open of it
 * and sends them back to the closing thread (as the kernel keeps signals pending
 * that no signalfd read), and only then closes our ends.  So a write never lands on
 * a closed or reused fd or on a pipe without a reader, and nothing blocks.  The
 * write end does not block either: a signal that does not fit in the pipe stays
 * pending with us.
 *
 * XXX i#1189: an app thread blocked in read() of the pipe when its last fd is
 * closed gets end-of-file once we close our write end, where natively it keeps
 * waiting.  A record that thread or another reads while we drain is not sent
 * back, as the app read it.
 *
 * XXX i#1189: this pipe implementation has holes, shared with upstream DynamoRIO
 * (which uses it for every signalfd) except where noted:
 * + Two signalfds with different but overlapping signal masks share one pipe
 *   (see handle_pre_signalfd()), and a signal goes only to the fd most recently
 *   given it.
 * + A signal goes to the pipe of the thread that received it, so a signalfd
 *   created in one thread does not see signals for another, and a thread reading
 *   it may get another's.  A forked child shares the pipe's contents.
 * + A signal is taken from the pending sets when it arrives, not when the app
 *   reads it: further instances of a standard signal are not coalesced, and the
 *   records the last close sends back all go to the thread that last gave the
 *   pipe its signals, as thread-directed ones.  (As upstream, a fd closed while
 *   another still shares its pipe keeps them.)
 * + We track the app's dups by fd number after the kernel's dup (see
 *   signal_handle_dup()), so a racing close or reuse of the number can lose
 *   track of a copy.
 * + The app reads the pipe directly: a read shorter than a record splits one.
 * + Our state does not survive execve, so a pipe inherited across one never
 *   becomes readable.
 * + The table is by fd number, so threads not sharing the fd table (clone()
 *   without CLONE_FILES, close_range(CLOSE_RANGE_UNSHARE)) confuse it.
 * + A signal that does not fit in the pipe waits with us, readable from no fd
 *   until something else delivers it (the app unblocking it, sigtimedwait()).
 *   (Upstream's write blocked in our signal handler instead.)
 * + Whether a signal is one we hold (sig_kernel_blockable()) is fixed when the fd
 *   is created: an alarm signal becomes one when a client starts an itimer, and
 *   an existing signalfd for it is not converted.  (Upstream has no real
 *   signalfds.)
 */
static generic_table_t *sigfd_table;

struct _sigfd_pipe_t {
    file_t write_fd;
    /* Our own open of the pipe for reading, with O_NONBLOCK. */
    file_t read_fd;
    /* App fds for the pipe (table entries). */
    uint refcount;
    /* SIGFD_PIPE_CLOSED and the number of signal handlers writing to write_fd. */
    volatile int state;
    /* The thread that last gave the pipe signals, which its records came from. */
    thread_id_t owner;
    struct _sigfd_pipe_t *next;
};

#define SIGFD_PIPE_CLOSED 0x40000000

/* Pipes whose last app fd has gone, for signalfd_finish_closes(), and closed
 * ones, freed at exit (see the strategy above).  Both are guarded by the table's
 * lock.
 */
static sigfd_pipe_t *retiring_pipes;
static sigfd_pipe_t *closed_pipes;
static bool signalfd_exiting;

/* Counts a signal handler in as a writer to pipe, unless it is closed. */
static bool
sigfd_pipe_enter(sigfd_pipe_t *pipe)
{
    while (true) {
        int state = atomic_aligned_read_int(&pipe->state);
        if (TESTANY(SIGFD_PIPE_CLOSED, state))
            return false;
        if (atomic_compare_exchange_int(&pipe->state, state, state + 1))
            return true;
    }
}

static void
sigfd_pipe_exit(sigfd_pipe_t *pipe)
{
    ATOMIC_DEC(int, pipe->state);
}

static bool
sigfd_pipe_is_closed(sigfd_pipe_t *pipe)
{
    return TESTANY(SIGFD_PIPE_CLOSED, atomic_aligned_read_int(&pipe->state));
}

static void
signalfd_record_to_siginfo(const struct signalfd_siginfo *rec, kernel_siginfo_t *si)
{
    int sig = (int)rec->ssi_signo;
    memset(si, 0, sizeof(*si));
    si->si_signo = sig;
    si->si_errno = rec->ssi_errno;
    /* A positive code claims to come from the kernel; our handler could take one
     * of a fault signal for a fault of its own.
     */
    si->si_code = rec->ssi_code > 0 ? SI_QUEUE : rec->ssi_code;
    if (rec->ssi_code == SI_TIMER) {
        si->si_timerid = rec->ssi_tid;
        si->si_overrun = rec->ssi_overrun;
    } else {
        si->si_pid = rec->ssi_pid;
        si->si_uid = rec->ssi_uid;
    }
    si->si_ptr = (void *)(ptr_uint_t)rec->ssi_ptr;
}

/* Sends the signal of si to thread tid of this process.  The kernel takes another
 * thread's siginfo only for a negative si_code other than SI_TKILL; otherwise we
 * send it with tgkill, which leaves it SI_TKILL from us.
 */
static bool
signalfd_requeue(thread_id_t tid, kernel_siginfo_t *si)
{
    if (si->si_code < 0 && si->si_code != SI_TKILL) {
        return dynamorio_syscall(SYS_rt_tgsigqueueinfo, 4, get_process_id(), tid,
                                 si->si_signo, si) == 0;
    }
    return dynamorio_syscall(SYS_tgkill, 3, get_process_id(), tid, si->si_signo) == 0;
}

/* Called with the table's write lock held when the last app fd for the pipe goes:
 * closes it to writers, for signalfd_finish_closes() to finish after the lock is
 * dropped.
 */
static void
sigfd_pipe_retire(sigfd_pipe_t *pipe)
{
    int state;
    do {
        state = atomic_aligned_read_int(&pipe->state);
    } while (!atomic_compare_exchange_int(&pipe->state, state,
                                          state | SIGFD_PIPE_CLOSED));
    pipe->next = retiring_pipes;
    retiring_pipes = pipe;
}

/* Finishes closing the pipes retired so far.  Called without the table's lock. */
static void
signalfd_finish_closes(void)
{
    struct signalfd_siginfo rec;
    kernel_siginfo_t si;
    if (retiring_pipes == NULL) /* Racy, but our own retirements are visible. */
        return;
    TABLE_RWLOCK(sigfd_table, write, lock);
    sigfd_pipe_t *list = retiring_pipes;
    retiring_pipes = NULL;
    TABLE_RWLOCK(sigfd_table, write, unlock);
    while (list != NULL) {
        sigfd_pipe_t *pipe = list;
        list = pipe->next;
        /* Handlers already writing are brief. */
        while ((atomic_aligned_read_int(&pipe->state) & ~SIGFD_PIPE_CLOSED) != 0)
            os_thread_yield();
        /* The records go back to the thread that gave the pipe its signals (or
         * this one, if that has exited): one we hold reaches our handler, which now
         * queues it.  Our signals are all standard ones, which the kernel keeps
         * pending once, so only the first record of each goes back (sending them
         * all would also nest them in our handler).
         */
        kernel_sigset_t sent;
        kernel_sigemptyset(&sent);
        while (!signalfd_exiting &&
               dynamorio_syscall(SYS_read, 3, pipe->read_fd, &rec, sizeof(rec)) ==
                   sizeof(rec)) {
            if (rec.ssi_signo == 0 || rec.ssi_signo > MAX_SIGNUM ||
                ((int)rec.ssi_signo < OFFS_RT &&
                 kernel_sigismember(&sent, (int)rec.ssi_signo)))
                continue;
            kernel_sigaddset(&sent, (int)rec.ssi_signo);
            signalfd_record_to_siginfo(&rec, &si);
            if (!signalfd_requeue(pipe->owner, &si) &&
                !signalfd_requeue(get_sys_thread_id(), &si)) {
                LOG(GLOBAL, LOG_ASYNCH, 1, "signalfd close: lost signal %d\n",
                    si.si_signo);
            }
        }
        os_close_protected(pipe->write_fd);
        os_close_protected(pipe->read_fd);
        TABLE_RWLOCK(sigfd_table, write, lock);
        pipe->next = closed_pipes;
        closed_pipes = pipe;
        TABLE_RWLOCK(sigfd_table, write, unlock);
    }
}

static void
sigfd_pipe_free(dcontext_t *dcontext, void *ptr)
{
    sigfd_pipe_t *pipe = (sigfd_pipe_t *)ptr;
    ASSERT(pipe->refcount > 0);
    pipe->refcount--;
    if (pipe->refcount == 0)
        sigfd_pipe_retire(pipe);
}

void
signalfd_init(void)
{
#define SIGNALFD_HTABLE_INIT_SIZE 6
    sigfd_table =
        generic_hash_create(GLOBAL_DCONTEXT, SIGNALFD_HTABLE_INIT_SIZE,
                            80 /* load factor: not perf-critical */,
                            HASHTABLE_ENTRY_SHARED | HASHTABLE_SHARED |
                                HASHTABLE_PERSISTENT | HASHTABLE_RELAX_CLUSTER_CHECKS,
                            sigfd_pipe_free _IF_DEBUG("signalfd table"));
    /* XXX: we need our lock rank to be higher than fd_table's so we
     * can call os_close_protected() when freeing.  We should
     * parametrize the generic table rank.  For now we just change it afterward
     * (we'll have issues if we ever call _resurrect):
     */
    ASSIGN_INIT_READWRITE_LOCK_FREE(sigfd_table->rwlock, sigfdtable_lock);
}

void
signalfd_exit(void)
{
    signalfd_exiting = true;
    /* Retires every pipe still open (sigfd_pipe_free()). */
    generic_hash_destroy(GLOBAL_DCONTEXT, sigfd_table);
    sigfd_table = NULL;
    while (retiring_pipes != NULL) {
        sigfd_pipe_t *pipe = retiring_pipes;
        retiring_pipes = pipe->next;
        os_close_protected(pipe->write_fd);
        os_close_protected(pipe->read_fd);
        HEAP_TYPE_FREE(GLOBAL_DCONTEXT, pipe, sigfd_pipe_t, ACCT_OTHER, PROTECTED);
    }
    while (closed_pipes != NULL) {
        sigfd_pipe_t *pipe = closed_pipes;
        closed_pipes = pipe->next;
        HEAP_TYPE_FREE(GLOBAL_DCONTEXT, pipe, sigfd_pipe_t, ACCT_OTHER, PROTECTED);
    }
}

void
signalfd_thread_exit(dcontext_t *dcontext, thread_sig_info_t *info)
{
    /* Nothing refers to the thread's info: a pipe outlives it. */
}

bool
handle_pre_extended_syscall_sigmasks(dcontext_t *dcontext, kernel_sigset_t *sigmask,
                                     size_t sizemask, bool *pending)
{
    thread_sig_info_t *info = (thread_sig_info_t *)dcontext->signal_field;

    /* XXX i#2311, #3240: We may currently deliver incorrect signals, because the
     * native sigprocmask the system call may get interrupted by may not be the same
     * as the native app expects. In addition to this, the p* variants of above syscalls
     * are not properly emulated w.r.t. their atomicity setting the sigprocmask and
     * executing the syscall.
     */
    *pending = false;
    if (sizemask != sizeof(kernel_sigset_t))
        return false;
    ASSERT(sigmask != NULL);
    ASSERT(!info->pre_syscall_app_sigprocmask_valid);
    info->pre_syscall_app_sigprocmask_valid = true;
    info->pre_syscall_app_sigprocmask = info->app_sigblocked;
    signal_block_in_kernel_ahead(dcontext, sigmask);
    signal_set_mask(dcontext, sigmask);
    /* Make sure we deliver pending signals that are now unblocked. */
    check_signals_pending(dcontext, info);
    *pending = dcontext->signals_pending;
    return true;
}

void
handle_post_extended_syscall_sigmasks(dcontext_t *dcontext, bool success)
{
    thread_sig_info_t *info = (thread_sig_info_t *)dcontext->signal_field;
    ASSERT(info->pre_syscall_app_sigprocmask_valid);
    /* We restore the mask here *before* we make it back to dispatch for
     * receive_pending_signal().  We rely on sigpending_t.unblocked_at_receipt
     * to deliver the signal ignoring the now-restored mask.
     */
    info->pre_syscall_app_sigprocmask_valid = false;
    signal_set_mask(dcontext, &info->pre_syscall_app_sigprocmask);
}

/* Maps the app's fd to pipe, which gains a reference.  Called with the table's
 * write lock held.
 */
static void
signalfd_table_add(file_t fd, sigfd_pipe_t *pipe)
{
    /* A stale entry: see the table caveats above. */
    if (generic_hash_lookup(GLOBAL_DCONTEXT, sigfd_table, fd) != NULL)
        generic_hash_remove(GLOBAL_DCONTEXT, sigfd_table, fd); /* sigfd_pipe_free() */
    generic_hash_add(GLOBAL_DCONTEXT, sigfd_table, fd, (void *)pipe);
}

/* Returns the thread's live pipe for sig, clearing a closed one. */
static sigfd_pipe_t *
thread_signalfd_pipe(thread_sig_info_t *info, int sig)
{
    sigfd_pipe_t *pipe = info->signalfd[sig];
    if (pipe != NULL && sigfd_pipe_is_closed(pipe)) {
        info->signalfd[sig] = NULL;
        pipe = NULL;
    }
    return pipe;
}

/* Converts a held signal to a signalfd record. */
static void
siginfo_to_signalfd_record(int sig, const kernel_siginfo_t *si,
                           struct signalfd_siginfo *rec)
{
    memset(rec, 0, sizeof(*rec));
    rec->ssi_signo = sig;
    rec->ssi_errno = si->si_errno;
    rec->ssi_code = si->si_code;
    rec->ssi_pid = si->si_pid;
    rec->ssi_uid = si->si_uid;
    rec->ssi_fd = si->si_fd;
    rec->ssi_tid = si->si_timerid;
    rec->ssi_band = si->si_band;
    rec->ssi_overrun = si->si_overrun;
    rec->ssi_status = si->si_status;
    rec->ssi_utime = si->si_utime;
    rec->ssi_stime = si->si_stime;
#ifdef __ARCH_SI_TRAPNO /* XXX: should update include/siginfo.h */
    rec->ssi_trapno = si->si_trapno;
#endif
    rec->ssi_addr = (ptr_int_t)si->si_addr;
    /* The queued value of sigqueue(), POSIX timers and message queues. */
    rec->ssi_int = si->si_int;
    rec->ssi_ptr = (ptr_uint_t)si->si_ptr;
}

/* Writes a record for sig to pipe without blocking.  Safe in our signal handler. */
static bool
signalfd_pipe_write(sigfd_pipe_t *pipe, int sig, const kernel_siginfo_t *si)
{
    struct signalfd_siginfo rec;
    bool written = false;
    siginfo_to_signalfd_record(sig, si, &rec);
    if (sigfd_pipe_enter(pipe)) {
        /* The pipe buffer holds 512 records; a write fails rather than split one. */
        written = write_syscall(pipe->write_fd, &rec, sizeof(rec)) == sizeof(rec);
        sigfd_pipe_exit(pipe);
    }
    return written;
}

/* Opens fd's pipe for reading again, with its own status flags.  Returns the new
 * fd or a negative errno.
 */
static int
signalfd_reopen(file_t fd, int flags)
{
    char path[64];
    snprintf(path, BUFFER_SIZE_ELEMENTS(path), "/proc/self/fd/%d", fd);
    NULL_TERMINATE_BUFFER(path);
    return (int)dynamorio_syscall(SYS_openat, 4, AT_FDCWD, path, O_RDONLY | flags, 0);
}

/* Gives the app another fd for pipe with its own flags: a new open of the pipe,
 * so that SFD_NONBLOCK (and later F_SETFL) are its own, as for a separate
 * signalfd.  Returns the fd or a negative errno.  Without /proc we fail rather
 * than share one fd's status flags with another.
 */
static int
signalfd_alias(sigfd_pipe_t *pipe, int flags)
{
    return signalfd_reopen(pipe->read_fd, flags);
}

/* Moves fd to our private fd space, closing it there, and marks the copy
 * close-on-exec: our state does not survive execve.  Returns the copy or -1.
 */
static file_t
signalfd_privatize(file_t fd)
{
    file_t priv = fd_priv_dup(fd);
    if (priv < 0 && DYNAMO_OPTION(steal_fds) == 0)
        priv = dup_syscall(fd);
    os_close(fd);
    if (priv < 0)
        return -1;
    if (!fd_mark_close_on_exec(priv)) {
        os_close(priv);
        return -1;
    }
    fd_table_add(priv, 0 /*keep across fork*/);
    return priv;
}

/* Creates a pipe, returning the app's fd for it or a negative errno.  Only a
 * complete pipe is returned: any failure undoes the rest.
 */
static int
signalfd_pipe_create(int flags, sigfd_pipe_t **pipe_out)
{
    int fds[2];
    file_t write_fd, read_fd;
    /* SYS_signalfd is even newer than SYS_pipe2, so pipe2 must be avail.
     * The flags are the same (SFD_NONBLOCK == O_NONBLOCK, SFD_CLOEXEC == O_CLOEXEC).
     */
    ptr_int_t res = dynamorio_syscall(SYS_pipe2, 2, fds, flags);
    if (res < 0)
        return (int)res;
    /* Our signal handler must never block on a full pipe, and our reads at the
     * last close must never block on an empty one.
     */
    res = dynamorio_syscall(SYS_fcntl, 3, fds[1], F_SETFL, O_NONBLOCK);
    if (res < 0) {
        os_close(fds[0]);
        os_close(fds[1]);
        return (int)res;
    }
    write_fd = signalfd_privatize(fds[1]);
    if (write_fd < 0) {
        os_close(fds[0]);
        return -EMFILE;
    }
    res = signalfd_reopen(fds[0], O_NONBLOCK);
    read_fd = res < 0 ? -1 : signalfd_privatize((file_t)res);
    if (read_fd < 0) {
        os_close_protected(write_fd);
        os_close(fds[0]);
        return res < 0 ? (int)res : -EMFILE;
    }
    sigfd_pipe_t *pipe =
        HEAP_TYPE_ALLOC(GLOBAL_DCONTEXT, sigfd_pipe_t, ACCT_OTHER, PROTECTED);
    memset(pipe, 0, sizeof(*pipe));
    pipe->refcount = 1;
    pipe->write_fd = write_fd;
    pipe->read_fd = read_fd;
    *pipe_out = pipe;
    return fds[0];
}

/* Points the thread's signals of mask at pipe, and its other signals off it. */
static void
signalfd_pipe_set_mask(dcontext_t *dcontext, thread_sig_info_t *info, sigfd_pipe_t *pipe,
                       const kernel_sigset_t *mask)
{
    pipe->owner = get_sys_thread_id();
    for (int sig = 1; sig <= MAX_SIGNUM; sig++) {
        if (sig == SIGKILL || sig == SIGSTOP)
            continue;
        if (kernel_sigismember((kernel_sigset_t *)mask, sig)) {
            /* XXX i#1189: a signal goes to one fd only, the latest one given it. */
            info->signalfd[sig] = pipe;
            LOG(THREAD, LOG_ASYNCH, 2, "adding signalfd pipe %d for signal %d\n",
                pipe->write_fd, sig);
            /* One that arrived before the fd existed is pending for it too.  It
             * leaves our queue only once it is in the pipe, in order; one that does
             * not fit stays queued.
             */
            kernel_siginfo_t si;
            while (signal_peek_held_signal(dcontext, sig, &si) &&
                   signalfd_pipe_write(pipe, sig, &si))
                signal_drop_held_signal(dcontext, sig);
        } else if (info->signalfd[sig] == pipe) {
            info->signalfd[sig] = NULL;
            LOG(THREAD, LOG_ASYNCH, 2, "removing signalfd pipe=%d for signal %d\n",
                pipe->write_fd, sig);
        }
    }
}

/* Emulates signalfd4(fd, mask, sizeof(*mask), flags), for valid arguments (see
 * signal_signalfd_route()).  Returns the result or a negative errno.
 */
ptr_int_t
handle_pre_signalfd(dcontext_t *dcontext, int fd, const kernel_sigset_t *mask, int flags)
{
    thread_sig_info_t *info = (thread_sig_info_t *)dcontext->signal_field;
    sigfd_pipe_t *pipe = NULL;
    ptr_int_t retval;
    LOG(THREAD, LOG_ASYNCH, 2, "%s: fd=%d, flags=0x%x\n", __FUNCTION__, fd, flags);
    TABLE_RWLOCK(sigfd_table, write, lock);
    if (fd != -1) {
        /* Changes the mask; the kernel ignores the flags here. */
        pipe = (sigfd_pipe_t *)generic_hash_lookup(GLOBAL_DCONTEXT, sigfd_table, fd);
        retval = pipe == NULL ? -EINVAL : fd;
    } else {
        /* FIXME i#1189: currently we do not properly handle two signalfds with
         * different but overlapping signal masks, as we do not monitor the
         * read/poll syscalls and thus cannot provide a set of pipes that
         * matches the two signal sets.  For now we err on the side of sending
         * too many signals and simply conflate such sets into a single pipe.
         */
        for (int sig = 1; sig <= MAX_SIGNUM; sig++) {
            if (sig == SIGKILL || sig == SIGSTOP ||
                !kernel_sigismember((kernel_sigset_t *)mask, sig))
                continue;
            pipe = thread_signalfd_pipe(info, sig);
            if (pipe != NULL)
                break;
        }
        if (pipe != NULL) {
            retval = signalfd_alias(pipe, flags);
            if (retval >= 0) {
                pipe->refcount++;
                signalfd_table_add((file_t)retval, pipe);
            }
        } else {
            retval = signalfd_pipe_create(flags, &pipe);
            if (retval >= 0) {
                signalfd_table_add((file_t)retval, pipe);
                LOG(THREAD, LOG_ASYNCH, 2, "created signalfd pipe app r=%d DR r=%d w=%d\n",
                    (int)retval, pipe->read_fd, pipe->write_fd);
            }
        }
    }
    if (retval >= 0)
        signalfd_pipe_set_mask(dcontext, info, pipe, mask);
    TABLE_RWLOCK(sigfd_table, write, unlock);
    signalfd_finish_closes(); /* For a stale table entry replaced. */
    return retval;
}

bool
notify_signalfd(dcontext_t *dcontext, thread_sig_info_t *info, int sig,
                sigframe_rt_t *frame)
{
    sigfd_pipe_t *pipe = thread_signalfd_pipe(info, sig);
    if (pipe == NULL)
        return false;
    /* A signal that does not fit in the pipe stays pending with us, where
     * sigpending() and sigtimedwait() see it.
     */
    bool written = signalfd_pipe_write(pipe, sig, &frame->info);
    LOG(THREAD, LOG_ASYNCH, 2, "writing to signalfd fd=%d for signal %d => %d\n",
        pipe->write_fd, sig, written);
    return written;
}

/* Returns whether no fd is an emulated signalfd: the usual case. */
static bool
signalfd_none(void)
{
    TABLE_RWLOCK(sigfd_table, read, lock);
    bool none = sigfd_table->entries == 0;
    TABLE_RWLOCK(sigfd_table, read, unlock);
    return none;
}

/* The app's dst is now a copy of src (dup, dup2, dup3, fcntl F_DUPFD*).
 * XXX i#1189: we update the table after the kernel's dup, by fd number, so a
 * close of src or dst by another thread in between, or the reuse of that number,
 * can leave the copy untracked or an entry stale.
 */
void
signal_handle_dup(dcontext_t *dcontext, file_t src, file_t dst)
{
    if (src == dst || signalfd_none() ||
        (!signal_is_emulated_signalfd(src) && !signal_is_emulated_signalfd(dst)))
        return;
    TABLE_RWLOCK(sigfd_table, write, lock);
    sigfd_pipe_t *pipe =
        (sigfd_pipe_t *)generic_hash_lookup(GLOBAL_DCONTEXT, sigfd_table, src);
    if (pipe != NULL) {
        /* Taken first, as replacing dst may drop the pipe's last reference. */
        pipe->refcount++;
        signalfd_table_add(dst, pipe);
    } else {
        /* dup2 and dup3 close an open dst first. */
        generic_hash_remove(GLOBAL_DCONTEXT, sigfd_table, dst); /* sigfd_pipe_free() */
    }
    TABLE_RWLOCK(sigfd_table, write, unlock);
    signalfd_finish_closes();
}

/* The app closes every fd in [first, last]. */
void
signal_handle_close_range(dcontext_t *dcontext, uint first, uint last)
{
    if (signalfd_none())
        return;
    TABLE_RWLOCK(sigfd_table, write, lock);
    generic_hash_range_remove(GLOBAL_DCONTEXT, sigfd_table, first, (ptr_uint_t)last + 1);
    TABLE_RWLOCK(sigfd_table, write, unlock);
    signalfd_finish_closes();
}

void
signal_handle_close(dcontext_t *dcontext, file_t fd)
{
    sigfd_pipe_t *pipe;
    TABLE_RWLOCK(sigfd_table, read, lock);
    pipe = (sigfd_pipe_t *)generic_hash_lookup(GLOBAL_DCONTEXT, sigfd_table, fd);
    TABLE_RWLOCK(sigfd_table, read, unlock);
    if (pipe == NULL)
        return;
    TABLE_RWLOCK(sigfd_table, write, lock);
    pipe = (sigfd_pipe_t *)generic_hash_lookup(GLOBAL_DCONTEXT, sigfd_table, fd);
    if (pipe != NULL) {
        /* this will call sigfd_pipe_free() */
        generic_hash_remove(GLOBAL_DCONTEXT, sigfd_table, fd);
    }
    TABLE_RWLOCK(sigfd_table, write, unlock);
    signalfd_finish_closes();
}

/* Returns whether fd is a signalfd we emulate with a pipe. */
bool
signal_is_emulated_signalfd(file_t fd)
{
    TABLE_RWLOCK(sigfd_table, read, lock);
    bool found = generic_hash_lookup(GLOBAL_DCONTEXT, sigfd_table, fd) != NULL;
    TABLE_RWLOCK(sigfd_table, read, unlock);
    return found;
}

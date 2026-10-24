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

/* Attach/detach/re-attach under load on AArch64, with native runs of the
 * same code as the oracle.  Each option variant runs in a forked child:
 *
 *   lifecycle: 2-8 workers, each in its own generator layout slot, run
 *     random blocks (a64_dr_prop_gen.h: exclusive loops for -ldstex2cas,
 *     planned faults and BRKs handled by the app, syscalls, PAuth, stolen
 *     register uses, indirect branches, an outer loop for long runs) over
 *     and over from fixed initial states.  Each block's expected final state
 *     (registers, NZCV, FPSR/FPCR, V registers, data buffer, written stack and
 *     every fault frame) comes from two identical native runs before DR is
 *     first attached.  A controller attaches DR (dr_app_setup_and_start()),
 *     lets the workers run for a random time, detaches it
 *     (dr_app_stop_and_cleanup()), lets them run natively, and repeats on a
 *     recorded schedule, so that attach and detach meet every worker
 *     anywhere: in DR, in the code cache, inside mangled sequences (stolen
 *     register swaps, -ldstex2cas loops, PAuth), at a syscall or in a fault
 *     handler.  A blocked-syscall worker waits in read() on a pipe that the
 *     controller writes a sequence of operation ids to around the
 *     transitions, a signal worker sends itself signals whose handler
 *     computes a checksum, and a process-signal worker sends the process
 *     numbered real-time signals.  Properties: every run's final state and
 *     faults equal the native ones; every operation id arrives once and in
 *     order; every handler run completes with the right checksum; every
 *     process signal arrives exactly once; every worker
 *     makes progress in every phase; the process exits cleanly.  Floors:
 *     transitions done, runs checked, and runs a transition interrupted.
 *
 * Counted known deviations: fault frames of runs a transition interrupted
 * may have PSTATE.DIT clear (moot: blocks do not set DIT, lc_init_features());
 * a signal the signal workers send while DR attaches may be dropped (DR
 * ignores delayable signals while it attaches, i#7598).
 *
 * Usage: a64_prop_lifecycle lifecycle [-seed S] [-rounds R] [-workers W]
 *        [-variants a,b,...] [-no_faults] [-no_signal_worker] [-v]
 *        a64_prop_lifecycle dump -seed S [-workers W] [-no_faults]
 */

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include "dr_api.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "a64_prop_support.h"

#define PSTATE_BTYPE 0xc00ULL
#define PSTATE_SSBS 0x1000ULL
#define PSTATE_DIT 0x1000000ULL
/* The process-signal worker's signal (see psig_worker()). */
#define PSIG (SIGRTMIN + 3)

static int verbose;
static int is_debug_build;
static int opt_no_signal_worker;
static int opt_no_faults;
/* This child's blocks have no planned faults (-no_faults). */
static int g_no_faults;

/* dr_ops NULL: no DR at all (the native control of the harness). */
static const variant_t lc_variants[] = {
    { "native", NULL, 0, 0, 0, 0 },
    { "default", "", 0, 0, 0, 0 },
    { "notraces", "-disable_traces", 0, 0, 0, 0 },
    { "nocas", "-no_ldstex2cas", 0, 0, 1, 0 },
    { "steal27", "-steal_reg 27", 0, 0, 1, 0 },
};
#define NVARIANTS ((int)(sizeof(lc_variants) / sizeof(lc_variants[0])))

static int
list_has(const char *list, const char *name)
{
    size_t len = strlen(name);
    for (const char *p = list; p != NULL && *p != '\0';) {
        const char *e = strchr(p, ',');
        size_t n = e == NULL ? strlen(p) : (size_t)(e - p);
        if (n == len && strncmp(p, name, n) == 0)
            return 1;
        p = e == NULL ? NULL : e + 1;
    }
    return 0;
}

static uint64_t
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void
sleep_us(uint64_t us)
{
    struct timespec ts = { (time_t)(us / 1000000), (long)(us % 1000000) * 1000 };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

/***************************************************************************
 * Controller state shared with the workers.
 */
/* Bumped before and after every transition: odd while one is in progress.
 * A run that sees a different value at its end than at its start was
 * interrupted by a transition.
 */
static volatile uint64_t g_transitions;
/* Phase: 0 native, 1 under DR (set after each transition completes). */
static volatile int g_phase;
static volatile int g_stop;
static pthread_mutex_t out_lock = PTHREAD_MUTEX_INITIALIZER;
/* Where comparisons that are only counted print their differences. */
static FILE *g_devnull;

/***************************************************************************
 * Block workers.
 */
#define MAXWK 8
#define NBLK 3

typedef struct {
    int id;
    pthread_t th;
    a64p_worker_t w;
    uint64_t seed;
    block_t *b[NBLK];
    result_t *expect[NBLK];
    int nblk;
    volatile int ready;
    /* Counts. */
    volatile long runs, fails, straddled, phase_runs[2];
    long masked_dit;
} worker_t;

static worker_t g_workers[MAXWK];
static int g_nworkers;

static void
on_masked(int i, fault_rec_t *n, fault_rec_t *d)
{
    /* Known deviations (BTYPE: DR-built frames; SSBS: kernel nondeterminism,
     * seen natively too) are counted by the caller's comparison result only.
     */
    (void)i;
    (void)n;
    (void)d;
}

static void
report_mismatch(worker_t *wk, int bi, result_t *got, uint64_t t0, uint64_t t1)
{
    pthread_mutex_lock(&out_lock);
    fprintf(stderr,
            "FAIL [lifecycle] worker %d block %d (seed %llu) run %ld: state differs from "
            "the native run (transitions %llu -> %llu, phase %d)\n",
            wk->id, bi, (unsigned long long)wk->b[bi]->seed, wk->runs,
            (unsigned long long)t0, (unsigned long long)t1, g_phase);
    a64p_cmp_results(stderr, wk->b[bi], wk->expect[bi], got);
    pthread_mutex_unlock(&out_lock);
}

/* Long blocks (an outer loop) without faults, or blocks with planned faults
 * and BRKs (whose count an outer loop would multiply).
 */
static void
lc_opts(gen_opts_t *o, int long_block)
{
    memset(o, 0, sizeof(*o));
    o->allow_excl = 1;
    o->allow_svc = 1;
    o->allow_fpcr = 1;
    o->allow_ctr = 1;
    o->outer_loop = long_block;
    o->allow_faults = o->allow_brk = !long_block;
    o->len = 60;
    o->dyn_max = 20000;
}

/* Blocks do not change PSTATE.DIT: a frame DR builds keeps only NZCV of PSTATE
 * (review R3, checked by a64_prop_signal), so a block that set DIT and faulted
 * while DR attached or detached would read DIT clear afterwards, in registers
 * and in memory.
 */
static void
lc_init_features(void)
{
    a64p_init_features();
    feat.dit = 0;
}

static void *
block_worker(void *arg)
{
    worker_t *wk = (worker_t *)arg;
    a64p_worker_bind(&wk->w);
    a64p_setup_maps();
    a64p_install_handlers(&wk->w, 0);
    /* The process signal goes to the other threads: a handler frame here could
     * land in the compared stack.
     */
    sigset_t psig_set;
    sigemptyset(&psig_set);
    sigaddset(&psig_set, PSIG);
    pthread_sigmask(SIG_BLOCK, &psig_set, NULL);
    gen_opts_t o;
    result_t *tmp = malloc(sizeof(*tmp));
    /* Native expectations, computed before DR is ever attached: blocks whose
     * two native runs differ, or that fault unplannedly, are not used.
     */
    for (int tries = 0; wk->nblk < NBLK && tries < 8 * NBLK; tries++) {
        block_t *b = malloc(sizeof(*b));
        result_t *e = malloc(sizeof(*e));
        uint64_t s = wk->seed * 1000 + (uint64_t)tries;
        lc_opts(&o, (wk->nblk % 2) == 0 || g_no_faults);
        if (!a64p_make_block(b, &o, s)) {
            free(b);
            free(e);
            continue;
        }
        a64p_install_code(&wk->w, b, 0);
        a64p_run_block(&wk->w, b, e);
        a64p_run_block(&wk->w, b, tmp);
        if (!a64p_check_planned(b, e) || a64p_cmp_results(g_devnull, b, e, tmp) != 0) {
            free(b);
            free(e);
            continue;
        }
        wk->b[wk->nblk] = b;
        wk->expect[wk->nblk] = e;
        wk->nblk++;
    }
    __atomic_store_n(&wk->ready, 1, __ATOMIC_RELEASE);
    rng_t r = { wk->seed ^ 0x5bd1e995ULL };
    int cur = -1;
    while (!__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE) && wk->nblk > 0) {
        int bi = (int)rn(&r, (uint32_t)wk->nblk);
        if (bi != cur) {
            /* Reinstalling code goes through munmap/mmap: also under DR. */
            a64p_install_code(&wk->w, wk->b[bi], 0);
            cur = bi;
        }
        uint64_t t0 = __atomic_load_n(&g_transitions, __ATOMIC_ACQUIRE);
        int ph = g_phase;
        a64p_run_block(&wk->w, wk->b[bi], tmp);
        uint64_t t1 = __atomic_load_n(&g_transitions, __ATOMIC_ACQUIRE);
        wk->runs++;
        int straddled = t0 != t1 || (t0 & 1) != 0;
        if (straddled) {
            wk->straddled++;
            /* Known deviation fault-dit-at-transition: a fault frame DR builds
             * while it attaches or detaches has PSTATE.DIT clear (DR-built frames
             * keep only NZCV of PSTATE, review R3).  Counted, 2026-10-14.
             */
            for (int i = 0; i < tmp->nf && i < wk->expect[bi]->nf && i < MAXF; i++) {
                if (((tmp->f[i].pstate ^ wk->expect[bi]->f[i].pstate) &
                     ~a64p_fault_pstate_ignore) == PSTATE_DIT) {
                    tmp->f[i].pstate = wk->expect[bi]->f[i].pstate;
                    wk->masked_dit++;
                }
            }
        } else
            wk->phase_runs[ph]++;
        if (a64p_cmp_results(g_devnull, wk->b[bi], wk->expect[bi], tmp) != 0) {
            wk->fails++;
            if (wk->fails <= 3)
                report_mismatch(wk, bi, tmp, t0, t1);
        }
    }
    free(tmp);
    return NULL;
}

/***************************************************************************
 * The blocked-syscall worker and the signal worker.
 */
static int g_pipe[2];
static volatile long g_ops_sent, g_ops_got, g_ops_bad;

static void *
pipe_worker(void *arg)
{
    (void)arg;
    uint32_t want = 1;
    for (;;) {
        uint32_t v;
        ssize_t n = read(g_pipe[0], &v, sizeof(v));
        if (n < 0 && errno == EINTR)
            continue;
        if (n != (ssize_t)sizeof(v)) {
            g_ops_bad++;
            fprintf(stderr, "FAIL [lifecycle] pipe read returned %zd (errno %d)\n", n,
                    errno);
            return NULL;
        }
        if (v == 0)
            return NULL; /* end */
        if (v != want) {
            g_ops_bad++;
            fprintf(stderr, "FAIL [lifecycle] operation id %u arrived, expected %u\n", v,
                    want);
        }
        want = v + 1;
        g_ops_got++;
    }
}

static void
send_op(uint32_t v)
{
    while (write(g_pipe[1], &v, sizeof(v)) < 0 && errno == EINTR) {
    }
    if (v != 0)
        g_ops_sent++;
}

#define SIG_SPIN 20000
static volatile long g_sig_runs, g_sig_bad, g_sig_dropped_at_attach;
static __thread volatile uint64_t sig_result;

static void
sig_handler(int sig)
{
    /* A handler long enough to be interrupted by attach and detach. */
    uint64_t s = 0;
    for (volatile int i = 1; i <= SIG_SPIN; i++)
        s += (uint64_t)i * (uint64_t)i;
    sig_result = s;
    (void)sig;
}

static void *
signal_worker(void *arg)
{
    (void)arg;
    uint64_t want = 0;
    for (uint64_t i = 1; i <= SIG_SPIN; i++)
        want += i * i;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    while (!__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE)) {
        sig_result = 0;
        uint64_t t0 = __atomic_load_n(&g_transitions, __ATOMIC_ACQUIRE);
        syscall(SYS_tgkill, getpid(), tid, SIGUSR2);
        uint64_t t1 = __atomic_load_n(&g_transitions, __ATOMIC_ACQUIRE);
        /* Whether DR attached during the send: transition() counts 1 mod 4 then. */
        int at_attach = t1 >= t0 + (5 - t0 % 4) % 4;
        if (sig_result == 0 && at_attach) {
            /* Known deviation signal-dropped-at-attach: the handler did not run
             * and DR attached while the signal was sent.  DR sets delayable
             * signals to SIG_IGN while it attaches (i#7598).
             */
            g_sig_dropped_at_attach++;
        } else if (sig_result != want) {
            g_sig_bad++;
            if (g_sig_bad <= 5) {
                fprintf(stderr,
                        "FAIL [lifecycle] handler result 0x%llx, expected 0x%llx "
                        "(transitions %llu -> %llu, under DR %d)\n",
                        (unsigned long long)sig_result, (unsigned long long)want,
                        (unsigned long long)t0, (unsigned long long)t1,
                        dr_app_running_under_dynamorio());
            }
        }
        g_sig_runs++;
    }
    return NULL;
}

/* The process-signal worker: sends the process a real-time signal (so none
 * coalesce) carrying a sequence number; whichever thread the kernel picks runs
 * the handler, which counts its number.  Every number must arrive exactly once,
 * across attach and detach: a signal DR has queued for a thread when it detaches
 * goes back to the process.
 */
#define PSIG_MAX (1 << 17)
static volatile uint8_t psig_got[PSIG_MAX];
static volatile uint8_t psig_at_attach[PSIG_MAX];
static volatile uint16_t psig_t0[PSIG_MAX], psig_t1[PSIG_MAX];
static volatile long psig_sent, psig_bad_value;

static void
psig_handler(int sig, siginfo_t *si, void *uc)
{
    int v = si->si_value.sival_int;
    if (si->si_code != SI_QUEUE || v < 0 || v >= PSIG_MAX)
        __atomic_add_fetch(&psig_bad_value, 1, __ATOMIC_RELAXED);
    else
        __atomic_add_fetch(&psig_got[v], 1, __ATOMIC_RELAXED);
    (void)sig;
    (void)uc;
}

static void *
psig_worker(void *arg)
{
    (void)arg;
    for (int seq = 0; seq < PSIG_MAX && !__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE);
         seq++) {
        uint64_t t0 = __atomic_load_n(&g_transitions, __ATOMIC_ACQUIRE);
        union sigval val = { .sival_int = seq };
        sigqueue(getpid(), PSIG, val);
        uint64_t t1 = __atomic_load_n(&g_transitions, __ATOMIC_ACQUIRE);
        psig_at_attach[seq] = t1 >= t0 + (5 - t0 % 4) % 4;
        psig_t0[seq] = (uint16_t)t0;
        psig_t1[seq] = (uint16_t)t1;
        __atomic_store_n(&psig_sent, seq + 1, __ATOMIC_RELEASE);
        sleep_us(100);
    }
    return NULL;
}

/***************************************************************************
 * The controller.
 */
typedef struct {
    const variant_t *v;
    uint64_t seed;
    int rounds, workers;
} child_args_t;

static void
transition(int attach, const variant_t *v)
{
    __atomic_add_fetch(&g_transitions, 1, __ATOMIC_ACQ_REL);
    if (v->dr_ops != NULL) {
        if (attach) {
            if (dr_app_setup_and_start() != 0) {
                fprintf(stderr, "ERROR: dr_app_setup_and_start failed\n");
                _exit(3);
            }
            if (!dr_app_running_under_dynamorio()) {
                fprintf(stderr, "ERROR: not running under DR after attach\n");
                _exit(3);
            }
        } else {
            dr_app_stop_and_cleanup();
            if (dr_app_running_under_dynamorio()) {
                fprintf(stderr, "ERROR: still under DR after detach\n");
                _exit(3);
            }
        }
    }
    g_phase = attach;
    __atomic_add_fetch(&g_transitions, 1, __ATOMIC_ACQ_REL);
}

static int
lifecycle_child(void *arg)
{
    child_args_t *a = (child_args_t *)arg;
    const variant_t *v = a->v;
    rng_t r = { a->seed * 0x9e3779b97f4a7c15ULL + 3 };
    if (v->dr_ops != NULL) {
        char buf[512];
        const char *base = getenv("DYNAMORIO_OPTIONS");
        snprintf(buf, sizeof(buf), "%s %s", base == NULL ? "" : base, v->dr_ops);
        setenv("DYNAMORIO_OPTIONS", buf, 1);
    }
    a64p_fault_pstate_ignore = PSTATE_BTYPE | PSTATE_SSBS;
    g_no_faults = opt_no_faults;
    a64p_on_masked_pstate = on_masked;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR2, &sa, NULL);
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = psig_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(PSIG, &sa, NULL);
    if (pipe(g_pipe) != 0) {
        perror("ERROR: pipe");
        return 1;
    }
    g_nworkers = a->workers;
    for (int i = 0; i < g_nworkers; i++) {
        worker_t *wk = &g_workers[i];
        memset(wk, 0, sizeof(*wk));
        wk->id = i;
        wk->seed = a->seed * 64 + (uint64_t)i;
        /* Slot 0 stays unused: every worker has a non-default layout. */
        a64p_worker_init_slot(&wk->w, i + 1);
        if (pthread_create(&wk->th, NULL, block_worker, wk) != 0) {
            fprintf(stderr, "ERROR: pthread_create\n");
            return 1;
        }
    }
    for (int i = 0; i < g_nworkers; i++) {
        while (!__atomic_load_n(&g_workers[i].ready, __ATOMIC_ACQUIRE))
            sleep_us(1000);
    }
    pthread_t pth, sth, psth;
    pthread_create(&pth, NULL, pipe_worker, NULL);
    int signal_worker_on = !opt_no_signal_worker;
    if (signal_worker_on) {
        pthread_create(&sth, NULL, signal_worker, NULL);
        pthread_create(&psth, NULL, psig_worker, NULL);
    }
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "transitions");
    /* The schedule: attach, run, detach, run; recorded for the report. */
    char sched[2048];
    int sl = 0;
    uint32_t op = 1;
    for (int round = 0; round < a->rounds; round++) {
        uint64_t on_us = 2000 + rn(&r, 60000), off_us = 1000 + rn(&r, 30000);
        if (sl < (int)sizeof(sched) - 32)
            sl += snprintf(sched + sl, sizeof(sched) - sl, " %llu/%llu",
                           (unsigned long long)on_us / 1000,
                           (unsigned long long)off_us / 1000);
        a64p_prog->run = round;
        send_op(op++);
        transition(1, v);
        send_op(op++);
        sleep_us(on_us);
        send_op(op++);
        transition(0, v);
        send_op(op++);
        sleep_us(off_us);
    }
    /* Every worker must still make progress after the last detach. */
    long after[MAXWK];
    for (int i = 0; i < g_nworkers; i++)
        after[i] = g_workers[i].runs;
    long stuck = 0;
    for (int i = 0; i < g_nworkers; i++) {
        uint64_t t0 = now_ns();
        while (g_workers[i].runs <= after[i] + 1 && now_ns() - t0 < 60000000000ULL)
            sleep_us(1000);
        if (g_workers[i].runs <= after[i] + 1) {
            fprintf(stderr,
                    "FAIL [lifecycle] worker %d made no progress in 60 s after "
                    "the last detach\n",
                    i);
            stuck++;
        }
    }
    __atomic_store_n(&g_stop, 1, __ATOMIC_RELEASE);
    for (int i = 0; i < g_nworkers; i++)
        pthread_join(g_workers[i].th, NULL);
    send_op(0);
    pthread_join(pth, NULL);
    long psig_lost = 0, psig_dup = 0, psig_dropped_at_attach = 0;
    if (signal_worker_on) {
        pthread_join(sth, NULL);
        pthread_join(psth, NULL);
        /* Natively, with no thread blocking it, a process signal is taken at once. */
        sleep_us(200000);
        for (long i = 0; i < psig_sent; i++) {
            if (psig_got[i] > 1)
                psig_dup++;
            else if (psig_got[i] == 0) {
                /* Known deviation signal-dropped-at-attach (see signal_worker()). */
                if (psig_at_attach[i])
                    psig_dropped_at_attach++;
                else {
                    if (psig_lost < 5) {
                        fprintf(stderr,
                                "FAIL [lifecycle] process signal %ld was never "
                                "delivered (transitions %d -> %d)\n",
                                i, psig_t0[i], psig_t1[i]);
                    }
                    psig_lost++;
                }
            }
        }
        if (psig_dup > 0 || psig_bad_value > 0) {
            fprintf(stderr,
                    "FAIL [lifecycle] process signals: %ld delivered more than once, "
                    "%ld with a bad value\n",
                    psig_dup, psig_bad_value);
        }
    }

    int fails = 0;
    a64p_counts_t c = { 0 };
    long straddled = 0, phase_runs[2] = { 0, 0 }, masked_dit = 0;
    for (int i = 0; i < g_nworkers; i++) {
        worker_t *wk = &g_workers[i];
        c.generated += NBLK;
        c.accepted += wk->nblk;
        c.executed += wk->runs;
        c.checked += wk->runs - wk->fails;
        fails += (int)wk->fails;
        straddled += wk->straddled;
        masked_dit += wk->masked_dit;
        c.suppressed += wk->masked_dit;
        phase_runs[0] += wk->phase_runs[0];
        phase_runs[1] += wk->phase_runs[1];
        if (verbose) {
            fprintf(stderr,
                    "  worker %d: blocks %d runs %ld native %ld dr %ld straddled %ld "
                    "fails %ld\n",
                    i, wk->nblk, wk->runs, wk->phase_runs[0], wk->phase_runs[1],
                    wk->straddled, wk->fails);
        }
    }
    fails += (int)stuck;
    if (g_ops_got != g_ops_sent || g_ops_bad != 0) {
        fprintf(stderr,
                "FAIL [lifecycle] operation ids: sent %ld, received %ld, bad %ld\n",
                g_ops_sent, g_ops_got, g_ops_bad);
        fails++;
    }
    fails += (int)g_sig_bad;
    fails += (int)(psig_lost + psig_dup + psig_bad_value);
    char label[96];
    snprintf(label, sizeof(label), "lifecycle %s", v->name);
    a64p_counts_print(stdout, label, &c);
    printf("lifecycle %s: %d workers, %d attach/detach rounds, runs native %ld, under "
           "DR %ld, interrupted by a transition %ld; %ld operation ids, %ld handler "
           "runs, %ld process signals\n",
           v->name, g_nworkers, a->rounds, phase_runs[0], phase_runs[1], straddled,
           g_ops_got, g_sig_runs, psig_sent);
    printf("lifecycle %s: known deviations masked: fault-dit-at-transition %ld, "
           "signal-dropped-at-attach %ld\n",
           v->name, masked_dit, g_sig_dropped_at_attach + psig_dropped_at_attach);
    fails += a64p_floor(label, "accepted blocks", c.accepted, (long)g_nworkers);
    fails += a64p_floor(label, "runs checked", c.checked, 50L * g_nworkers);
    if (v->dr_ops != NULL)
        fails += a64p_floor(label, "runs interrupted by a transition", straddled, 1);
    if (signal_worker_on) {
        fails += a64p_floor(label, "handler runs", g_sig_runs, 10);
        fails += a64p_floor(label, "process signals", psig_sent, 100);
    }
    if (fails != 0) {
        fprintf(stderr,
                "A64P-REPLAY v1 prog=a64_prop_lifecycle mode=lifecycle variant=%s "
                "seed=%llu workers=%d rounds=%d schedule(ms on/off):%s\n",
                v->name, (unsigned long long)a->seed, g_nworkers, a->rounds, sched);
    }
    return fails;
}

int
main(int argc, const char *argv[])
{
    const char *mode = argc > 1 ? argv[1] : "lifecycle";
    uint64_t seed = 1;
    int rounds = 60, workers = -1;
    const char *vlist = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc)
            seed = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-rounds") == 0 && i + 1 < argc)
            rounds = atoi(argv[++i]);
        else if (strcmp(argv[i], "-workers") == 0 && i + 1 < argc)
            workers = atoi(argv[++i]);
        else if (strcmp(argv[i], "-variants") == 0 && i + 1 < argc)
            vlist = argv[++i];
        else if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "-known") == 0) {
            /* No known issue is skipped any more; accepted for old reproducers. */
        } else if (strcmp(argv[i], "-no_signal_worker") == 0)
            opt_no_signal_worker = 1;
        else if (strcmp(argv[i], "-no_faults") == 0)
            opt_no_faults = 1;
        else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if (strcmp(mode, "dump") == 0) {
        /* dump -seed S [-no_faults]: print block S (long if -no_faults). */
        lc_init_features();
        /* Worker w uses slot w + 1: -workers gives w here. */
        static a64p_worker_t dw;
        a64p_worker_init_slot(&dw, (workers < 0 ? 0 : workers) + 1);
        a64p_worker_bind(&dw);
        gen_opts_t o;
        lc_opts(&o, opt_no_faults);
        block_t *b = malloc(sizeof(*b));
        if (!a64p_make_block(b, &o, seed))
            return 1;
        print_block(stdout, b);
        return 0;
    }
    if (strcmp(mode, "lifecycle") != 0) {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
#ifdef A64_DR_PROP_DEBUG_DR
    is_debug_build = 1;
#endif
    lc_init_features();
    a64p_progress_init("a64_prop_lifecycle");
    g_devnull = fopen("/dev/null", "w");
    setvbuf(stdout, NULL, _IOLBF, 0);
    int fails = 0, nrun = 0;
    for (int i = 0; i < NVARIANTS; i++) {
        const variant_t *v = &lc_variants[i];
        if (vlist != NULL ? !list_has(vlist, v->name)
                          : (v->debug_only && !is_debug_build))
            continue;
        rng_t r = { seed + (uint64_t)i };
        child_args_t a = { v, seed + (uint64_t)i, rounds,
                           workers > 0 ? workers : 2 + (int)rn(&r, MAXWK - 1) };
        int f = a64p_in_child(mode, v, lifecycle_child, &a);
        if (f != 0)
            fprintf(stderr, "FAIL [%s] variant=%s: %d failures\n", mode, v->name, f);
        fails += f;
        nrun++;
    }
    fails += a64p_floor(mode, "variants run", nrun, 1);
    printf("%s: %s\n", mode, fails == 0 ? "all properties hold" : "FAILURES");
    return fails == 0 ? 0 : 1;
}

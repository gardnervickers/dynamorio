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

/* The contracts of DR's flush API (dr_flush_region(),
 * dr_flush_region_ex(), dr_unlink_flush_region(), dr_delay_flush_region())
 * and of resets, on AArch64, under load, with native runs of the same code as
 * the oracle for the application's state.  Each option variant runs in a
 * forked child that starts static DR with an in-process client.
 *
 * 2-8 workers, each in its own generator layout slot, run random blocks
 * (a64_dr_prop_gen.h: an outer loop for long runs, planned faults and BRKs,
 * syscalls, exclusives, indirect branches) over and over from fixed initial
 * states; each run's final state and faults must equal the native run's
 * (computed before DR starts).  Each worker's code region is a flush region.
 *
 * The client instruments every block of a region with a clean call at its
 * entry and one before its last instruction.  Each passes the block's build
 * epoch: the region's epoch counter when the client instrumented it.  A
 * flush first increments the region's epoch, so every fragment built before
 * the flush has an older epoch, and when the flush's contract says it is
 * complete the flusher publishes the epoch as the region's valid epoch.  A
 * check that reads a valid epoch newer than its block's build epoch has
 * executed a fragment the flush covered, and records that observation.
 * Properties, per flush kind:
 *   full (dr_flush_region(), dr_flush_region_ex()): after it returns no
 *     thread executes any flushed fragment, so every such observation is a
 *     failure.  Called from a clean call it must redirect (the caller resumes
 *     with dr_redirect_execution() at the instrumented instruction: the run's
 *     final state checks that), and the _ex completion callback runs exactly
 *     once, before it returns, while every other thread is suspended (their
 *     check counters must not move during it).
 *   unlink (dr_unlink_flush_region()): a thread already in a flushed fragment
 *     may finish it, but no thread enters one after it returns.  Each region's
 *     fragment entries are counted (a trace keeps only its first entry
 *     check); the flusher reads the count after publishing (with fences on
 *     both sides), and an observation from an entry more than one past that
 *     count is a failure.
 *   delayed (dr_delay_flush_region()): with a callback, the callback runs
 *     exactly once and within a bounded time, and after it no flushed
 *     fragment executes (as for full); without one, only the state oracle.
 * Flushes are issued from a worker's own check clean call (of its own or
 * another worker's region), from a clean call in the controller's host code,
 * and from a pre-syscall event; and over a region that was never executed.
 * Resets (-reset_every_nth_pending, -reset_every_nth_bb_unit) must be seen to
 * happen: a sentinel thread spins in a long loop that nothing flushes; a
 * pending-deletion reset moves it out of the cache (a block is built at a
 * mid-loop pc), a full reset rebuilds its blocks.  Floors on runs checked,
 * flushes of each kind and issuer, flushes that took effect (a block was
 * rebuilt with the new epoch), and observed resets.
 *
 * Variants: native (the harness's control: no DR, the operations do
 * nothing), default, smallbb (-max_bb_instrs 6), reset_pending (unlink and
 * delayed flushes only, so that the pending-deletion list fills and every
 * synchall is a reset's) and reset_all (-reset_every_nth_bb_unit).  Traces
 * are off by default on AArch64; -enable_traces currently fails without any
 * flush (a usage error "Incorrect predicate value" in trace building, and
 * pointer authentication failures in generated code), so no variant uses
 * them.  -thread_private is not usable on AArch64 either (it enables
 * -coarse_units and inlined trace IBL, both not yet implemented there).
 *
 * Known, not yet fixed DR issues (2026-10-14), seen in debug builds only:
 *   smallbb-xl8-spill: under -max_bb_instrs 6, translating a thread for a
 *     synchall flush can trip translate.c's check that a register spilled
 *     across an app instruction is restored from TLS later in the block
 *     (translate.c "spill_or_restore && r == reg - REG_START_SPILL ...");
 *     about 1 in 40 runs.  smallbb therefore only runs when named.
 *   last-exit-deleted: rarely (about 1 in 80 runs of default), an unlink
 *     flush from a clean call finds the thread's last_fragment deleted while
 *     last_exit is not one of its exits (link.c last_exit_deleted()
 *     ASSERT_NOT_REACHED; release builds just mark the exit ordinal invalid).
 *
 * Usage: a64_prop_flush flush [-seed S] [-secs T] [-workers W]
 *        [-variants a,b,...] [-ops a,b,...] [-issuers a,b,...] [-v]
 * Each DR variant runs for T seconds (default 20; native 2).  The seed sets the
 * blocks, worker count and operation schedule; the interleaving with the
 * workers is not reproducible, so a failure prints the last operations.
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
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "a64_prop_support.h"

#define PSTATE_BTYPE 0xc00ULL
#define PSTATE_SSBS 0x1000ULL

static int verbose;
static int is_debug_build;
/* -ops a,b: only these operation kinds; -issuers a,b: only these issuers. */
static const char *opt_ops, *opt_issuers;

typedef struct {
    variant_t v;
    /* Flush kinds that use a synchall (full, _ex, delayed with a callback):
     * off where a reset must be attributable to the pending-deletion trigger.
     */
    int synchall_ops;
    /* 1: a pending-deletion reset must be observed; 2: a full reset. */
    int want_reset;
    /* Runs only when named with -variants (see the known issues above). */
    int opt_in;
} fl_variant_t;

/* dr_ops NULL: no DR at all (the native control of the harness). */
static const fl_variant_t fl_variants[] = {
    { { "native", NULL, 0, 0, 0, 0 }, 1, 0, 0 },
    { { "default", "", 0, 0, 0, 0 }, 1, 0, 0 },
    /* Many small fragments: more fragment boundaries and redirect points. */
    { { "smallbb", "-max_bb_instrs 6", 0, 0, 0, 0 }, 1, 0, 1 },
    { { "reset_pending", "-enable_reset -reset_every_nth_pending 3", 0, 0, 0, 0 },
      0,
      1,
      0 },
    { { "reset_all", "-enable_reset -reset_every_nth_bb_unit 8", 0, 0, 0, 0 }, 1, 2, 0 },
};
#define NVARIANTS ((int)(sizeof(fl_variants) / sizeof(fl_variants[0])))

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

static pthread_mutex_t out_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_devnull;
static volatile int g_stop;
static int g_under_dr;

/***************************************************************************
 * Regions and epochs (shared by the client and the test).
 */
#define MAXWK 8
/* Regions 0..MAXWK-1 are the workers'; one more is mapped but never run. */
#define MAXR (MAXWK + 1)
#define MAXE 8192
#define UNEXEC_SLOT 40
#define SENTINEL_SLOT 41

enum { ET_NONE, ET_FULL, ET_UNLINK, ET_DELAY };
enum { CK_ENTRY, CK_EXIT };

static int g_nregions;
static uint64_t g_region_lo[MAXR], g_region_hi[MAXR];
/* Build epoch: incremented before every flush of the region. */
static volatile uint64_t g_build[MAXR];
/* The newest epoch whose flush is complete per its contract. */
static volatile uint64_t g_valid[MAXR];
/* Fragment entries in the region (only its worker runs its code). */
static volatile long g_entries[MAXR];
/* Per epoch: the kind of flush that published it, and for unlink flushes
 * the region's entry count read after publishing.
 */
static uint8_t g_etype[MAXR][MAXE];
static long g_snap[MAXR][MAXE];
/* The unlink flush was issued by the region's own worker: it knows exactly
 * which fragment it is in, so no entry after its count is allowed.
 */
static uint8_t g_snap_self[MAXR][MAXE];
/* Checks executed, and checks that saw their own block's epoch current
 * after a flush (the flush took effect: a block was rebuilt).
 */
static volatile long g_checks[MAXR], g_rebuilt_seen[MAXR];
/* Whether the region's worker is inside check_cc() (diagnostics). */
static volatile int g_in_cc[MAXR];

typedef struct {
    int kind;
    uint64_t built, valid;
    long n;
    uint64_t pc;
} stale_t;
#define MAXSTALE 1024
static stale_t g_stale[MAXR][MAXSTALE];
static volatile long g_nstale[MAXR];

static int
region_of(uint64_t pc)
{
    for (int r = 0; r < g_nregions; r++) {
        if (pc >= g_region_lo[r] && pc < g_region_hi[r])
            return r;
    }
    return -1;
}

static uint64_t
bump_epoch(int r)
{
    return __atomic_add_fetch(&g_build[r], 1, __ATOMIC_SEQ_CST);
}

static void
publish(int r, uint64_t e, int type, int self)
{
    if (e >= MAXE)
        return;
    g_etype[r][e] = (uint8_t)type;
    g_snap_self[r][e] = (uint8_t)self;
    uint64_t cur = __atomic_load_n(&g_valid[r], __ATOMIC_SEQ_CST);
    while (cur < e &&
           !__atomic_compare_exchange_n(&g_valid[r], &cur, e, false, __ATOMIC_SEQ_CST,
                                        __ATOMIC_SEQ_CST)) {
    }
    if (type == ET_UNLINK) {
        /* Dekker with check_cc(): either this read sees an entry's increment
         * or that entry's check sees the new valid epoch.
         */
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        g_snap[r][e] = __atomic_load_n(&g_entries[r], __ATOMIC_SEQ_CST);
    }
}

/***************************************************************************
 * Flush operations.
 */
enum {
    OP_FULL,         /* dr_flush_region() */
    OP_FULL_EX,      /* dr_flush_region_ex() with a completion callback */
    OP_UNLINK,       /* dr_unlink_flush_region() */
    OP_DELAY_CB,     /* dr_delay_flush_region() with a callback */
    OP_DELAY_NOCB,   /* dr_delay_flush_region() without one */
    OP_FULL_UNEXEC,  /* dr_flush_region() over a never-executed region */
    OP_DELAY_UNEXEC, /* dr_delay_flush_region() with a callback, likewise */
    OP_NUM
};
static const char *const op_names[OP_NUM] = { "full",        "full_ex",    "unlink",
                                              "delay_cb",    "delay_nocb", "full_unexec",
                                              "delay_unexec" };
enum { IS_CTRL_CC, IS_CTRL_SYS, IS_WORKER, IS_NUM };
static const char *const issuer_names[IS_NUM] = { "ctrl-cleancall", "ctrl-syscall",
                                                  "worker" };

typedef struct {
    int kind, issuer, target, worker;
    uint32_t id;
    uint64_t epoch;
    volatile int state; /* 0 posted, 1 taken, 2 done */
    volatile int ok;
    volatile int cb_count, cb_after_return, cb_threads_moved;
    /* Diagnostics: per region, checks during the callback, and whether its
     * worker was inside a check's clean call when the callback started;
     * [MAXR]: sentinel progress.
     */
    long cb_moved[MAXR + 1];
    int cb_in_cc[MAXR];
    volatile int returned;
    int self; /* the issuing worker flushed its own region */
    uint64_t t_post;
} op_t;

#define MAXOPS 4096
static op_t g_ops[MAXOPS];
static volatile int g_nops;
/* Per worker mailbox, polled by its checks. */
static op_t *volatile g_mail[MAXWK];

/* Delayed flushes with a callback, by id. */
typedef struct {
    int region;
    uint64_t epoch, t_req, t_done;
    volatile int count;
} delay_t;
static delay_t g_delay[MAXOPS];

static volatile long g_ops_done[OP_NUM][IS_NUM];
static volatile long g_self_redirects;
/* Sentinel progress, read by the completion callbacks. */
static volatile uint64_t g_sentinel[2]; /* [0] stop flag, [1] progress */

static void
delay_cb(int id)
{
    delay_t *d = &g_delay[id];
    int c = __atomic_add_fetch(&d->count, 1, __ATOMIC_SEQ_CST);
    if (c == 1) {
        d->t_done = now_ns();
        if (d->region >= 0)
            publish(d->region, d->epoch, ET_DELAY, 0);
    }
}

static void
full_ex_cb(void *user_data)
{
    op_t *op = (op_t *)user_data;
    __atomic_add_fetch(&op->cb_count, 1, __ATOMIC_SEQ_CST);
    if (op->returned)
        op->cb_after_return = 1;
    /* Every other thread is suspended: nothing may move. */
    long before[MAXR + 1], after[MAXR + 1];
    int in_cc[MAXR];
    for (int r = 0; r < g_nregions; r++) {
        in_cc[r] = __atomic_load_n(&g_in_cc[r], __ATOMIC_SEQ_CST);
        before[r] = __atomic_load_n(&g_checks[r], __ATOMIC_SEQ_CST);
    }
    before[MAXR] = (long)__atomic_load_n(&g_sentinel[1], __ATOMIC_SEQ_CST);
    uint64_t t0 = now_ns();
    while (now_ns() - t0 < 300000) {
    }
    for (int r = 0; r < g_nregions; r++)
        after[r] = __atomic_load_n(&g_checks[r], __ATOMIC_SEQ_CST);
    after[MAXR] = (long)__atomic_load_n(&g_sentinel[1], __ATOMIC_SEQ_CST);
    for (int r = 0; r < g_nregions; r++) {
        op->cb_moved[r] = after[r] - before[r];
        op->cb_in_cc[r] = in_cc[r];
        if (before[r] != after[r])
            op->cb_threads_moved = 1;
    }
    op->cb_moved[MAXR] = after[MAXR] - before[MAXR];
    if (before[MAXR] != after[MAXR])
        op->cb_threads_moved = 1;
}

/* Performs op on the calling thread.  pc, if not 0, is where a clean call
 * that performs a full flush must redirect to.
 */
static void
perform_op(op_t *op, uint64_t pc)
{
    int t = op->target;
    app_pc base = (app_pc)(uintptr_t)g_region_lo[t];
    size_t size = (size_t)(g_region_hi[t] - g_region_lo[t]);
    dr_mcontext_t mc;
    void *dc = dr_get_current_drcontext();
    int redirect = 0;
    switch (op->kind) {
    case OP_FULL:
    case OP_FULL_EX:
        if (pc != 0) {
            mc.size = sizeof(mc);
            mc.flags = DR_MC_ALL;
            dr_get_mcontext(dc, &mc);
            mc.pc = (app_pc)(uintptr_t)pc;
            redirect = 1;
        }
        op->epoch = bump_epoch(t);
        if (op->kind == OP_FULL)
            op->ok = dr_flush_region(base, size);
        else
            op->ok = dr_flush_region_ex(base, size, full_ex_cb, op);
        op->returned = 1;
        publish(t, op->epoch, ET_FULL, 0);
        break;
    case OP_UNLINK:
        op->epoch = bump_epoch(t);
        op->ok = dr_unlink_flush_region(base, size);
        publish(t, op->epoch, ET_UNLINK, op->self);
        break;
    case OP_DELAY_CB:
    case OP_DELAY_UNEXEC:
        op->epoch = bump_epoch(t);
        g_delay[op->id].region = op->kind == OP_DELAY_CB ? t : -1;
        g_delay[op->id].epoch = op->epoch;
        g_delay[op->id].t_req = now_ns();
        op->ok = dr_delay_flush_region(base, size, op->id, delay_cb);
        break;
    case OP_DELAY_NOCB:
        op->epoch = bump_epoch(t);
        op->ok = dr_delay_flush_region(base, size, op->id, NULL);
        break;
    case OP_FULL_UNEXEC:
        op->epoch = bump_epoch(t);
        op->ok = dr_flush_region(base, size);
        break;
    }
    __atomic_add_fetch(&g_ops_done[op->kind][op->issuer], 1, __ATOMIC_SEQ_CST);
    if (redirect && op->self)
        __atomic_add_fetch(&g_self_redirects, 1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&op->state, 2, __ATOMIC_RELEASE);
    if (redirect) {
        dr_redirect_execution(&mc);
        DR_ASSERT_MSG(false, "dr_redirect_execution returned");
    }
}

static int
take_op(op_t *op)
{
    int expect = 0;
    return __atomic_compare_exchange_n(&op->state, &expect, 1, false, __ATOMIC_ACQ_REL,
                                       __ATOMIC_ACQUIRE);
}

/***************************************************************************
 * The client.
 */
#define NOTE_ENTRY_START ((void *)(uintptr_t)0xf1a5e001)
#define NOTE_ENTRY_END ((void *)(uintptr_t)0xf1a5e002)
/* Not a syscall; unlike 4000, which the generator uses as one. */
#define MAGIC_SYSNUM 4093

static volatile int g_sentinel_warm;
#define MAXNAT 512
static uint64_t g_sentinel_nat[MAXNAT];
static volatile int g_nnat;
static volatile long g_sentinel_mid, g_sentinel_natural;
static volatile long g_traces_trimmed, g_traces_region, g_traces_all;

static void
check_cc(int r, int built, int kind, uint64_t pc)
{
    __atomic_store_n(&g_in_cc[r], 1, __ATOMIC_SEQ_CST);
    long n;
    if (kind == CK_ENTRY) {
        n = __atomic_load_n(&g_entries[r], __ATOMIC_RELAXED) + 1;
        __atomic_store_n(&g_entries[r], n, __ATOMIC_RELAXED);
    } else
        n = __atomic_load_n(&g_entries[r], __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    uint64_t v = __atomic_load_n(&g_valid[r], __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_checks[r], g_checks[r] + 1, __ATOMIC_RELAXED);
    if ((uint64_t)built < v) {
        long i = g_nstale[r];
        if (i < MAXSTALE) {
            g_stale[r][i].kind = kind;
            g_stale[r][i].built = (uint64_t)built;
            g_stale[r][i].valid = v;
            g_stale[r][i].n = n;
            g_stale[r][i].pc = pc;
        }
        __atomic_store_n(&g_nstale[r], i + 1, __ATOMIC_RELEASE);
    } else if ((uint64_t)built == v && v > 0)
        __atomic_store_n(&g_rebuilt_seen[r], g_rebuilt_seen[r] + 1, __ATOMIC_RELAXED);
    if (r < MAXWK) {
        op_t *op = __atomic_exchange_n(&g_mail[r], NULL, __ATOMIC_ACQ_REL);
        if (op != NULL && take_op(op)) {
            __atomic_store_n(&g_in_cc[r], 2, __ATOMIC_SEQ_CST);
            perform_op(op, pc);
        }
    }
    __atomic_store_n(&g_in_cc[r], 0, __ATOMIC_SEQ_CST);
}

/* The controller's flush gate: the client inserts a clean call at its entry,
 * where a full flush's redirect resumes (the operation is then done, so the
 * clean call returns at once).
 */
static uint64_t g_gate_pc;
__attribute__((noinline, used)) void
ctrl_gate(op_t *op)
{
    __asm__ volatile("" : : "r"(op) : "memory");
}

static void
ctrl_gate_cc_pc(op_t *op)
{
    if (take_op(op)) {
        perform_op(op, op->kind == OP_FULL || op->kind == OP_FULL_EX ? g_gate_pc : 0);
    }
}

static void
sentinel_bb(uint64_t tag)
{
    if (!__atomic_load_n(&g_sentinel_warm, __ATOMIC_ACQUIRE)) {
        int n = g_nnat;
        for (int i = 0; i < n; i++) {
            if (g_sentinel_nat[i] == tag)
                return;
        }
        if (n < MAXNAT) {
            g_sentinel_nat[n] = tag;
            __atomic_store_n(&g_nnat, n + 1, __ATOMIC_RELEASE);
        }
        return;
    }
    for (int i = 0; i < g_nnat; i++) {
        if (g_sentinel_nat[i] == tag) {
            __atomic_add_fetch(&g_sentinel_natural, 1, __ATOMIC_SEQ_CST);
            return;
        }
    }
    __atomic_add_fetch(&g_sentinel_mid, 1, __ATOMIC_SEQ_CST);
}

static dr_emit_flags_t
event_bb(void *dc, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    uint64_t pc = (uint64_t)(uintptr_t)tag;
    if (pc == (uint64_t)(uintptr_t)ctrl_gate) {
        instr_t *first = instrlist_first_app(bb);
        g_gate_pc = (uint64_t)(uintptr_t)instr_get_app_pc(first);
        dr_insert_clean_call(dc, bb, first, (void *)ctrl_gate_cc_pc, false, 1,
                             opnd_create_reg(DR_REG_X0));
        return DR_EMIT_DEFAULT;
    }
    if (pc >= a64g_slot_code_base(SENTINEL_SLOT) &&
        pc < a64g_slot_code_base(SENTINEL_SLOT) + CODE_SIZE) {
        if (!for_trace && !translating)
            sentinel_bb(pc);
        return DR_EMIT_DEFAULT;
    }
    int r = region_of(pc);
    if (r < 0)
        return DR_EMIT_DEFAULT;
    /* One movz whatever the value: translation recreates the same layout. */
    uint64_t built = __atomic_load_n(&g_build[r], __ATOMIC_SEQ_CST);
    if (built > 0xffff)
        built = 0xffff;
    instr_t *first = instrlist_first_app(bb), *last = instrlist_last_app(bb);
    instr_t *l0 = INSTR_CREATE_label(dc), *l1 = INSTR_CREATE_label(dc);
    instr_set_note(l0, NOTE_ENTRY_START);
    instr_set_note(l1, NOTE_ENTRY_END);
    instrlist_meta_preinsert(bb, first, l0);
    dr_insert_clean_call(dc, bb, first, (void *)check_cc, false, 4, OPND_CREATE_INT32(r),
                         OPND_CREATE_INT32((int)built), OPND_CREATE_INT32(CK_ENTRY),
                         OPND_CREATE_INTPTR(instr_get_app_pc(first)));
    instrlist_meta_preinsert(bb, first, l1);
    if (last != first) {
        dr_insert_clean_call(dc, bb, last, (void *)check_cc, false, 4,
                             OPND_CREATE_INT32(r), OPND_CREATE_INT32((int)built),
                             OPND_CREATE_INT32(CK_EXIT),
                             OPND_CREATE_INTPTR(instr_get_app_pc(last)));
    }
    return DR_EMIT_DEFAULT;
}

/* A trace keeps only its first entry check: a thread entering a trace
 * enters one fragment.
 */
static dr_emit_flags_t
event_trace(void *dc, void *tag, instrlist_t *trace, bool translating)
{
    int seen = 0, removing = 0, trimmed = 0;
    instr_t *in, *next;
    for (in = instrlist_first(trace); in != NULL; in = next) {
        next = instr_get_next(in);
        int is_start = instr_is_label(in) && instr_get_note(in) == NOTE_ENTRY_START;
        int is_end = instr_is_label(in) && instr_get_note(in) == NOTE_ENTRY_END;
        if (is_start && seen++ > 0)
            removing = 1;
        if (removing) {
            instrlist_remove(trace, in);
            instr_destroy(dc, in);
            trimmed = 1;
            if (is_end)
                removing = 0;
        }
    }
    if (trimmed && !translating)
        __atomic_add_fetch(&g_traces_trimmed, 1, __ATOMIC_RELAXED);
    if (!translating)
        __atomic_add_fetch(&g_traces_all, 1, __ATOMIC_RELAXED);
    if (seen > 0 && !translating)
        __atomic_add_fetch(&g_traces_region, 1, __ATOMIC_RELAXED);
    return DR_EMIT_DEFAULT;
}

static bool
event_filter_syscall(void *dc, int sysnum)
{
    return sysnum == MAGIC_SYSNUM;
}

static bool
event_pre_syscall(void *dc, int sysnum)
{
    if (sysnum != MAGIC_SYSNUM)
        return true;
    op_t *op = (op_t *)dr_syscall_get_param(dc, 0);
    if (op >= g_ops && op < g_ops + MAXOPS && take_op(op))
        perform_op(op, 0);
    dr_syscall_set_result(dc, 0);
    return false;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_register_bb_event(event_bb);
    dr_register_trace_event(event_trace);
    dr_register_filter_syscall_event(event_filter_syscall);
    dr_register_pre_syscall_event(event_pre_syscall);
}

/***************************************************************************
 * Block workers (as in a64_prop_lifecycle.c).
 */
#define NBLK 2

typedef struct {
    int id;
    pthread_t th;
    a64p_worker_t w;
    uint64_t seed;
    block_t *b[NBLK];
    result_t *expect[NBLK];
    int nblk;
    volatile int ready;
    volatile long runs, fails;
} worker_t;

static worker_t g_workers[MAXWK];
static int g_nworkers;
static volatile int g_go;

static void
fl_opts(gen_opts_t *o, int long_block)
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

static void
report_mismatch(worker_t *wk, int bi, result_t *got)
{
    pthread_mutex_lock(&out_lock);
    fprintf(stderr,
            "FAIL [flush] worker %d block %d (seed %llu) run %ld: state differs from "
            "the native run\n",
            wk->id, bi, (unsigned long long)wk->b[bi]->seed, wk->runs);
    a64p_cmp_results(stderr, wk->b[bi], wk->expect[bi], got);
    if (got->nf != wk->expect[bi]->nf)
        a64p_print_faults(stderr, "dr", got);
    pthread_mutex_unlock(&out_lock);
}

static void *
block_worker(void *arg)
{
    worker_t *wk = (worker_t *)arg;
    a64p_worker_bind(&wk->w);
    a64p_setup_maps();
    a64p_install_handlers(&wk->w, 0);
    gen_opts_t o;
    result_t *tmp = malloc(sizeof(*tmp));
    for (int tries = 0; wk->nblk < NBLK && tries < 8 * NBLK; tries++) {
        block_t *b = malloc(sizeof(*b));
        result_t *e = malloc(sizeof(*e));
        uint64_t s = wk->seed * 1000 + (uint64_t)tries;
        fl_opts(&o, (wk->nblk % 2) == 0);
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
    while (!__atomic_load_n(&g_go, __ATOMIC_ACQUIRE))
        sleep_us(1000);
    rng_t r = { wk->seed ^ 0x5bd1e995ULL };
    int cur = -1;
    while (!__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE) && wk->nblk > 0) {
        /* Mostly stay on one block: a switch reinstalls the code (munmap and
         * mmap, which DR flushes too).
         */
        int bi = cur < 0 || rp(&r, 3) ? (int)rn(&r, (uint32_t)wk->nblk) : cur;
        if (bi != cur) {
            a64p_install_code(&wk->w, wk->b[bi], 0);
            cur = bi;
        }
        a64p_run_block(&wk->w, wk->b[bi], tmp);
        wk->runs++;
        if (a64p_cmp_results(g_devnull, wk->b[bi], wk->expect[bi], tmp) != 0) {
            wk->fails++;
            if (wk->fails <= 3)
                report_mismatch(wk, bi, tmp);
        }
    }
    free(tmp);
    return NULL;
}

/***************************************************************************
 * The sentinel: a long loop that nothing flushes.
 */
#define SENTINEL_ADDS 1500

static void
install_sentinel(void)
{
    uint64_t base = a64g_slot_code_base(SENTINEL_SLOT);
    uint32_t *p = mmap((void *)base, CODE_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p != (uint32_t *)base) {
        fprintf(stderr, "ERROR: cannot map the sentinel\n");
        exit(2);
    }
    int n = 0;
    /* loop: add x1, x1, #1 (x SENTINEL_ADDS); str x1, [x0, #8];
     *       ldr x2, [x0]; cbz x2, loop; ret
     */
    for (int i = 0; i < SENTINEL_ADDS; i++)
        p[n++] = 0x91000421;
    p[n++] = 0xf9000401;
    p[n++] = 0xf9400002;
    p[n] = 0xb4000002 | ((uint32_t)(-(n)) & 0x7ffff) << 5;
    n++;
    p[n++] = 0xd65f03c0;
    __builtin___clear_cache((char *)p, (char *)(p + n));
    if (mprotect(p, CODE_SIZE, PROT_READ | PROT_EXEC) != 0) {
        perror("ERROR: mprotect");
        exit(2);
    }
}

static void *
sentinel_thread(void *arg)
{
    (void)arg;
    void (*fn)(volatile uint64_t *) =
        (void (*)(volatile uint64_t *))(uintptr_t)a64g_slot_code_base(SENTINEL_SLOT);
    fn(g_sentinel);
    return NULL;
}

/* A region that is mapped and holds code but never runs. */
static void
install_unexec(void)
{
    uint64_t base = a64g_slot_code_base(UNEXEC_SLOT);
    uint32_t *p = mmap((void *)base, CODE_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p != (uint32_t *)base) {
        fprintf(stderr, "ERROR: cannot map the unexecuted region\n");
        exit(2);
    }
    for (int i = 0; i < 64; i++)
        p[i] = 0xd65f03c0;
    if (mprotect(p, CODE_SIZE, PROT_READ | PROT_EXEC) != 0) {
        perror("ERROR: mprotect");
        exit(2);
    }
}

/***************************************************************************
 * The controller.
 */
typedef struct {
    const fl_variant_t *fv;
    uint64_t seed;
    int workers;
    double secs;
} child_args_t;

/* Issues op and waits for it; returns 0 if it did not complete in time. */
static int
issue(op_t *op)
{
    op->t_post = now_ns();
    if (!g_under_dr) {
        /* The native control: nothing to flush. */
        op->state = 2;
        op->ok = 1;
        __atomic_add_fetch(&g_ops_done[op->kind][op->issuer], 1, __ATOMIC_SEQ_CST);
        if (op->kind == OP_DELAY_CB || op->kind == OP_DELAY_UNEXEC) {
            g_delay[op->id].region = -1;
            g_delay[op->id].t_req = now_ns();
            delay_cb((int)op->id);
        }
        return 1;
    }
    switch (op->issuer) {
    case IS_CTRL_CC: ctrl_gate(op); break;
    case IS_CTRL_SYS: syscall(MAGIC_SYSNUM, op); break;
    case IS_WORKER: __atomic_store_n(&g_mail[op->worker], op, __ATOMIC_RELEASE); break;
    }
    uint64_t t0 = now_ns();
    while (__atomic_load_n(&op->state, __ATOMIC_ACQUIRE) != 2) {
        if (now_ns() - t0 > 30000000000ULL) {
            /* Withdraw it if still in the mailbox. */
            op_t *expect = op;
            __atomic_compare_exchange_n(&g_mail[op->worker], &expect, NULL, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
            return 0;
        }
        sleep_us(100);
    }
    return 1;
}

static void
print_op(FILE *f, op_t *op)
{
    fprintf(f, "    op %u %s by %s", op->id, op_names[op->kind],
            issuer_names[op->issuer]);
    if (op->issuer == IS_WORKER)
        fprintf(f, " %d", op->worker);
    fprintf(f, " of region %d epoch %llu ok %d\n", op->target,
            (unsigned long long)op->epoch, op->ok);
}

static int
flush_child(void *arg)
{
    child_args_t *a = (child_args_t *)arg;
    const fl_variant_t *fv = a->fv;
    g_under_dr = fv->v.dr_ops != NULL;
    rng_t r = { a->seed * 0x9e3779b97f4a7c15ULL + 7 };
    a64p_fault_pstate_ignore = PSTATE_BTYPE | PSTATE_SSBS;
    g_nworkers = a->workers;
    g_nregions = g_nworkers + 1;
    for (int i = 0; i < g_nworkers; i++) {
        g_region_lo[i] = a64g_slot_code_base(i + 1);
        g_region_hi[i] = g_region_lo[i] + CODE_SIZE;
    }
    g_region_lo[g_nworkers] = a64g_slot_code_base(UNEXEC_SLOT);
    g_region_hi[g_nworkers] = g_region_lo[g_nworkers] + CODE_SIZE;
    install_unexec();
    install_sentinel();
    for (int i = 0; i < g_nworkers; i++) {
        worker_t *wk = &g_workers[i];
        memset(wk, 0, sizeof(*wk));
        wk->id = i;
        wk->seed = a->seed * 64 + (uint64_t)i;
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
    pthread_t sth;
    pthread_create(&sth, NULL, sentinel_thread, NULL);
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "start");
    if (g_under_dr)
        a64p_start_dr(fv->v.dr_ops);
    __atomic_store_n(&g_go, 1, __ATOMIC_RELEASE);
    /* Warm up: the sentinel's blocks are built, the workers run. */
    uint64_t t0 = now_ns();
    while ((__atomic_load_n(&g_sentinel[1], __ATOMIC_ACQUIRE) < 20000 ||
            now_ns() - t0 < 200000000ULL) &&
           now_ns() - t0 < 30000000000ULL)
        sleep_us(1000);
    __atomic_store_n(&g_sentinel_warm, 1, __ATOMIC_RELEASE);

    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "flushes");
    int fails = 0;
    uint64_t t_end = now_ns() + (uint64_t)(a->secs * 1e9);
    long lost = 0, unexpected_false = 0, ex_bad = 0, ex_moved = 0;
    while (now_ns() < t_end && g_nops < MAXOPS - 1) {
        op_t *op = &g_ops[g_nops];
        memset(op, 0, sizeof(*op));
        op->id = (uint32_t)g_nops;
        int k;
        do {
            k = (int)rn(&r, 20);
            /* Weights: full 4, full_ex 2, unlink 5, delay_cb 4, delay_nocb 3,
             * the unexecuted region 1 each.
             */
            k = k < 4    ? OP_FULL
                : k < 6  ? OP_FULL_EX
                : k < 11 ? OP_UNLINK
                : k < 15 ? OP_DELAY_CB
                : k < 18 ? OP_DELAY_NOCB
                : k < 19 ? OP_FULL_UNEXEC
                         : OP_DELAY_UNEXEC;
        } while ((!fv->synchall_ops &&
                  (k == OP_FULL || k == OP_FULL_EX || k == OP_DELAY_CB ||
                   k == OP_FULL_UNEXEC || k == OP_DELAY_UNEXEC)) ||
                 (opt_ops != NULL && !list_has(opt_ops, op_names[k])));
        op->kind = k;
        do
            op->issuer = (int)rn(&r, IS_NUM);
        while (opt_issuers != NULL && !list_has(opt_issuers, issuer_names[op->issuer]));
        op->worker = (int)rn(&r, (uint32_t)g_nworkers);
        if (k == OP_FULL_UNEXEC || k == OP_DELAY_UNEXEC)
            op->target = g_nworkers;
        else if (op->issuer == IS_WORKER && rp(&r, 50))
            op->target = op->worker;
        else
            op->target = (int)rn(&r, (uint32_t)g_nworkers);
        op->self = op->issuer == IS_WORKER && op->target == op->worker;
        __atomic_store_n(&g_nops, g_nops + 1, __ATOMIC_RELEASE);
        a64p_prog->run = (int)op->id;
        snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "op %s by %s of region %d",
                 op_names[op->kind], issuer_names[op->issuer], op->target);
        if (!issue(op)) {
            lost++;
            pthread_mutex_lock(&out_lock);
            fprintf(stderr, "FAIL [flush] operation not performed within 30 s:\n");
            print_op(stderr, op);
            pthread_mutex_unlock(&out_lock);
            continue;
        }
        if (!op->ok) {
            unexpected_false++;
            pthread_mutex_lock(&out_lock);
            fprintf(stderr, "FAIL [flush] flush call returned false:\n");
            print_op(stderr, op);
            pthread_mutex_unlock(&out_lock);
        }
        if (op->kind == OP_FULL_EX && g_under_dr &&
            (op->cb_count != 1 || op->cb_after_return)) {
            ex_bad++;
            pthread_mutex_lock(&out_lock);
            fprintf(stderr,
                    "FAIL [flush] dr_flush_region_ex callback ran %d times (after "
                    "return: %d)\n",
                    op->cb_count, op->cb_after_return);
            print_op(stderr, op);
            pthread_mutex_unlock(&out_lock);
        }
        if (op->kind == OP_FULL_EX && op->cb_threads_moved) {
            ex_moved++;
            pthread_mutex_lock(&out_lock);
            fprintf(stderr,
                    "FAIL [flush] other threads ran during dr_flush_region_ex's "
                    "completion callback:");
            for (int rg = 0; rg < g_nregions; rg++) {
                if (op->cb_moved[rg] != 0) {
                    fprintf(stderr, " region %d +%ld checks (in a check: %d)", rg,
                            op->cb_moved[rg], op->cb_in_cc[rg]);
                }
            }
            if (op->cb_moved[MAXR] != 0)
                fprintf(stderr, " sentinel +%ld", op->cb_moved[MAXR]);
            fprintf(stderr, "\n");
            print_op(stderr, op);
            pthread_mutex_unlock(&out_lock);
        }
        sleep_us(500 + rn(&r, 8000));
    }
    fails += (int)(lost + unexpected_false + ex_bad + ex_moved);

    /* Every delayed flush with a callback completes, exactly once, while the
     * workers still run (any thread entering the cache processes them).
     */
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "delayed");
    t0 = now_ns();
    int nops = g_nops;
    long delay_req = 0, delay_never = 0, delay_multi = 0;
    uint64_t delay_max_ns = 0;
    for (;;) {
        int pending = 0;
        for (int i = 0; i < nops; i++) {
            op_t *op = &g_ops[i];
            if ((op->kind == OP_DELAY_CB || op->kind == OP_DELAY_UNEXEC) && op->ok &&
                op->state == 2 && g_delay[i].count == 0)
                pending++;
        }
        if (pending == 0 || now_ns() - t0 > 20000000000ULL)
            break;
        sleep_us(2000);
    }
    __atomic_store_n(&g_stop, 1, __ATOMIC_RELEASE);
    for (int i = 0; i < g_nworkers; i++)
        pthread_join(g_workers[i].th, NULL);
    __atomic_store_n(&g_sentinel[0], 1, __ATOMIC_RELEASE);
    pthread_join(sth, NULL);
    for (int i = 0; i < nops; i++) {
        op_t *op = &g_ops[i];
        if (!(op->kind == OP_DELAY_CB || op->kind == OP_DELAY_UNEXEC) || op->state != 2)
            continue;
        delay_req++;
        int c = g_delay[i].count;
        if (c == 0) {
            delay_never++;
            if (delay_never <= 3) {
                fprintf(stderr,
                        "FAIL [flush] delayed flush callback never ran (%.1f s):\n",
                        (now_ns() - g_delay[i].t_req) / 1e9);
                print_op(stderr, op);
            }
        } else if (c > 1) {
            delay_multi++;
            fprintf(stderr, "FAIL [flush] delayed flush callback ran %d times:\n", c);
            print_op(stderr, op);
        } else if (g_delay[i].t_done - g_delay[i].t_req > delay_max_ns)
            delay_max_ns = g_delay[i].t_done - g_delay[i].t_req;
    }
    fails += (int)(delay_never + delay_multi);

    /* Stale executions. */
    long stale_full = 0, stale_unlink = 0, inflight = 0, stale_total = 0;
    for (int rg = 0; rg < g_nregions; rg++) {
        long ns = g_nstale[rg];
        if (ns > MAXSTALE) {
            fprintf(stderr, "FAIL [flush] region %d: %ld stale observations (log full)\n",
                    rg, ns);
            fails++;
            ns = MAXSTALE;
        }
        for (long i = 0; i < ns; i++) {
            stale_t *s = &g_stale[rg][i];
            stale_total++;
            int t = s->valid < MAXE ? g_etype[rg][s->valid] : ET_NONE;
            int bad = 0;
            const char *why = "";
            if (t == ET_FULL || t == ET_DELAY) {
                bad = 1;
                why = t == ET_FULL ? "after a full flush returned"
                                   : "after a delayed flush's callback";
                stale_full++;
            } else if (t == ET_UNLINK) {
                if (s->n >= g_snap[rg][s->valid] + (g_snap_self[rg][s->valid] ? 1 : 2)) {
                    bad = 1;
                    why = "entered after an unlink flush returned";
                    stale_unlink++;
                } else
                    inflight++;
            } else {
                bad = 1;
                why = "epoch published by no flush (harness bug)";
            }
            if (bad && stale_full + stale_unlink <= 5) {
                fprintf(stderr,
                        "FAIL [flush] region %d: a fragment built at epoch %llu executed "
                        "(%s check at pc 0x%llx, entry %ld) %s (epoch %llu, entries "
                        "then %ld)\n",
                        rg, (unsigned long long)s->built,
                        s->kind == CK_ENTRY ? "entry" : "exit", (unsigned long long)s->pc,
                        s->n, why, (unsigned long long)s->valid,
                        t == ET_UNLINK ? g_snap[rg][s->valid] : -1L);
            }
            fails += bad;
        }
    }

    /* Counts and floors. */
    a64p_counts_t c = { 0 };
    long runs = 0, rebuilt = 0, checks = 0;
    for (int i = 0; i < g_nworkers; i++) {
        worker_t *wk = &g_workers[i];
        if (verbose) {
            fprintf(stderr, "  worker %d: blocks %d runs %ld fails %ld checks %ld\n", i,
                    wk->nblk, wk->runs, wk->fails, g_checks[i]);
        }
        c.generated += NBLK;
        c.accepted += wk->nblk;
        c.executed += wk->runs;
        c.checked += wk->runs - wk->fails;
        runs += wk->runs;
        fails += (int)wk->fails;
        if (wk->runs < 10) {
            fprintf(stderr, "FAIL [flush] worker %d completed only %ld runs\n", i,
                    wk->runs);
            fails++;
        }
    }
    for (int rg = 0; rg < g_nregions; rg++) {
        rebuilt += g_rebuilt_seen[rg];
        checks += g_checks[rg];
    }
    char label[96];
    snprintf(label, sizeof(label), "flush %s", fv->v.name);
    a64p_counts_print(stdout, label, &c);
    printf("flush %s: %d workers, %d operations:", fv->v.name, g_nworkers, nops);
    for (int k = 0; k < OP_NUM; k++) {
        long n = 0;
        for (int is = 0; is < IS_NUM; is++)
            n += g_ops_done[k][is];
        printf(" %s %ld", op_names[k], n);
    }
    printf("\n");
    printf("flush %s: checks %ld, after-flush rebuilds seen %ld, self-flush redirects "
           "%ld, stale (in-flight, allowed) %ld, traces %ld/%ld (trimmed %ld), delayed "
           "callbacks %ld (max %.1f ms)\n",
           fv->v.name, checks, rebuilt, g_self_redirects, inflight, g_traces_region,
           g_traces_all, g_traces_trimmed, delay_req - delay_never, delay_max_ns / 1e6);
    printf("flush %s: sentinel blocks %d, rebuilt %ld, rebuilt mid-loop %ld\n",
           fv->v.name, g_nnat, g_sentinel_natural, g_sentinel_mid);
    fails += a64p_floor(label, "accepted blocks", c.accepted, (long)g_nworkers);
    fails += a64p_floor(label, "runs checked", c.checked, 20L * g_nworkers);
    if (g_under_dr) {
        long by_issuer[IS_NUM] = { 0 };
        for (int k = 0; k < OP_NUM; k++) {
            for (int is = 0; is < IS_NUM; is++)
                by_issuer[is] += g_ops_done[k][is];
        }
        for (int is = 0; is < IS_NUM; is++)
            fails += a64p_floor(label, issuer_names[is], by_issuer[is], 5);
        long kmin = 5;
        fails += a64p_floor(label, "unlink flushes",
                            g_ops_done[OP_UNLINK][0] + g_ops_done[OP_UNLINK][1] +
                                g_ops_done[OP_UNLINK][2],
                            kmin);
        if (fv->synchall_ops) {
            fails += a64p_floor(label, "full flushes",
                                g_ops_done[OP_FULL][0] + g_ops_done[OP_FULL][1] +
                                    g_ops_done[OP_FULL][2],
                                kmin);
            fails += a64p_floor(label, "full_ex flushes",
                                g_ops_done[OP_FULL_EX][0] + g_ops_done[OP_FULL_EX][1] +
                                    g_ops_done[OP_FULL_EX][2],
                                2);
            fails +=
                a64p_floor(label, "delayed callbacks", delay_req - delay_never, kmin);
            fails += a64p_floor(label, "self-flush redirects", g_self_redirects, 1);
        }
        fails += a64p_floor(label, "checks", checks, 1000);
        fails += a64p_floor(label, "after-flush rebuilds seen", rebuilt, 10);
        fails += a64p_floor(label, "sentinel blocks", g_nnat, 1);
        /* Without resets (and without synchall flushes) the sentinel leaves the
         * cache about once per run at most.
         */
        if (fv->want_reset == 1) {
            fails += a64p_floor(label, "sentinel moved out of the cache (resets)",
                                g_sentinel_mid, 10);
        }
        if (fv->want_reset == 2)
            fails += a64p_floor(label, "full resets seen", g_sentinel_natural, 1);
        if (fv->want_reset == 0 && g_sentinel_natural != 0) {
            fprintf(stderr,
                    "FAIL [flush] %s: the sentinel's blocks were rebuilt %ld times "
                    "without a reset\n",
                    fv->v.name, g_sentinel_natural);
            fails++;
        }
    }
    if (fails != 0) {
        fprintf(stderr,
                "A64P-REPLAY v1 prog=a64_prop_flush mode=flush variant=%s seed=%llu "
                "workers=%d secs=%.1f ops=%d; last operations:\n",
                fv->v.name, (unsigned long long)a->seed, g_nworkers, a->secs, nops);
        for (int i = nops > 16 ? nops - 16 : 0; i < nops; i++)
            print_op(stderr, &g_ops[i]);
    }
    if (g_under_dr)
        a64p_stop_dr();
    return fails;
}

int
main(int argc, const char *argv[])
{
    const char *mode = argc > 1 ? argv[1] : "flush";
    uint64_t seed = 1;
    int workers = -1;
    double secs = -1;
    const char *vlist = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc)
            seed = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-secs") == 0 && i + 1 < argc)
            secs = atof(argv[++i]);
        else if (strcmp(argv[i], "-workers") == 0 && i + 1 < argc)
            workers = atoi(argv[++i]);
        else if (strcmp(argv[i], "-variants") == 0 && i + 1 < argc)
            vlist = argv[++i];
        else if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "-ops") == 0 && i + 1 < argc)
            opt_ops = argv[++i];
        else if (strcmp(argv[i], "-issuers") == 0 && i + 1 < argc)
            opt_issuers = argv[++i];
        else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if (strcmp(mode, "flush") != 0) {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
#ifdef A64_DR_PROP_DEBUG_DR
    is_debug_build = 1;
#endif
    a64p_init_features();
    a64p_progress_init("a64_prop_flush");
    g_devnull = fopen("/dev/null", "w");
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (vlist != NULL) {
        for (const char *p = vlist; *p != '\0';) {
            const char *e = strchr(p, ',');
            size_t n = e == NULL ? strlen(p) : (size_t)(e - p);
            int found = 0;
            for (int i = 0; i < NVARIANTS; i++) {
                if (strlen(fl_variants[i].v.name) == n &&
                    strncmp(fl_variants[i].v.name, p, n) == 0)
                    found = 1;
            }
            if (!found) {
                fprintf(stderr, "unknown variant %.*s\n", (int)n, p);
                return 2;
            }
            p = e == NULL ? p + n : e + 1;
        }
    }
    int fails = 0, nrun = 0;
    for (int i = 0; i < NVARIANTS; i++) {
        const fl_variant_t *fv = &fl_variants[i];
        if (vlist != NULL ? !list_has(vlist, fv->v.name)
                          : (fv->opt_in || (fv->v.debug_only && !is_debug_build)))
            continue;
        rng_t r = { seed + (uint64_t)i };
        double s = secs > 0 ? secs : fv->v.dr_ops == NULL ? 2 : 20;
        child_args_t a = { fv, seed + (uint64_t)i,
                           workers > 0 ? workers : 2 + (int)rn(&r, MAXWK - 1), s };
        int f = a64p_in_child_timeout(mode, &fv->v, flush_child, &a, (int)s + 120);
        if (f != 0)
            fprintf(stderr, "FAIL [%s] variant=%s: %d failures\n", mode, fv->v.name, f);
        fails += f;
        nrun++;
    }
    fails += a64p_floor(mode, "variants run", nrun, 1);
    printf("%s: %s\n", mode, fails == 0 ? "all properties hold" : "FAILURES");
    return fails == 0 ? 0 : 1;
}

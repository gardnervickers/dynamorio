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

/* Differential property tests of AArch64 execution under DynamoRIO, using the
 * native CPU as the oracle.  Random but valid code blocks (a64_dr_prop_gen.h)
 * run natively and then under DR (static DR, started with
 * dr_app_setup_and_start() in a forked child per option variant) from the
 * same initial state.  Properties (one mode each):
 *
 *   transparency: final GPRs, SP, NZCV, FPSR, FPCR, V registers, the data
 *     buffer and the written stack must be identical, and every synchronous
 *     fault (guard page, PAC failure, SP alignment, UDF, BRK) must be reported
 *     to the app handler with identical signal number, si_code, si_addr, PC,
 *     registers, PSTATE, FP/SIMD state and ESR; the handler skips the faulting
 *     instruction and the resumed execution must match too.  Variants change
 *     DR's mangling (stolen register, -no_ldstex2cas, tiny blocks, resets) and
 *     how the code is installed (fresh mapping, rewritten in place with cache
 *     maintenance, writable code sandboxed with -sandbox_writable).
 *     Hand-written regression blocks for bugs found here run first.
 *   signals: asynchronous signals (itimer, POSIX timer, another thread's
 *     tgkill) interrupt long-running blocks.  Every interrupted context must be
 *     a real native state: its PC and full register/memory state must equal
 *     the state at that PC in a single-stepped (ptrace) native trace, in
 *     program order.  A context attributed to a run must be in the block, its
 *     entry/exit stubs or the host trampoline (run_code); no run may report a
 *     synchronous fault.  The handler also changes a register and a vector
 *     register the block never touches, and the resumed block must observe it.
 *     Each block and variant (and the native oracle self-check) must yield
 *     -quota in-block contexts per signal source, with up to -max_extra extra
 *     batches of 50 runs; fewer is a coverage failure.  Also checks that
 *     queued real-time signals are all delivered in order.
 *   instr: the same blocks under an in-process client that inserts drreg
 *     reservations of random registers and the flags with clobbering, drx
 *     counters and drutil_insert_get_mem_addr() for each memory operand, logging
 *     the address and pc inline (or with a clean call: A64_DR_PROP_CLEANCALL=1).
 *     The app must stay transparent (including fault contexts) and every
 *     drutil call must succeed; for traced blocks the drx count must equal the
 *     native dynamic instruction count per instruction, and each computed
 *     address and its pc must equal those of the native pre-instruction state.
 *   ssbs: a diagnostic, not a property: counts native signal frames that report
 *     PSTATE.SSBS set, then runs the transparency blocks with SSBS compared
 *     strictly (see the known deviations below).
 *
 * Every mode prints how many cases were generated, accepted (valid oracle),
 * executed, checked, suppressed (a known-deviation mask hid a difference) and
 * inconclusive, and enforces floors on them; "all properties hold" is only
 * printed when every check and every floor passed.
 *
 * Usage: a64_dr_prop <transparency|signals|instr|ssbs|regress> [-seed S] [-n N]
 *        [-variants a,b,...] [-runs R] [-quota Q] [-max_extra E] [-v]
 * -variants takes exact variant names; an unknown name is an error.
 * Each failure prints the seed, the variant, the differing state and the
 * block listing, a replay record (raw words, initial state, DR options, page
 * size, HWCAPs and, for signals, the delivery log) and the command line that
 * reproduces it.  To localize a
 * divergence: a64_dr_prop dbisect -seed S -variants V truncates the block after
 * every dynamic instruction of its native trace and reports the first point
 * where native and DR states differ ("bisect" truncates statically).
 * Environment knobs: A64_DR_PROP_SUMMARY=1 prints per-variant results;
 * A64_DR_PROP_STRICT=1 disables the known-deviation masks below;
 * A64_DR_PROP_GMODE=instr and A64_DR_PROP_INSTR=1 make (d)bisect use the instr
 * generator and client; A64_DR_PROP_IDISABLE=<bits> disables client pieces;
 * A64_DR_PROP_NOEXCL=1 omits exclusives; A64_DR_PROP_SIG_SCALE scales signal
 * periods under DR; A64_DR_PROP_DEBUG_DR=0/1 overrides whether debug-only
 * (internal option) variants run; A64P_REPLAY_DIR=<dir> also saves the data
 * and stack contents of failing blocks there.
 *
 * Known deviations (kdevs[] below), masked unless A64_DR_PROP_STRICT=1, and
 * counted and printed every time a mask hides a difference:
 * + fault-btype/async-btype: in a signal frame at the target of an indirect
 *   branch DR reports BTYPE 0 where the CPU reports the branch's BTYPE (DR
 *   enters the target through its IBL and the fragment prefix, which reset the
 *   hardware BTYPE; api.a64_prop_bti's frame-btype deviation).  Only that
 *   direction is masked: any other BTYPE difference fails.
 * + fault-ssbs/async-ssbs: PSTATE.SSBS in a signal frame is not deterministic,
 *   natively or under DR.  On a CPU without FEAT_SSBS the kernel's spectre-v4
 *   task mitigation rewrites SSBS in the saved user PSTATE on a context
 *   switch, so a frame set up after one reports SSBS=1 (the test VM: 132 of
 *   3M native SIGILL frames with a CPU hog on the same CPU, 7641 of 3M
 *   unpinned, 2026-10-14).  Mode ssbs repeats that native count and compares
 *   SSBS strictly under DR; the first masked divergence is recorded with both
 *   PSTATEs and PR_GET_SPECULATION_CTRL.
 */

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drx.h"

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include "a64_prop_support.h"

/***************************************************************************
 * Configuration and shared state.
 */
static int verbose;

/* Per-variant summaries are printed with -v or A64_DR_PROP_SUMMARY=1. */
static int
print_summary(void)
{
    return getenv("A64_DR_PROP_SUMMARY") != NULL;
}
static int is_debug_build;
static int dczva_ok;

#define PSTATE_BTYPE 0xc00ULL
/* PSTATE.SSBS (bit 12): the kernel can set it in a saved PSTATE on a context
 * switch (see the known deviations above).
 */
#define PSTATE_SSBS 0x1000ULL

/* The (only) worker: execution state shared with the signal handlers. */
static a64p_worker_t g_w;
/* Asynchronous signal sources (signals mode). */
static a64p_sigsrc_t g_src;

/* In-process client state (instr mode). */
static int g_instr_on;
/* Debug aid (A64_DR_PROP_IDISABLE bits): 1 drx counter, 2 register/flag clobbers,
 * 4 memory address instrumentation, 8 the clean call only.
 */
static int g_instr_disable;
static volatile int g_drutil_fail;
static uint64_t g_instr_seed;
static volatile uint64_t g_dyn_count;
/* Per-instruction execution counts (instr mode), to localize count mismatches. */
static uint64_t *g_pc_count;
typedef struct {
    uint64_t cnt, pc, addr;
} mlog_t;
#define MAXML 65536
static mlog_t *g_mlog;
static volatile int g_nml;
/* Inline logging (the default): the address each memory operand accesses,
 * indexed by the dynamic instruction count.  A64_DR_PROP_CLEANCALL=1 logs with
 * a clean call instead.
 */
#define ADDR_LOG_MASK 0xffff
static uint64_t *g_addr_by_cnt;
/* The pc of the instruction that logged each address (also inline). */
static uint64_t *g_pc_by_cnt;
static int g_use_cleancall;

/***************************************************************************
 * Generation options per mode.
 */
static int opt_allow_ctr = 1;

static void
opts_for(const char *mode, uint64_t seed, gen_opts_t *o)
{
    memset(o, 0, sizeof(*o));
    o->allow_svc = 1;
    o->allow_fpcr = 1;
    o->allow_ctr = opt_allow_ctr;
    if (strcmp(mode, "signals") == 0) {
        o->traced = 1;
        o->reserve = 1;
        o->outer_loop = 1;
        o->len = 40;
        o->dyn_max = 20000;
    } else if (strcmp(mode, "instr") == 0) {
        o->traced = (seed % 2) == 0;
        o->allow_excl = !o->traced;
        o->allow_faults = 1;
        o->len = 50;
        o->dyn_max = 2500;
    } else {
        o->allow_excl = getenv("A64_DR_PROP_NOEXCL") == NULL;
        o->allow_faults = 1;
        o->allow_brk = 1;
        o->len = 60;
        o->dyn_max = 3000;
    }
}

static int
make_block(block_t *b, const char *mode, uint64_t seed, int i)
{
    gen_opts_t o;
    (void)i;
    opts_for(mode, seed, &o);
    return a64p_make_block(b, &o, seed);
}

/***************************************************************************
 * Counts and known deviations.
 */
/* Counters a child reports to the parent through the progress page. */
enum {
    ST_BLOCKS_CHECKED, /* blocks all of whose runs were compared */
    ST_RUNS,           /* runs executed under DR */
    ST_RUNS_CHECKED,   /* ...and compared against the oracle */
    /* Known deviations: a difference hidden by a mask. */
    ST_KD_FAULT_BTYPE,
    ST_KD_FAULT_SSBS,
    ST_KD_ASYNC_BTYPE,
    ST_KD_ASYNC_SSBS,
    /* The first SSBS divergence, for the record. */
    ST_SSBS_NATIVE_PSTATE,
    ST_SSBS_DR_PSTATE,
    ST_SSBS_DR_PRCTL,
    /* Signals mode. */
    ST_SIG_RECORDS, /* interrupted contexts attributed to a run */
    ST_SIG_STUB,    /* ...whose pc was in the entry/exit stub or the trampoline */
    ST_SIG_HITS0,   /* in-block contexts checked, per source (3) */
    ST_SIG_EXTRA = ST_SIG_HITS0 + 3, /* extra batches run to meet the quota */
    ST_SIG_RUNS_NF0,                 /* runs checked to have no synchronous fault */
    /* Instr mode. */
    ST_INSTR_TRACED,   /* blocks checked against a native trace */
    ST_INSTR_UNTRACED, /* blocks checked without one */
    ST_INSTR_ADDRS,    /* computed addresses compared */
    /* A masked BTYPE difference other than DR reporting 0 for a native nonzero. */
    ST_BTYPE_UNEXPECTED,
    ST_NUM
};
_Static_assert(ST_NUM <= A64P_NSTAT, "progress_t.stat is too small");

/* Known deviations: compared with a mask by default, counted every time the
 * mask hides a difference, and never counted as validated.
 * A64_DR_PROP_STRICT=1 removes every mask; mode "ssbs" removes the SSBS ones.
 * (fault-ssbs/async-ssbs are kernel nondeterminism rather than DR deviations,
 * but are counted the same way.)
 */
typedef struct {
    const char *name;
    int stat;
    const char *why;
} kdev_t;
static const kdev_t kdevs[] = {
    { "fault-btype", ST_KD_FAULT_BTYPE,
      "DR reports BTYPE 0 in a frame at an indirect branch target where the CPU "
      "reports the branch's BTYPE (2026-10-14; api.a64_prop_bti frame-btype)" },
    { "fault-ssbs", ST_KD_FAULT_SSBS,
      "the kernel sets PSTATE.SSBS in a saved PSTATE on some context switches, so "
      "frames differ in SSBS natively too (2026-10-14; see mode ssbs)" },
    { "async-btype", ST_KD_ASYNC_BTYPE,
      "as fault-btype, for interrupted contexts (api.a64_prop_bti async-btype)" },
    { "async-ssbs", ST_KD_ASYNC_SSBS, "as fault-ssbs, for interrupted contexts" },
};
#define NUM_KDEVS (sizeof(kdevs) / sizeof(kdevs[0]))

#define PSTATE_NZCV 0xf0000000ULL
#define PSTATE_DIT 0x01000000ULL
/* PSTATE bits compared in interrupted contexts (the rest, e.g. SS while
 * single-stepping, are not the app's).
 */
#define ASYNC_PSTATE_CMP (PSTATE_NZCV | PSTATE_DIT | PSTATE_SSBS | PSTATE_BTYPE)
/* PSTATE bits masked as known deviations. */
static uint64_t async_pstate_masked = PSTATE_SSBS | PSTATE_BTYPE;

static int g_prctl_ssb_native;
/* Totals over all children of the current mode. */
static long g_stat[A64P_NSTAT];

static int
prctl_ssb(void)
{
    return prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);
}

static void
stat_add(int i, long v)
{
    a64p_prog->stat[i] += v;
}

static void
note_ssbs(uint64_t native, uint64_t dr)
{
    if (a64p_prog->stat[ST_KD_FAULT_SSBS] + a64p_prog->stat[ST_KD_ASYNC_SSBS] == 0) {
        a64p_prog->stat[ST_SSBS_NATIVE_PSTATE] = (long)native;
        a64p_prog->stat[ST_SSBS_DR_PSTATE] = (long)dr;
        a64p_prog->stat[ST_SSBS_DR_PRCTL] = prctl_ssb();
    }
}

static volatile long ssbs_frames;

static void
ssbs_count_handler(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    if (uc->uc_mcontext.pstate & PSTATE_SSBS)
        ssbs_frames++;
    uc->uc_mcontext.pc += 4;
}

/* How many of n native UDF frames report PSTATE.SSBS set. */
static long
native_ssbs_frames(long n)
{
    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = ssbs_count_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGILL, &sa, &old);
    ssbs_frames = 0;
    for (long i = 0; i < n; i++)
        __asm__ volatile(".inst 0x00000000" ::: "memory"); /* udf #0 */
    sigaction(SIGILL, &old, NULL);
    return ssbs_frames;
}

static void
on_masked_fault_pstate(int i, fault_rec_t *n, fault_rec_t *d)
{
    uint64_t diff = n->pstate ^ d->pstate;
    if (diff & PSTATE_BTYPE) {
        if ((d->pstate & PSTATE_BTYPE) != 0)
            stat_add(ST_BTYPE_UNEXPECTED, 1);
        else
            stat_add(ST_KD_FAULT_BTYPE, 1);
    }
    if (diff & PSTATE_SSBS) {
        note_ssbs(n->pstate, d->pstate);
        stat_add(ST_KD_FAULT_SSBS, 1);
    }
}

/* Counts masked bits that differ between an interrupted context and its
 * native state.
 */
static void
count_masked_async(uint64_t native, uint64_t dr)
{
    uint64_t diff = (native ^ dr) & async_pstate_masked;
    if (diff & PSTATE_BTYPE) {
        if ((dr & PSTATE_BTYPE) != 0)
            stat_add(ST_BTYPE_UNEXPECTED, 1);
        else
            stat_add(ST_KD_ASYNC_BTYPE, 1);
    }
    if (diff & PSTATE_SSBS) {
        note_ssbs(native, dr);
        stat_add(ST_KD_ASYNC_SSBS, 1);
    }
}

/* Adds the finished child's counters to the totals. */
static void
collect_stats(void)
{
    for (int i = 0; i < ST_NUM; i++) {
        if (i == ST_SSBS_NATIVE_PSTATE || i == ST_SSBS_DR_PSTATE ||
            i == ST_SSBS_DR_PRCTL) {
            if (g_stat[ST_KD_FAULT_SSBS] + g_stat[ST_KD_ASYNC_SSBS] == 0)
                g_stat[i] = a64p_prog->stat[i];
        } else
            g_stat[i] += a64p_prog->stat[i];
    }
}

static long
masked_total(void)
{
    long n = 0;
    for (size_t k = 0; k < NUM_KDEVS; k++)
        n += g_stat[kdevs[k].stat];
    return n;
}

/* Prints the known-deviation counts; returns the number of masked
 * differences that are not the known deviation (a failure).
 */
static int
print_kdevs(const char *label)
{
    printf("%s: known deviations masked:", label);
    for (size_t k = 0; k < NUM_KDEVS; k++)
        printf("%s %s %ld", k == 0 ? "" : ",", kdevs[k].name, g_stat[kdevs[k].stat]);
    printf("\n");
    if (g_stat[ST_KD_FAULT_SSBS] + g_stat[ST_KD_ASYNC_SSBS] > 0) {
        printf("%s: SSBS record: first divergence native pstate 0x%lx, dr pstate 0x%lx; "
               "PR_GET_SPECULATION_CTRL(SSB) native %d, dr %ld\n",
               label, g_stat[ST_SSBS_NATIVE_PSTATE], g_stat[ST_SSBS_DR_PSTATE],
               g_prctl_ssb_native, g_stat[ST_SSBS_DR_PRCTL]);
    }
    if (verbose) {
        for (size_t k = 0; k < NUM_KDEVS; k++)
            printf("  %s: %s\n", kdevs[k].name, kdevs[k].why);
    }
    if (g_stat[ST_BTYPE_UNEXPECTED] > 0) {
        fprintf(stderr,
                "FAIL [%s]: %ld masked BTYPE differences where DR reports a nonzero "
                "BTYPE (only DR reporting 0 is a known deviation)\n",
                label, g_stat[ST_BTYPE_UNEXPECTED]);
        return 1;
    }
    return 0;
}

static int
variant_ok(const variant_t *v)
{
    return is_debug_build || !v->debug_only;
}

static const variant_t *
variant_named(const char *name)
{
    for (int i = 0; i < a64p_num_variants; i++) {
        if (strcmp(a64p_variants[i].name, name) == 0)
            return &a64p_variants[i];
    }
    abort();
}

/***************************************************************************
 * Property 1+3: transparency (including synchronous faults).
 */
typedef struct {
    const char *mode;
    const variant_t *v;
    uint64_t seed0;
    int n;
    result_t *native;
    uint8_t *valid;
} p1_args_t;

static int
p1_child(void *argp)
{
    p1_args_t *a = (p1_args_t *)argp;
    block_t *b = malloc(sizeof(*b));
    result_t *r = malloc(sizeof(*r));
    int fails = 0;
    a64p_install_handlers(&g_w, a->v->altstack);
    a64p_on_masked_pstate = on_masked_fault_pstate;
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "dr start");
    a64p_start_dr(a->v->dr_ops);
    for (int i = 0; i < a->n; i++) {
        if (!a->valid[i])
            continue;
        uint64_t seed = a->seed0 + i;
        a64p_prog->block = i;
        a64p_prog->seed = seed;
        snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "generate+install");
        if (!make_block(b, a->mode, seed, i)) {
            fprintf(stderr, "FAIL [%s] variant=%s seed=%llu: block no longer generates\n",
                    a->mode, a->v->name, (unsigned long long)seed);
            fails++;
            continue;
        }
        a64p_install_code(&g_w, b, a->v->install);
        int ok = 1;
        for (int rep = 0; rep < 2; rep++) {
            a64p_prog->run = rep;
            snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "run");
            a64p_run_block(&g_w, b, r);
            stat_add(ST_RUNS, 1);
            snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "compare");
            char *txt = NULL;
            size_t len = 0;
            FILE *o = open_memstream(&txt, &len);
            int bad = a64p_cmp_results(o, b, &a->native[i], r);
            fclose(o);
            stat_add(ST_RUNS_CHECKED, 1);
            if (bad > 0) {
                fails++;
                ok = 0;
                fprintf(stderr,
                        "FAIL [%s] variant=%s seed=%llu run=%d: %d differences\n%s",
                        a->mode, a->v->name, (unsigned long long)seed, rep, bad, txt);
                a64p_print_faults(stderr, "native", &a->native[i]);
                a64p_print_faults(stderr, "dr", r);
                print_block(stderr, b);
                a64p_print_replay(stderr, "a64_dr_prop", a->mode, a->v, b);
                fprintf(stderr,
                        "  repro: a64_dr_prop %s -seed %llu -n 1 -variants %s -v\n",
                        a->mode, (unsigned long long)seed, a->v->name);
                rep = 2;
            }
            free(txt);
            if (fails > 5)
                break;
        }
        if (ok)
            stat_add(ST_BLOCKS_CHECKED, 1);
        if (fails > 5) {
            fprintf(stderr, "  (stopping this variant after %d failures)\n", fails);
            break;
        }
    }
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "dr stop");
    a64p_stop_dr();
    return fails;
}

static int
mode_transparency(const char *mode, const char *label, uint64_t seed0, int n,
                  const char *vlist, int *nvariants)
{
    result_t *native = calloc(n, sizeof(result_t));
    result_t *again = malloc(sizeof(result_t));
    uint8_t *valid = calloc(n, 1);
    block_t *b = malloc(sizeof(*b));
    int gen_bugs = 0, gen_fail = 0, nondet = 0, faults = 0, ncas = 0, ncas_primed = 0;
    a64p_install_handlers(&g_w, 0);
    for (int i = 0; i < n; i++) {
        uint64_t seed = seed0 + i;
        if (!make_block(b, mode, seed, i)) {
            gen_fail++;
            continue;
        }
        ncas += b->ncas;
        ncas_primed += b->ncas_primed;
        a64p_install_code(&g_w, b, 0);
        a64p_run_block(&g_w, b, &native[i]);
        a64p_run_block(&g_w, b, again);
        if (!a64p_check_planned(b, &native[i])) {
            fprintf(stderr, "GENERATOR BUG: unplanned native fault, seed %llu\n",
                    (unsigned long long)seed);
            a64p_print_faults(stderr, "native", &native[i]);
            print_block(stderr, b);
            gen_bugs++;
            continue;
        }
        if (a64p_cmp_results(stderr, b, &native[i], again) != 0) {
            fprintf(stderr, "NOTE: native run not deterministic, seed %llu: skipped\n",
                    (unsigned long long)seed);
            a64p_print_faults(stderr, "run1", &native[i]);
            a64p_print_faults(stderr, "run2", again);
            nondet++;
            continue;
        }
        faults += native[i].nf;
        valid[i] = 1;
        if (verbose) {
            print_block(stdout, b);
            a64p_print_faults(stdout, "native", &native[i]);
        }
    }
    int nvalid = 0;
    for (int i = 0; i < n; i++)
        nvalid += valid[i];
    if (verbose || print_summary()) {
        printf("%s: %d/%d blocks valid natively (%d native faults; %d CAS, %d primed to "
               "succeed), %d generator bugs\n",
               label, nvalid, n, faults, ncas, ncas_primed, gen_bugs);
    }
    int total = gen_bugs;
    memset(g_stat, 0, sizeof(g_stat));
    int nrun = 0;
    for (int vi = 0; vi < a64p_num_variants; vi++) {
        const variant_t *v = &a64p_variants[vi];
        if (!a64p_variant_selected(vlist, v))
            continue;
        if (!variant_ok(v))
            continue;
        if (v->no_ctr && opt_allow_ctr)
            continue; /* run separately with CTR reads disabled */
        p1_args_t a = { mode, v, seed0, n, native, valid };
        int f = a64p_in_child(mode, v, p1_child, &a);
        long checked = a64p_prog->stat[ST_BLOCKS_CHECKED];
        collect_stats();
        nrun++;
        if (verbose || print_summary())
            printf("%s variant %-12s: %s (%d failing blocks, %ld checked)\n", label,
                   v->name, f ? "FAIL" : "ok", f, checked);
        total += f;
        /* Every valid block must have been checked under every variant. */
        if (f == 0)
            total += a64p_floor(label, v->name, checked, nvalid);
    }
    a64p_counts_t c = { n,
                        nvalid,
                        g_stat[ST_RUNS],
                        g_stat[ST_RUNS_CHECKED],
                        masked_total(),
                        gen_fail + nondet + gen_bugs };
    a64p_counts_print(stdout, label, &c);
    total += print_kdevs(label);
    /* Floors: at least half the seeds give a valid oracle. */
    total += a64p_floor(label, "natively valid blocks", nvalid, (n + 1) / 2);
    *nvariants += nrun;
    free(native);
    free(again);
    free(valid);
    free(b);
    return total;
}

/***************************************************************************
 * Regression blocks: hand-written sequences for bugs the properties found.
 * Every register starts as a distinct pointer into D (x_i = D + 0x40 * i), so
 * any register can serve as a base.
 */
static void
r_mov(asm_t *a, int r, uint64_t v)
{
    for (int hw = 0; hw < 4; hw++) {
        uint32_t c = (v >> (16 * hw)) & 0xffff;
        emit(a, e_movw(1, hw == 0 ? 2 : 3, hw, c, r), "mov%c x%d, #0x%x, lsl #%d",
             hw == 0 ? 'z' : 'k', r, c, 16 * hw);
    }
}

/* ldxp/stxp retry loop: sf selects X or W pairs; the stored first value is
 * src (with junk above bit 31 for W), the second is the loaded second value.
 */
static void
r_xpair_loop(asm_t *a, int sf, int base, int rt, int rt2, int src, int st, int acqrel)
{
    int retry = lab_new(a);
    lab_bind(a, retry);
    emit(a, e_excl(sf ? 3 : 2, 0, 1, 1, 31, acqrel, rt2, base, rt),
         "ld%sxp %s, %s, [x%d]", acqrel ? "a" : "", GR(sf, rt), GR(sf, rt2), base);
    emit(a, U(1) << 31 | U(2) << 29 | 0x0Au << 24 | 30u << 16 | U(rt) << 5 | U(src),
         "eor x%d, x%d, x30", src, rt);
    emit(a, e_excl(sf ? 3 : 2, 0, 0, 1, st, acqrel, rt2, base, src),
         "st%sxp w%d, %s, %s, [x%d]", acqrel ? "l" : "", st, GR(sf, src), GR(sf, rt2),
         base);
    int at = emit(a, 0x35000000u | U(st), "cbnz w%d, retry", st);
    fixup(a, at, retry, FX_B19);
}

static void
reg_ldxp_stolen_w(asm_t *a)
{
    /* -ldstex2cas turned ldxp [x28] into an ldp whose memory operand had lost its
     * pre-index flag when x28 was swapped out, which failed to encode.
     */
    r_mov(a, 30, 0x5a5a5a5a00000000ULL);
    r_xpair_loop(a, 0, 28, 5, 20, 19, 2, 0);
}

static void
reg_ldxp_stolen_x(asm_t *a)
{
    r_mov(a, 30, 0x1111);
    r_xpair_loop(a, 1, 28, 5, 20, 19, 2, 1);
}

static void
reg_stxp_w_upper(asm_t *a)
{
    /* A 2x4-byte stxp was converted to an 8-byte stxr of src0 | src1 << 32 using
     * the full 64-bit src0, OR-ing its upper half into the second word.
     */
    r_mov(a, 30, 0xf0f0f0f012345678ULL);
    r_xpair_loop(a, 0, 7, 19, 9, 11, 4, 1);
    r_mov(a, 30, 0xffffffff00000000ULL);
    r_xpair_loop(a, 0, 3, 1, 2, 0, 4, 0);
}

static void
reg_sandbox_pcrel_xl8(asm_t *a)
{
    /* Translating a fault in a selfmod-sandboxed fragment re-decoded the
     * fragment's copy of the app code at the copy's address, so a literal load's
     * mangling (a mov of the literal address) changed length and the faulting
     * load was reported one instruction late.  Needs -sandbox_writable with
     * writable code (the "sandbox" variant).
     */
    int over = lab_new(a), lit = lab_new(a);
    int at = emit(a, 0x14000000u, "b over");
    fixup(a, at, over, FX_B26);
    if (a->n % 2 != 0)
        emit(a, 0xd503201fu, "nop");
    lab_bind(a, lit);
    at = emit(a, 0x89abcdefu, ".word");
    a->isdata[at] = 1;
    at = emit(a, 0x01234567u, ".word");
    a->isdata[at] = 1;
    lab_bind(a, over);
    for (int i = 0; i < 3; i++) {
        at = emit(a, 0x58000000u | U(i + 1), "ldr x%d, lit", i + 1);
        fixup(a, at, lit, FX_B19);
        at = emit(a, 0x10000000u | U(10 + i), "adr x%d, lit", 10 + i);
        fixup(a, at, lit, FX_ADR);
    }
    /* An ADRP far from the copy: its absolute value takes a different number of
     * MOVZ/MOVK instructions than the copy-relative value.
     */
    for (int i = 0; i < 3; i++) {
        uint64_t pc = pc_of(a->n), tgt = D_ADDR + 0x1000ULL * i;
        int64_t pages = (int64_t)((tgt & ~0xfffULL) - (pc & ~0xfffULL)) >> 12;
        uint32_t imm = U(pages) & 0x1fffff;
        emit(a, 0x90000000u | (imm & 3) << 29 | ((imm >> 2) & 0x7ffff) << 5 | U(7 + i),
             "adrp x%d, D+0x%x", 7 + i, 0x1000 * i);
    }
    r_mov(a, 4, GUARD_ADDR + 0x10);
    emit(a, e_ldst_uimm(3, 0, 1, 0, 4, 5), "ldr x5, [x4] (faults)");
    emit(a, e_ldst_uimm(3, 0, 1, 1, 4, 6), "ldr x6, [x4, #8] (faults)");
}

static void
reg_ldxr_misaligned(asm_t *a)
{
    /* -ldstex2cas turned exclusive loads into plain loads, which do not raise the
     * alignment fault an exclusive load does for a misaligned address.
     */
    static const int sz[] = { 1, 2, 3 };
    for (int i = 0; i < 3; i++) {
        r_mov(a, 22, D_ADDR + 0x8cf + i);
        emit(a, e_excl(sz[i], 0, 1, 0, 31, i == 1, 31, 22, 16),
             "ld%sxr w/x16, [x22] (faults)", i == 1 ? "a" : "");
        emit(a, 0xd503305fu, "clrex");
    }
    r_mov(a, 22, D_ADDR + 0x8c8);
    emit(a, e_excl(3, 0, 1, 1, 31, 0, 17, 22, 16), "ldxp x16, x17, [x22] (faults)");
    emit(a, 0xd503305fu, "clrex");
}

typedef struct {
    const char *name;
    void (*build)(asm_t *a);
} regress_t;

static const regress_t regressions[] = {
    { "ldxp_stolen_w", reg_ldxp_stolen_w },
    { "ldxp_stolen_x", reg_ldxp_stolen_x },
    { "stxp_w_upper", reg_stxp_w_upper },
    { "sandbox_pcrel_xl8", reg_sandbox_pcrel_xl8 },
    { "ldxr_misaligned", reg_ldxr_misaligned },
    { NULL, NULL },
};
#define NUM_REGRESS (sizeof(regressions) / sizeof(regressions[0]) - 1)

static void
make_regress_block(block_t *b, int idx)
{
    gen_opts_t o;
    memset(&o, 0, sizeof(o));
    /* Reuse the generator for the initial state (V regs, FPCR, memory). */
    gen_block(b, 0x5eed0000ULL + idx, &o);
    asm_t *a = &b->a;
    memset(a, 0, sizeof(*a));
    b->seed = (uint64_t)idx;
    for (int i = 0; i < 31; i++)
        b->in.x[i] = D_ADDR + 0x40ULL * i;
    emit_entry(a);
    b->block_start = a->n;
    regressions[idx].build(a);
    int exit_lab = lab_new(a);
    lab_bind(a, exit_lab);
    b->exit_start = a->n;
    emit_exit(a);
    resolve(a);
    b->nfaults_planned = 0;
    b->has_excl = 1;
    b->wild_branch = 0;
    b->xres = b->vres = -1;
    memset(b->sinit_final, 0, sizeof(b->sinit_final));
    for (uint64_t x = b->in.sp; x < STK_TOP; x++)
        b->sinit_final[x - STK_CMP_LO] = 1;
}

typedef struct {
    const variant_t *v;
    result_t *native;
} regress_args_t;

static int
regress_child(void *argp)
{
    regress_args_t *a = (regress_args_t *)argp;
    block_t *b = malloc(sizeof(*b));
    result_t *r = malloc(sizeof(*r));
    int fails = 0;
    a64p_install_handlers(&g_w, a->v->altstack);
    a64p_on_masked_pstate = on_masked_fault_pstate;
    a64p_start_dr(a->v->dr_ops);
    for (size_t i = 0; i < NUM_REGRESS; i++) {
        a64p_prog->block = (int)i;
        snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "regress %s",
                 regressions[i].name);
        make_regress_block(b, (int)i);
        a64p_install_code(&g_w, b, a->v->install);
        a64p_run_block(&g_w, b, r);
        stat_add(ST_RUNS, 1);
        char *txt = NULL;
        size_t len = 0;
        FILE *o = open_memstream(&txt, &len);
        int bad = a64p_cmp_results(o, b, &a->native[i], r);
        fclose(o);
        stat_add(ST_RUNS_CHECKED, 1);
        if (bad) {
            fails++;
            fprintf(stderr, "FAIL [regress %s] variant=%s:\n%s", regressions[i].name,
                    a->v->name, txt);
            print_block(stderr, b);
        } else
            stat_add(ST_BLOCKS_CHECKED, 1);
        free(txt);
    }
    a64p_stop_dr();
    return fails;
}

static int
mode_regress(const char *vlist, int *nvariants)
{
    block_t *b = malloc(sizeof(*b));
    result_t *native = calloc(NUM_REGRESS, sizeof(result_t));
    a64p_install_handlers(&g_w, 0);
    for (size_t i = 0; i < NUM_REGRESS; i++) {
        make_regress_block(b, (int)i);
        a64p_install_code(&g_w, b, 0);
        a64p_run_block(&g_w, b, &native[i]);
        if (verbose)
            print_block(stdout, b);
    }
    int total = 0, nrun = 0;
    memset(g_stat, 0, sizeof(g_stat));
    for (int vi = 0; vi < a64p_num_variants; vi++) {
        const variant_t *v = &a64p_variants[vi];
        if (!a64p_variant_selected(vlist, v))
            continue;
        if (!variant_ok(v) || (v->no_ctr && opt_allow_ctr))
            continue;
        regress_args_t a = { v, native };
        int f = a64p_in_child("regress", v, regress_child, &a);
        collect_stats();
        nrun++;
        if (verbose || print_summary())
            printf("regress variant %-12s: %s\n", v->name, f ? "FAIL" : "ok");
        total += f;
    }
    a64p_counts_t c = { NUM_REGRESS,     NUM_REGRESS,
                        g_stat[ST_RUNS], g_stat[ST_RUNS_CHECKED],
                        masked_total(),  0 };
    a64p_counts_print(stdout, "regress", &c);
    if (total == 0) {
        total += a64p_floor("regress", "blocks checked", g_stat[ST_BLOCKS_CHECKED],
                            (long)NUM_REGRESS * nrun);
    }
    *nvariants += nrun;
    free(native);
    free(b);
    return total;
}

/***************************************************************************
 * Bisection helper: truncate the block at every instruction (replacing it
 * with a branch to the exit stub) and report the first truncation point where
 * native and DR results differ.  The culprit is the dynamic predecessor.
 */
static void
truncate_block(block_t *dst, block_t *src, int k)
{
    memcpy(dst, src, sizeof(*dst));
    dst->a.w[k] = 0x14000000u | (U(src->exit_start - k) & 0x3ffffff);
}

typedef struct {
    const variant_t *v;
    block_t *b;
    result_t *native; /* indexed by instruction */
} bisect_args_t;

static void
maybe_enable_instr(uint64_t seed)
{
    if (getenv("A64_DR_PROP_INSTR") != NULL) {
        g_instr_on = 1;
        g_instr_seed = seed * 31 + 7;
        g_mlog = malloc(sizeof(mlog_t) * MAXML);
        g_addr_by_cnt = calloc(ADDR_LOG_MASK + 1, sizeof(uint64_t));
        g_use_cleancall = getenv("A64_DR_PROP_CLEANCALL") != NULL;
    }
}

static int
bisect_child(void *argp)
{
    bisect_args_t *a = (bisect_args_t *)argp;
    block_t *t = malloc(sizeof(*t));
    result_t *r = malloc(sizeof(*r));
    a64p_install_handlers(&g_w, a->v->altstack);
    maybe_enable_instr(a->b->seed);
    a64p_start_dr(a->v->dr_ops);
    int found = 0;
    for (int k = a->b->block_start + 1; k < a->b->exit_start && !found; k++) {
        if (a->b->a.isdata[k])
            continue;
        truncate_block(t, a->b, k);
        /* Only compare stack bytes at or above the SP at the truncation point. */
        for (uint64_t i = 0; i < STK_CMP; i++) {
            if (STK_CMP_LO + i < a->native[k].out.sp)
                t->sinit_final[i] = 0;
        }
        a64p_install_code(&g_w, t, 0);
        a64p_run_block(&g_w, t, r);
        char *txt = NULL;
        size_t len = 0;
        FILE *o = open_memstream(&txt, &len);
        int bad = a64p_cmp_results(o, t, &a->native[k], r);
        fclose(o);
        if (bad) {
            fprintf(stderr, "first divergence when exiting at %llx (instruction %d):\n%s",
                    (unsigned long long)pc_of(k), k, txt);
            for (int i = k - 12 < a->b->block_start ? a->b->block_start : k - 12; i <= k;
                 i++)
                fprintf(stderr, "    %llx: %08x  %s\n", (unsigned long long)pc_of(i),
                        a->b->a.w[i], a->b->a.txt[i]);
            found = 1;
        }
        free(txt);
    }
    if (!found)
        fprintf(stderr, "no divergence found by truncation\n");
    a64p_stop_dr();
    return found;
}

static int
mode_bisect(const char *gmode, uint64_t seed, const char *vlist)
{
    block_t *b = malloc(sizeof(*b)), *t = malloc(sizeof(*t));
    a64p_install_handlers(&g_w, 0);
    if (!make_block(b, gmode, seed, 0))
        return 1;
    result_t *native = calloc(b->exit_start + 1, sizeof(result_t));
    for (int k = b->block_start + 1; k < b->exit_start; k++) {
        if (b->a.isdata[k])
            continue;
        truncate_block(t, b, k);
        a64p_install_code(&g_w, t, 0);
        a64p_run_block(&g_w, t, &native[k]);
    }
    print_block(stderr, b);
    for (int vi = 0; vi < a64p_num_variants; vi++) {
        const variant_t *v = &a64p_variants[vi];
        if (!a64p_variant_selected(vlist, v))
            continue;
        bisect_args_t a = { v, b, native };
        fprintf(stderr, "== variant %s\n", v->name);
        a64p_in_child("bisect", v, bisect_child, &a);
    }
    return 0;
}

/* Dynamic truncation: exit when instruction k is reached for the n-th time.
 * Instruction k is replaced by a branch to a stub after the exit stub that
 * counts arrivals (in harness memory) and either exits or executes the
 * original instruction and branches back.  k must not be PC-relative.
 */
#define DYN_COUNTER (HARN_ADDR + 0x700)

static int
pc_relative(uint32_t w)
{
    return (w & 0x7c000000u) == 0x14000000u || /* b, bl */
        (w & 0xff000010u) == 0x54000000u ||    /* b.cond */
        (w & 0x7e000000u) == 0x34000000u ||    /* cbz/cbnz */
        (w & 0x7e000000u) == 0x36000000u ||    /* tbz/tbnz */
        (w & 0x1f000000u) == 0x10000000u ||    /* adr/adrp */
        (w & 0x3b000000u) == 0x18000000u ||    /* ldr literal */
        (w & 0xfe000000u) == 0xd6000000u ||    /* br/blr/ret and PAuth forms */
        (w & 0xfffff01fu) == 0xd503201fu ||    /* hints (paciasp etc. use SP/x30) */
        w == 0xd10023ffu;                      /* sub sp, sp, #8 (misalign) */
}

static void
dyn_truncate(block_t *dst, block_t *src, int k)
{
    memcpy(dst, src, sizeof(*dst));
    asm_t *a = &dst->a;
    int stub = a->n;
    uint32_t orig = a->w[k];
    a->w[k] = 0x14000000u | (U(stub - k) & 0x3ffffff);
#define W(x) (a->w[a->n++] = (x))
    W(e_ldst_pair(2, 0, 3, 0, -4, 1, 31, 0)); /* stp x0, x1, [sp, #-32]! */
    W(e_mrs(SR_NZCV, 1));
    W(e_ldst_uimm(3, 0, 0, 2, 31, 1)); /* str x1, [sp, #16] */
    for (int hw = 0; hw < 4; hw++) {
        uint32_t c = (DYN_COUNTER >> (16 * hw)) & 0xffff;
        W(e_movw(1, hw == 0 ? 2 : 3, hw, c, 0));
    }
    W(e_ldst_uimm(3, 0, 1, 0, 0, 1));     /* ldr x1, [x0] */
    W(e_addsub_imm(1, 1, 0, 0, 1, 1, 1)); /* sub x1, x1, #1 */
    W(e_ldst_uimm(3, 0, 0, 0, 0, 1));     /* str x1, [x0] */
    int cbz = a->n;
    W(0xb4000000u | 1u);               /* cbz x1, do_exit */
    W(e_ldst_uimm(3, 0, 1, 2, 31, 1)); /* ldr x1, [sp, #16] */
    W(e_msr(SR_NZCV, 1));
    W(e_ldst_pair(2, 0, 1, 1, 4, 1, 31, 0)); /* ldp x0, x1, [sp], #32 */
    W(orig);
    W(0x14000000u | (U(k + 1 - a->n) & 0x3ffffff));
    a->w[cbz] |= (U(a->n - cbz) & 0x7ffff) << 5;
    W(e_ldst_uimm(3, 0, 1, 2, 31, 1));
    W(e_msr(SR_NZCV, 1));
    W(e_ldst_pair(2, 0, 1, 1, 4, 1, 31, 0));
    W(0x14000000u | (U(src->exit_start - a->n) & 0x3ffffff));
#undef W
}

typedef struct {
    const variant_t *v;
    block_t *b;
    trace_t *t;
    int *ks; /* static instruction for dynamic step i, or -1 */
    int *nth;
    result_t *native;
} dbisect_args_t;

static int
dbisect_child(void *argp)
{
    dbisect_args_t *a = (dbisect_args_t *)argp;
    block_t *t = malloc(sizeof(*t));
    result_t *r = malloc(sizeof(*r));
    a64p_install_handlers(&g_w, a->v->altstack);
    maybe_enable_instr(a->b->seed);
    a64p_start_dr(a->v->dr_ops);
    int found = 0, last_ok = -1;
    for (int i = 0; i < a->t->n && !found; i++) {
        if (a->ks[i] < 0)
            continue;
        dyn_truncate(t, a->b, a->ks[i]);
        for (uint64_t j = 0; j < STK_CMP; j++) {
            if (STK_CMP_LO + j < a->native[i].out.sp)
                t->sinit_final[j] = 0;
        }
        a64p_install_code(&g_w, t, a->v->install);
        *(uint64_t *)DYN_COUNTER = (uint64_t)a->nth[i];
        a64p_run_block(&g_w, t, r);
        char *txt = NULL;
        size_t len = 0;
        FILE *o = open_memstream(&txt, &len);
        int bad = a64p_cmp_results(o, t, &a->native[i], r);
        fclose(o);
        if (bad) {
            fprintf(
                stderr,
                "first divergence at dynamic step %d (pc %llx, arrival %d); last good "
                "step %d (pc %llx):\n%s",
                i, (unsigned long long)a->t->steps[i].pc, a->nth[i], last_ok,
                last_ok >= 0 ? (unsigned long long)a->t->steps[last_ok].pc : 0ULL, txt);
            fprintf(stderr, "  dynamic path between them:\n");
            for (int j = last_ok < 0 ? 0 : last_ok; j <= i; j++) {
                int idx = (int)((a->t->steps[j].pc - CODE_BASE) / 4);
                fprintf(stderr, "    [%d] %llx: %08x  %s\n", j,
                        (unsigned long long)a->t->steps[j].pc, a->b->a.w[idx],
                        a->b->a.txt[idx]);
            }
            found = 1;
        } else
            last_ok = i;
        free(txt);
    }
    if (!found)
        fprintf(stderr, "no divergence found\n");
    a64p_stop_dr();
    return found;
}

static int
mode_dbisect(const char *gmode, uint64_t seed, const char *vlist)
{
    block_t *b = malloc(sizeof(*b)), *t = malloc(sizeof(*t));
    a64p_install_handlers(&g_w, 0);
    if (!make_block(b, gmode, seed, 0))
        return 1;
    trace_t tr;
    tr.cap = 100000;
    tr.steps = malloc(sizeof(tstep_t) * tr.cap);
    tr.want_dhash = 0;
    a64p_install_code(&g_w, b, 0);
    if (a64p_trace_block(&g_w, b, &tr) < 0) {
        fprintf(stderr, "trace failed (exclusives or BRK?): use 'bisect'\n");
        return 1;
    }
    int *ks = calloc(tr.n, sizeof(int)), *nth = calloc(tr.n, sizeof(int));
    int *cnt = calloc(b->a.n, sizeof(int));
    result_t *native = calloc(tr.n, sizeof(result_t));
    for (int i = 0; i < tr.n; i++) {
        int k = (int)((tr.steps[i].pc - CODE_BASE) / 4);
        nth[i] = ++cnt[k];
        ks[i] = (k >= b->exit_start || b->a.fault_ok[k] || pc_relative(b->a.w[k]) ||
                 tr.steps[i].sp % 16 != 0)
            ? -1
            : k;
        if (ks[i] < 0)
            continue;
        dyn_truncate(t, b, k);
        a64p_install_code(&g_w, t, 0);
        *(uint64_t *)DYN_COUNTER = (uint64_t)nth[i];
        a64p_run_block(&g_w, t, &native[i]);
    }
    print_block(stderr, b);
    fprintf(stderr, "native trace: %d steps\n", tr.n);
    for (int vi = 0; vi < a64p_num_variants; vi++) {
        const variant_t *v = &a64p_variants[vi];
        if (!a64p_variant_selected(vlist, v))
            continue;
        dbisect_args_t a = { v, b, &tr, ks, nth, native };
        fprintf(stderr, "== variant %s\n", v->name);
        a64p_in_child("dbisect", v, dbisect_child, &a);
    }
    return 0;
}

/***************************************************************************
 * Property 2: asynchronous signal translation.
 */
/* Queued real-time signals: block one, queue many with payloads, unblock, and
 * check that all are delivered once, in order, with their payloads.  Under DR
 * these all become pending at once (more than -max_pending_signals).
 */
#define QSIG_N 40
static volatile int qsig_seen;
static int qsig_vals[QSIG_N];

static void
qsig_handler(int sig, siginfo_t *si, void *ucv)
{
    if (qsig_seen < QSIG_N)
        qsig_vals[qsig_seen] = si->si_value.sival_int;
    qsig_seen++;
}

static int
check_signal_queue(const char *who)
{
    int sig = SIGRTMIN + 3, fails = 0;
    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = qsig_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(sig, &sa, &old);
    sigset_t set, prev;
    sigemptyset(&set);
    sigaddset(&set, sig);
    for (int round = 0; round < 3; round++) {
        qsig_seen = 0;
        sigprocmask(SIG_BLOCK, &set, &prev);
        for (int i = 0; i < QSIG_N; i++) {
            union sigval v;
            v.sival_int = round * 1000 + i;
            sigqueue(getpid(), sig, v);
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);
        if (qsig_seen != QSIG_N) {
            fprintf(stderr,
                    "FAIL [signals queue] %s: %d of %d queued signals delivered\n", who,
                    qsig_seen, QSIG_N);
            fails++;
            continue;
        }
        for (int i = 0; i < QSIG_N; i++) {
            if (qsig_vals[i] != round * 1000 + i) {
                fprintf(stderr,
                        "FAIL [signals queue] %s: signal %d had payload %d, want %d\n",
                        who, i, qsig_vals[i], round * 1000 + i);
                fails++;
                break;
            }
        }
    }
    sigaction(sig, &old, NULL);
    return fails;
}

typedef struct {
    const variant_t *v;
    block_t *b;
    result_t *base;
    trace_t *t;
    int runs;
    int native;
    /* In-block interrupted contexts checked, per signal source. */
    long hits[3];
    long records, stub, extra;
} p2_args_t;

/* Coverage quota: in-block interrupted contexts per signal source per block
 * and variant (and natively), reached with at most sig_max_extra extra batches
 * of 50 runs beyond the scheduled ones.  A miss is a coverage failure, never a
 * pass.
 */
static int sig_quota = 10;
static int sig_max_extra = 200;
#define SIG_BATCH 50

static int
state_diffs(FILE *o, arec_t *r, tstep_t *s, int xres, uint64_t xexp, int print)
{
    int bad = 0;
    for (int i = 0; i < 31; i++) {
        uint64_t exp = i == xres ? xexp : s->x[i];
        if (r->x[i] != exp) {
            if (print)
                fprintf(o, "      x%-2d native 0x%016llx  signal 0x%016llx\n", i,
                        (unsigned long long)exp, (unsigned long long)r->x[i]);
            bad++;
        }
    }
#define ACMP(f, m)                                                          \
    do {                                                                    \
        if ((r->f & (m)) != (s->f & (m))) {                                 \
            if (print)                                                      \
                fprintf(o, "      %-6s native 0x%llx  signal 0x%llx\n", #f, \
                        (unsigned long long)(s->f & (m)),                   \
                        (unsigned long long)(r->f & (m)));                  \
            bad++;                                                          \
        }                                                                   \
    } while (0)
    ACMP(sp, ~0ULL);
    ACMP(pstate, ASYNC_PSTATE_CMP & ~async_pstate_masked);
    ACMP(fpsr, ~0U);
    ACMP(fpcr, ~0U);
    ACMP(vhash, ~0ULL);
    ACMP(dhash, ~0ULL);
#undef ACMP
    return bad;
}

/* Validates the async log for the runs just made with source src; returns
 * the failure count.
 */
static int
validate_async(FILE *o, p2_args_t *a, int run_lo, int run_hi, result_t *finals, int src)
{
    block_t *b = a->b;
    trace_t *t = a->t;
    int fails = 0;
    uint64_t lo = pc_of(b->block_start), hi = pc_of(b->exit_start);
    uint64_t code_hi = CODE_BASE + 4ULL * b->a.n;
    /* Outside every run (run id -1) the app is in host code: a context in the
     * generated code there is impossible.
     */
    for (int k = 0; k < g_w.na; k++) {
        arec_t *r = &g_w.alog[k];
        if (r->run < 0 && r->pc >= CODE_BASE && r->pc < code_hi) {
            fprintf(o, "    signal %d: pc 0x%llx in the generated code outside any run\n",
                    k, (unsigned long long)r->pc);
            fails++;
        }
    }
    for (int run = run_lo; run < run_hi; run++) {
        int last = 0;
        uint64_t xsum = 0;
        /* Records are in delivery order; signals between runs carry other ids. */
        for (int k = 0; k < g_w.na; k++) {
            arec_t *r = &g_w.alog[k];
            if (r->run != run)
                continue;
            a->records++;
            if (r->pc < lo || r->pc > hi) {
                /* Between the run id store and the block, and between the block
                 * and the run id reset, only the generated entry/exit stubs and
                 * the host trampoline run.
                 */
                if ((r->pc >= CODE_BASE && r->pc < code_hi) ||
                    a64p_pc_in_trampoline(r->pc)) {
                    a->stub++;
                    continue;
                }
                fprintf(o,
                        "    run %d signal %d (sig %d): pc 0x%llx is neither the block, "
                        "its stubs nor the trampoline\n",
                        run, k, r->sig, (unsigned long long)r->pc);
                fails++;
                continue;
            }
            a->hits[src]++;
            uint64_t xexp = b->xres >= 0 ? b->in.x[b->xres] + xsum : 0;
            int found = -1, best = -1, bestd = 1 << 30;
            for (int i = last; i < t->n; i++) {
                if (t->steps[i].pc != r->pc)
                    continue;
                int d = state_diffs(o, r, &t->steps[i], b->xres, xexp, 0);
                if (d == 0) {
                    found = i;
                    break;
                }
                if (d < bestd) {
                    bestd = d;
                    best = i;
                }
            }
            if (b->vres >= 0 && found >= 0 &&
                r->vres_lo != (uint64_t)b->in.v[b->vres] + xsum) {
                fprintf(o,
                        "    run %d: v%d (handler-modified) is 0x%llx, expected 0x%llx\n",
                        run, b->vres, (unsigned long long)r->vres_lo,
                        (unsigned long long)((uint64_t)b->in.v[b->vres] + xsum));
                fails++;
            }
            if (found < 0) {
                fails++;
                fprintf(
                    o,
                    "    run %d signal #%d (sig %d): interrupted context at pc 0x%llx "
                    "matches no native state at/after trace step %d\n",
                    run, k, r->sig, (unsigned long long)r->pc, last);
                if (best >= 0) {
                    fprintf(o, "      closest native step %d differs in %d fields:\n",
                            best, bestd);
                    state_diffs(o, r, &t->steps[best], b->xres, xexp, 1);
                } else
                    fprintf(o, "      (pc never executed natively after step %d)\n",
                            last);
            } else {
                last = found;
                if (!a->native)
                    count_masked_async(t->steps[found].pstate, r->pstate);
            }
            if (r->applied)
                xsum += 0x10001ULL * (uint64_t)(k + 1);
        }
        result_t *f = &finals[run - run_lo];
        /* The block raises no synchronous fault natively (the generator plans
         * none here), so none may be reported: the sync handler would skip it.
         */
        if (f->nf != 0) {
            fprintf(o, "    run %d: %d unexpected synchronous fault(s)\n", run, f->nf);
            a64p_print_faults(o, "run", f);
            fails++;
        }
        /* Final state: native base plus the handler's changes. */
        int bad = a64p_cmp_state(o, "final", &a->base->out, &f->out, b->xres, xsum,
                                 b->vres, xsum);
        bad += a64p_cmp_mem(o, b, a->base, f);
        if (bad) {
            fprintf(o, "    run %d: final state differs (handler deltas 0x%llx)\n", run,
                    (unsigned long long)xsum);
            fails++;
        }
        if (fails > 4)
            break;
    }
    if (fails > 0) {
        /* The delivery log: what the seed cannot reproduce. */
        fprintf(o, "    deliveries (record: run sig pc applied):");
        for (int j = 0; j < g_w.na; j++) {
            fprintf(o, "%s %d:%d:%d:0x%llx:%d", j % 6 == 0 ? "\n     " : "", j,
                    g_w.alog[j].run, g_w.alog[j].sig, (unsigned long long)g_w.alog[j].pc,
                    g_w.alog[j].applied);
        }
        fprintf(o, "\n");
    }
    return fails;
}

static int
p2_runs(p2_args_t *a)
{
    block_t *b = a->b;
    rng_t r = { b->seed ^ (a->native ? 0x1111 : 0x2222) };
    int fails = 0;
    a64p_sigsrc_calibrate(&g_src, b);
    g_w.xres = b->xres;
    g_w.vres = b->vres;
    g_w.na = 0;
    result_t *finals = malloc(sizeof(result_t) * SIG_BATCH);
    int scheduled = (a->runs + SIG_BATCH - 1) / SIG_BATCH;
    for (int batch = 0; fails == 0; batch++) {
        int src, cnt = SIG_BATCH;
        if (batch < scheduled) {
            src = batch % 3;
            if (a->runs - batch * SIG_BATCH < cnt)
                cnt = a->runs - batch * SIG_BATCH;
        } else {
            /* Extra batches for the source furthest below the quota. */
            src = -1;
            for (int s = 0; s < 3; s++) {
                if (a->hits[s] < sig_quota && (src < 0 || a->hits[s] < a->hits[src]))
                    src = s;
            }
            if (src < 0 || a->runs == 0)
                break;
            if (batch >= scheduled + sig_max_extra) {
                fprintf(stderr,
                        "COVERAGE FAIL [signals%s] variant=%s seed=%llu: in-block "
                        "interrupted contexts itimer %ld, posix-timer %ld, tgkill %ld "
                        "after %d runs (quota %d per source)\n",
                        a->native ? " native" : "", a->v->name,
                        (unsigned long long)b->seed, a->hits[0], a->hits[1], a->hits[2],
                        batch * SIG_BATCH, sig_quota);
                fails++;
                break;
            }
            a->extra++;
        }
        int run0 = batch * SIG_BATCH;
        g_w.na = 0;
        g_w.async_on = 1;
        if (!a64p_sigsrc_arm(&g_src, src, &r)) {
            fails++;
            break;
        }
        for (int i = 0; i < cnt; i++) {
            a64p_prog->run = run0 + i;
            a64p_run_block_id(&g_w, b, &finals[i], run0 + i);
        }
        g_w.async_on = 0;
        a64p_sigsrc_disarm(&g_src, src);
        char *txt = NULL;
        size_t len = 0;
        FILE *o = open_memstream(&txt, &len);
        int f = validate_async(o, a, run0, run0 + cnt, finals, src);
        fclose(o);
        if (verbose) {
            printf("    %s batch %d (%s): %d signals, in-block so far %ld/%ld/%ld\n",
                   a->native ? "native" : a->v->name, batch, a64p_sigsrc_name(src),
                   g_w.na, a->hits[0], a->hits[1], a->hits[2]);
        }
        if (f > 0) {
            fprintf(stderr,
                    "FAIL [signals%s] variant=%s seed=%llu source=%s: %d bad interrupted "
                    "contexts/finals\n%s",
                    a->native ? " (NATIVE ORACLE SELF-CHECK)" : "", a->v->name,
                    (unsigned long long)b->seed, a64p_sigsrc_name(src), f, txt);
            print_block(stderr, b);
            a64p_print_replay(stderr, "a64_dr_prop", "signals", a->native ? NULL : a->v,
                              b);
            fprintf(stderr,
                    "  repro: a64_dr_prop signals -seed %llu -n 1 -variants %s -v\n",
                    (unsigned long long)b->seed, a->v->name);
            fails += f;
        }
        free(txt);
    }
    free(finals);
    return fails;
}

static int
p2_child(void *argp)
{
    p2_args_t *a = (p2_args_t *)argp;
    a64p_install_handlers(&g_w, a->v->altstack);
    a64p_prog->block = 0;
    a64p_prog->seed = a->b->seed;
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "dr start");
    a64p_start_dr(a->v->dr_ops);
    a64p_sigsrc_init(&g_src, &g_w);
    {
        const char *e = getenv("A64_DR_PROP_SIG_SCALE");
        g_src.period_scale = e != NULL ? atoi(e) : 4;
    }
    a64p_install_code(&g_w, a->b, a->v->install);
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "signal queue");
    int f = check_signal_queue(a->v->name);
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "signal runs");
    f += p2_runs(a);
    for (int s = 0; s < 3; s++)
        stat_add(ST_SIG_HITS0 + s, a->hits[s]);
    stat_add(ST_SIG_RECORDS, a->records);
    stat_add(ST_SIG_STUB, a->stub);
    stat_add(ST_SIG_EXTRA, a->extra);
    if (f == 0)
        stat_add(ST_BLOCKS_CHECKED, 1);
    if (verbose) {
        printf("  dr %s: in-block interrupted contexts checked: itimer %ld, posix-timer "
               "%ld, tgkill %ld (%ld extra batches)\n",
               a->v->name, a->hits[0], a->hits[1], a->hits[2], a->extra);
    }
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "dr stop");
    a64p_stop_dr();
    return f;
}

static int
mode_signals(uint64_t seed0, int n, const char *vlist, int runs, int *nvariants)
{
    block_t *b = malloc(sizeof(*b));
    result_t *base = malloc(sizeof(*base));
    trace_t t;
    t.cap = 60000;
    t.steps = malloc(sizeof(tstep_t) * t.cap);
    t.want_dhash = 1;
    int total = 0, gen_fail = 0, trace_fail = 0, accepted = 0;
    long native_hits[3] = { 0 }, nchildren = 0;
    a64p_install_handlers(&g_w, 0);
    a64p_sigsrc_init(&g_src, &g_w);
    if (check_signal_queue("native") != 0) {
        fprintf(stderr, "ORACLE ERROR: native signal queue check failed\n");
        total++;
    }
    memset(g_stat, 0, sizeof(g_stat));
    int vfail[64] = { 0 }, vran[64] = { 0 };
    for (int i = 0; i < n; i++) {
        uint64_t seed = seed0 + i;
        if (!make_block(b, "signals", seed, i)) {
            gen_fail++;
            continue;
        }
        a64p_install_code(&g_w, b, 0);
        a64p_run_block(&g_w, b, base);
        if (base->nf != 0) {
            fprintf(stderr, "GENERATOR BUG: fault in signals block seed %llu\n",
                    (unsigned long long)seed);
            a64p_print_faults(stderr, "native", base);
            total++;
            continue;
        }
        int steps = a64p_trace_block(&g_w, b, &t);
        if (steps < 0) {
            fprintf(stderr, "NOTE: seed %llu: native trace failed or too long; skipped\n",
                    (unsigned long long)seed);
            trace_fail++;
            continue;
        }
        if (verbose) {
            print_block(stdout, b);
            printf("  native trace: %d steps\n", steps);
        }
        /* The oracle must accept native interrupted contexts, and see enough of
         * them for its acceptance to mean something.
         */
        variant_t nv = { "native", "", 0, 0, 0, 0 };
        p2_args_t a = { &nv, b, base, &t, runs / 2, 1 };
        int f = p2_runs(&a);
        if (f) {
            fprintf(stderr, "ORACLE ERROR: native signal contexts rejected (seed %llu)\n",
                    (unsigned long long)seed);
            total += f;
            continue;
        }
        for (int s = 0; s < 3; s++)
            native_hits[s] += a.hits[s];
        if (verbose) {
            printf("  native: in-block interrupted contexts checked: itimer %ld, "
                   "posix-timer %ld, tgkill %ld\n",
                   a.hits[0], a.hits[1], a.hits[2]);
        }
        accepted++;
        for (int vi = 0; vi < a64p_num_variants; vi++) {
            const variant_t *v = &a64p_variants[vi];
            if (!a64p_variant_selected(vlist, v))
                continue;
            if (!variant_ok(v) || v->install != 0 || (v->no_ctr && opt_allow_ctr))
                continue;
            p2_args_t da = { v, b, base, &t, runs, 0 };
            /* The child reports its counts through the progress page. */
            int f2 = a64p_in_child("signals", v, p2_child, &da);
            collect_stats();
            nchildren++;
            vfail[vi] += f2 != 0;
            vran[vi]++;
            total += f2;
        }
    }
    int nrun = 0;
    for (int vi = 0; vi < a64p_num_variants; vi++) {
        if (vran[vi] == 0)
            continue;
        nrun++;
        if (verbose || print_summary())
            printf("signals variant %-12s: %s (%d failing blocks)\n",
                   a64p_variants[vi].name, vfail[vi] ? "FAIL" : "ok", vfail[vi]);
    }
    long hits =
        g_stat[ST_SIG_HITS0] + g_stat[ST_SIG_HITS0 + 1] + g_stat[ST_SIG_HITS0 + 2];
    a64p_counts_t c = { n,
                        accepted,
                        nchildren,
                        g_stat[ST_BLOCKS_CHECKED],
                        masked_total(),
                        gen_fail + trace_fail };
    a64p_counts_print(stdout, "signals (block x variant)", &c);
    printf("signals: in-block interrupted contexts checked: itimer %ld, posix-timer %ld, "
           "tgkill %ld (native %ld, %ld, %ld); %ld in stubs; %ld extra batches\n",
           g_stat[ST_SIG_HITS0], g_stat[ST_SIG_HITS0 + 1], g_stat[ST_SIG_HITS0 + 2],
           native_hits[0], native_hits[1], native_hits[2], g_stat[ST_SIG_STUB],
           g_stat[ST_SIG_EXTRA]);
    total += print_kdevs("signals");
    /* Floors: most seeds give a traceable block, and the per-block quotas
     * (enforced in p2_runs) add up.
     */
    total += a64p_floor("signals", "blocks with a native oracle", accepted, (n + 1) / 2);
    if (runs > 0) {
        total += a64p_floor("signals", "in-block contexts checked under DR", hits,
                            3L * sig_quota * nchildren);
    }
    *nvariants += nrun;
    free(t.steps);
    free(base);
    free(b);
    return total;
}

/***************************************************************************
 * Property 4: instrumentation transparency (in-process client).
 */

static void
log_mem(uint64_t pc, uint64_t addr)
{
    if (g_nml < MAXML) {
        g_mlog[g_nml].cnt = g_dyn_count;
        g_mlog[g_nml].pc = pc;
        g_mlog[g_nml].addr = addr;
        g_nml++;
    }
}

static int
rand_reserve(void *dc, instrlist_t *bb, instr_t *where, rng_t *r, reg_id_t *out)
{
    drvector_t allowed;
    drreg_init_and_fill_vector(&allowed, false);
    int any = 0;
    for (int i = 0; i < 31; i++) {
        if (rp(r, 30) && DR_REG_X0 + i != dr_get_stolen_reg()) {
            drreg_set_vector_entry(&allowed, DR_REG_X0 + i, true);
            any = 1;
        }
    }
    drreg_status_t res =
        drreg_reserve_register(dc, bb, where, any ? &allowed : NULL, out);
    if (res != DRREG_SUCCESS && any)
        res = drreg_reserve_register(dc, bb, where, NULL, out);
    drvector_delete(&allowed);
    return res == DRREG_SUCCESS;
}

static dr_emit_flags_t
event_insert(void *dc, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace,
             bool translating, void *user_data)
{
    if (!instr_is_app(inst))
        return DR_EMIT_DEFAULT;
    uint64_t pc = (uint64_t)instr_get_app_pc(inst);
    if (pc < g_w.blk_lo || pc > g_w.blk_hi)
        return DR_EMIT_DEFAULT;
    /* Deterministic per pc, so translation re-creates identical code. */
    rng_t r = { g_instr_seed ^ (pc * 0x9e3779b97f4a7c15ULL) };
    if (!(g_instr_disable & 1)) {
        drx_insert_counter_update(dc, bb, inst, (dr_spill_slot_t)(SPILL_SLOT_MAX + 1),
                                  (dr_spill_slot_t)(SPILL_SLOT_MAX + 1),
                                  (void *)&g_dyn_count, 1, DRX_COUNTER_64BIT);
        if (g_pc_count != NULL) {
            drx_insert_counter_update(dc, bb, inst, (dr_spill_slot_t)(SPILL_SLOT_MAX + 1),
                                      (dr_spill_slot_t)(SPILL_SLOT_MAX + 1),
                                      (void *)&g_pc_count[(pc - CODE_BASE) / 4], 1,
                                      DRX_COUNTER_64BIT);
        }
    }
    if (!(g_instr_disable & 2) && rp(&r, 60)) {
        reg_id_t regs[3];
        int nr = 1 + (int)rn(&r, 3), got = 0;
        for (int i = 0; i < nr; i++) {
            if (rand_reserve(dc, bb, inst, &r, &regs[got]))
                got++;
        }
        for (int i = 0; i < got; i++) {
            instrlist_insert_mov_immed_ptrsz(
                dc, (ptr_int_t)rnext(&r), opnd_create_reg(regs[i]), bb, inst, NULL, NULL);
        }
        if (got > 0 && rp(&r, 50) &&
            drreg_reserve_aflags(dc, bb, inst) == DRREG_SUCCESS) {
            instrlist_meta_preinsert(bb, inst,
                                     INSTR_CREATE_msr(dc, opnd_create_reg(DR_REG_NZCV),
                                                      opnd_create_reg(regs[0])));
            drreg_unreserve_aflags(dc, bb, inst);
        }
        for (int i = 0; i < got; i++)
            drreg_unreserve_register(dc, bb, inst, regs[i]);
    }
    for (int s = 0; s < 2 && !(g_instr_disable & 4); s++) {
        /* ADR/ADRP have address operands that are not accesses. */
        if (s ? !instr_writes_memory(inst) : !instr_reads_memory(inst))
            continue;
        int nops = s ? instr_num_dsts(inst) : instr_num_srcs(inst);
        for (int i = 0; i < nops; i++) {
            opnd_t ref = s ? instr_get_dst(inst, i) : instr_get_src(inst, i);
            if (!opnd_is_memory_reference(ref))
                continue;
            reg_id_t ra, rs;
            if (!rand_reserve(dc, bb, inst, &r, &ra))
                continue;
            if (!rand_reserve(dc, bb, inst, &r, &rs)) {
                drreg_unreserve_register(dc, bb, inst, ra);
                continue;
            }
            if (drutil_insert_get_mem_addr(dc, bb, inst, ref, ra, rs)) {
                reg_id_t ri;
                if (g_instr_disable & 8) {
                    /* No logging. */
                } else if (g_use_cleancall) {
                    dr_insert_clean_call(dc, bb, inst, (void *)log_mem, false, 2,
                                         OPND_CREATE_INTPTR(pc), opnd_create_reg(ra));
                } else if (rand_reserve(dc, bb, inst, &r, &ri)) {
                    /* g_addr_by_cnt[g_dyn_count & ADDR_LOG_MASK] = ra */
                    instrlist_insert_mov_immed_ptrsz(dc, (ptr_int_t)&g_dyn_count,
                                                     opnd_create_reg(rs), bb, inst, NULL,
                                                     NULL);
                    instrlist_meta_preinsert(bb, inst,
                                             INSTR_CREATE_ldr(dc, opnd_create_reg(rs),
                                                              OPND_CREATE_MEMPTR(rs, 0)));
                    instrlist_meta_preinsert(
                        bb, inst,
                        INSTR_CREATE_and(dc, opnd_create_reg(rs), opnd_create_reg(rs),
                                         OPND_CREATE_INT(ADDR_LOG_MASK)));
                    instrlist_insert_mov_immed_ptrsz(dc, (ptr_int_t)g_addr_by_cnt,
                                                     opnd_create_reg(ri), bb, inst, NULL,
                                                     NULL);
                    instrlist_meta_preinsert(
                        bb, inst,
                        INSTR_CREATE_str(dc,
                                         opnd_create_base_disp_aarch64(
                                             ri, rs, DR_EXTEND_UXTX, true, 0, 0, OPSZ_8),
                                         opnd_create_reg(ra)));
                    /* g_pc_by_cnt[g_dyn_count & ADDR_LOG_MASK] = pc (ra is free now) */
                    instrlist_insert_mov_immed_ptrsz(dc, (ptr_int_t)g_pc_by_cnt,
                                                     opnd_create_reg(ri), bb, inst, NULL,
                                                     NULL);
                    instrlist_insert_mov_immed_ptrsz(
                        dc, (ptr_int_t)pc, opnd_create_reg(ra), bb, inst, NULL, NULL);
                    instrlist_meta_preinsert(
                        bb, inst,
                        INSTR_CREATE_str(dc,
                                         opnd_create_base_disp_aarch64(
                                             ri, rs, DR_EXTEND_UXTX, true, 0, 0, OPSZ_8),
                                         opnd_create_reg(ra)));
                    drreg_unreserve_register(dc, bb, inst, ri);
                }
            } else
                g_drutil_fail++;
            drreg_unreserve_register(dc, bb, inst, rs);
            drreg_unreserve_register(dc, bb, inst, ra);
        }
    }
    return DR_EMIT_DEFAULT;
}

static void
client_exit(void)
{
    drx_exit();
    drutil_exit();
    drreg_exit();
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    if (!g_instr_on)
        return;
    /* Conservative: without it drreg documents that dead registers may hold
     * tool values at a fault, which this property would flag.
     */
    drreg_options_t ops = { sizeof(ops), 3, true };
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drutil_init() ||
        !drx_init())
        DR_ASSERT(false);
    drmgr_register_bb_instrumentation_event(NULL, event_insert, NULL);
    dr_register_exit_event(client_exit);
}

typedef struct {
    uint64_t cnt, pc, addr;
    int must;
} mexp_t;

typedef struct {
    int valid, traced, nexp;
    uint64_t total;
    mexp_t *exp;
    uint32_t *pc_count; /* native executions per instruction index */
} p4_native_t;

typedef struct {
    const variant_t *v;
    uint64_t seed0;
    int n;
    result_t *native;
    p4_native_t *pn;
} p4_args_t;

static uint64_t
model_addr(meminfo_t *m, tstep_t *s)
{
    if (m->lit)
        return m->litaddr;
    uint64_t base = m->base == 31 ? s->sp : s->x[m->base];
    if (m->pac)
        base = a64p_xpacd(base);
    uint64_t a = base + (m->wb == 2 ? 0 : (int64_t)m->off);
    if (m->idx >= 0) {
        uint64_t iv = m->idx == 31 ? 0 : s->x[m->idx];
        if (m->ext == 2)
            iv = (uint32_t)iv;
        else if (m->ext == 6)
            iv = (uint64_t)(int64_t)(int32_t)iv;
        a += iv << m->shift;
    }
    return a;
}

/* Turns the inline address log into records like the clean call's: the pc
 * is the one the instrumentation logged, never one taken from the expectation.
 */
static void
collect_inline_log(void)
{
    if (g_use_cleancall)
        return;
    g_nml = 0;
    for (uint64_t cnt = 0; cnt <= ADDR_LOG_MASK && g_nml < MAXML; cnt++) {
        if (g_addr_by_cnt[cnt] == 0)
            continue;
        g_mlog[g_nml].cnt = cnt;
        g_mlog[g_nml].pc = g_pc_by_cnt[cnt];
        g_mlog[g_nml].addr = g_addr_by_cnt[cnt];
        g_nml++;
    }
}

/* Text of the instruction at pc, or a placeholder outside the code. */
static const char *
txt_at(block_t *b, uint64_t pc)
{
    if (pc < CODE_BASE || pc >= CODE_BASE + 4ULL * b->a.n || pc % 4 != 0)
        return "(not in the block!)";
    return b->a.txt[(pc - CODE_BASE) / 4];
}

/* Checks that need no native trace: instrumentation API failures. */
static int
p4_check_api(FILE *o)
{
    if (g_drutil_fail > 0) {
        fprintf(o, "    drutil_insert_get_mem_addr failed %d times\n", g_drutil_fail);
        return 1;
    }
    return 0;
}

/* Checks against the native trace: counts and addresses. */
static int
p4_check(FILE *o, block_t *b, p4_native_t *pn)
{
    int bad = 0;
    collect_inline_log();
    if (g_dyn_count != pn->total) {
        fprintf(o, "    drx count %llu, native dynamic instruction count %llu\n",
                (unsigned long long)g_dyn_count, (unsigned long long)pn->total);
        bad++;
    }
    /* Per instruction, always: equal totals can hide misattributed counts. */
    if (!(g_instr_disable & 1)) {
        for (int i = 0; i < b->a.n; i++) {
            if (g_pc_count[i] != pn->pc_count[i]) {
                fprintf(o, "      %llx (%s): executed %u times natively, counted %llu\n",
                        (unsigned long long)pc_of(i), b->a.txt[i], pn->pc_count[i],
                        (unsigned long long)g_pc_count[i]);
                bad++;
            }
        }
    }
    int l = 0;
    for (int e = 0; e < pn->nexp && bad < 10; e++) {
        mexp_t *x = &pn->exp[e];
        for (; l < g_nml && g_mlog[l].cnt < x->cnt; l++) {
            fprintf(
                o,
                "    step %llu pc 0x%llx (%s): address 0x%llx logged for a step with no "
                "modelled memory access\n",
                (unsigned long long)g_mlog[l].cnt, (unsigned long long)g_mlog[l].pc,
                txt_at(b, g_mlog[l].pc), (unsigned long long)g_mlog[l].addr);
            bad++;
        }
        int seen = 0;
        for (; l < g_nml && g_mlog[l].cnt == x->cnt; l++) {
            seen++;
            stat_add(ST_INSTR_ADDRS, 1);
            if (g_mlog[l].pc != x->pc || g_mlog[l].addr != x->addr) {
                fprintf(o,
                        "    step %llu pc 0x%llx (%s): drutil address 0x%llx, native "
                        "address 0x%llx%s\n",
                        (unsigned long long)x->cnt, (unsigned long long)x->pc,
                        txt_at(b, x->pc), (unsigned long long)g_mlog[l].addr,
                        (unsigned long long)x->addr,
                        g_mlog[l].pc != x->pc ? " (pc mismatch!)" : "");
                bad++;
            }
        }
        if (seen == 0 && x->must) {
            fprintf(o, "    step %llu pc 0x%llx (%s): no memory operand instrumented\n",
                    (unsigned long long)x->cnt, (unsigned long long)x->pc,
                    txt_at(b, x->pc));
            bad++;
        }
    }
    for (; l < g_nml && bad < 10; l++) {
        fprintf(o,
                "    step %llu pc 0x%llx (%s): address 0x%llx logged for a step with no "
                "modelled memory access\n",
                (unsigned long long)g_mlog[l].cnt, (unsigned long long)g_mlog[l].pc,
                txt_at(b, g_mlog[l].pc), (unsigned long long)g_mlog[l].addr);
        bad++;
    }
    return bad;
}

static int
p4_child(void *argp)
{
    p4_args_t *a = (p4_args_t *)argp;
    block_t *b = malloc(sizeof(*b));
    result_t *r = malloc(sizeof(*r));
    int fails = 0;
    a64p_install_handlers(&g_w, a->v->altstack);
    g_instr_on = 1;
    g_instr_seed = a->seed0 * 31 + 7;
    g_mlog = malloc(sizeof(mlog_t) * MAXML);
    g_addr_by_cnt = calloc(ADDR_LOG_MASK + 1, sizeof(uint64_t));
    g_pc_by_cnt = calloc(ADDR_LOG_MASK + 1, sizeof(uint64_t));
    g_use_cleancall = getenv("A64_DR_PROP_CLEANCALL") != NULL;
    g_pc_count = calloc(MAXW, sizeof(uint64_t));
    a64p_on_masked_pstate = on_masked_fault_pstate;
    /* Instrument only the block range: set before DR builds anything. */
    g_w.blk_lo = CODE_BASE;
    g_w.blk_hi = CODE_BASE;
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "dr start");
    a64p_start_dr(a->v->dr_ops);
    for (int i = 0; i < a->n; i++) {
        if (!a->pn[i].valid)
            continue;
        uint64_t seed = a->seed0 + i;
        a64p_prog->block = i;
        a64p_prog->seed = seed;
        /* Per block, so that "-seed S -n 1" reproduces the same instrumentation. */
        g_instr_seed = seed * 31 + 7;
        if (!make_block(b, "instr", seed, i)) {
            fprintf(stderr,
                    "FAIL [instr] variant=%s seed=%llu: block no longer generates\n",
                    a->v->name, (unsigned long long)seed);
            fails++;
            continue;
        }
        a64p_install_code(&g_w, b, a->v->install);
        int ok = 1;
        for (int rep = 0; rep < 2; rep++) {
            a64p_prog->run = rep;
            g_dyn_count = 0;
            g_nml = 0;
            g_drutil_fail = 0;
            memset(g_addr_by_cnt, 0, sizeof(uint64_t) * (ADDR_LOG_MASK + 1));
            memset(g_pc_by_cnt, 0, sizeof(uint64_t) * (ADDR_LOG_MASK + 1));
            memset(g_pc_count, 0, sizeof(uint64_t) * MAXW);
            snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "run");
            a64p_run_block(&g_w, b, r);
            stat_add(ST_RUNS, 1);
            char *txt = NULL;
            size_t len = 0;
            FILE *o = open_memstream(&txt, &len);
            int bad = a64p_cmp_results(o, b, &a->native[i], r);
            bad += p4_check_api(o);
            if (a->pn[i].traced)
                bad += p4_check(o, b, &a->pn[i]);
            fclose(o);
            stat_add(ST_RUNS_CHECKED, 1);
            if (bad > 0) {
                ok = 0;
                fails++;
                fprintf(stderr,
                        "FAIL [instr] variant=%s seed=%llu run=%d: %d differences\n%s",
                        a->v->name, (unsigned long long)seed, rep, bad, txt);
                a64p_print_faults(stderr, "native", &a->native[i]);
                a64p_print_faults(stderr, "dr", r);
                print_block(stderr, b);
                a64p_print_replay(stderr, "a64_dr_prop", "instr", a->v, b);
                fprintf(stderr,
                        "  repro: a64_dr_prop instr -seed %llu -n 1 -variants %s -v\n",
                        (unsigned long long)seed, a->v->name);
                rep = 2;
            }
            free(txt);
        }
        if (ok) {
            stat_add(ST_BLOCKS_CHECKED, 1);
            stat_add(a->pn[i].traced ? ST_INSTR_TRACED : ST_INSTR_UNTRACED, 1);
        }
        if (fails > 5)
            break;
    }
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "dr stop");
    a64p_stop_dr();
    return fails;
}

static int
mode_instr(uint64_t seed0, int n, const char *vlist, int *nvariants)
{
    result_t *native = calloc(n, sizeof(result_t));
    p4_native_t *pn = calloc(n, sizeof(p4_native_t));
    block_t *b = malloc(sizeof(*b));
    trace_t t;
    t.cap = 20000;
    t.steps = malloc(sizeof(tstep_t) * t.cap);
    t.want_dhash = 0;
    int total = 0, ntraced = 0, nexp = 0, gen_fail = 0, gen_bugs = 0, trace_fail = 0;
    int nvalid = 0, ntrace_wanted = 0;
    a64p_install_handlers(&g_w, 0);
    for (int i = 0; i < n; i++) {
        uint64_t seed = seed0 + i;
        if (!make_block(b, "instr", seed, i)) {
            gen_fail++;
            continue;
        }
        a64p_install_code(&g_w, b, 0);
        a64p_run_block(&g_w, b, &native[i]);
        if (!a64p_check_planned(b, &native[i])) {
            fprintf(stderr, "GENERATOR BUG: unplanned native fault, seed %llu\n",
                    (unsigned long long)seed);
            a64p_print_faults(stderr, "native", &native[i]);
            print_block(stderr, b);
            total++;
            gen_bugs++;
            continue;
        }
        gen_opts_t o;
        opts_for("instr", seed, &o);
        pn[i].valid = 1;
        nvalid++;
        if (o.traced) {
            ntrace_wanted++;
            int steps = a64p_trace_block(&g_w, b, &t);
            if (steps < 0) {
                fprintf(stderr, "NOTE: seed %llu: trace failed; address checks skipped\n",
                        (unsigned long long)seed);
                trace_fail++;
                continue;
            }
            pn[i].traced = 1;
            pn[i].total = (uint64_t)steps;
            pn[i].pc_count = calloc(b->a.n, sizeof(uint32_t));
            for (int s = 0; s < steps; s++)
                pn[i].pc_count[(t.steps[s].pc - CODE_BASE) / 4]++;
            int cnt = 0;
            for (int s = 0; s < steps; s++) {
                if (b->a.mi[(t.steps[s].pc - CODE_BASE) / 4].valid)
                    cnt++;
            }
            pn[i].exp = malloc(sizeof(mexp_t) * (cnt + 1));
            for (int s = 0; s < steps; s++) {
                meminfo_t *m = &b->a.mi[(t.steps[s].pc - CODE_BASE) / 4];
                if (!m->valid)
                    continue;
                mexp_t *x = &pn[i].exp[pn[i].nexp++];
                x->cnt = (uint64_t)s + 1;
                x->pc = t.steps[s].pc;
                x->addr = model_addr(m, &t.steps[s]);
                x->must = m->must;
            }
            ntraced++;
            nexp += pn[i].nexp;
        }
        if (verbose)
            print_block(stdout, b);
    }
    if (verbose || print_summary())
        printf("instr: %d blocks, %d traced with %d modelled memory accesses\n", n,
               ntraced, nexp);
    memset(g_stat, 0, sizeof(g_stat));
    int nrun = 0;
    for (int vi = 0; vi < a64p_num_variants; vi++) {
        const variant_t *v = &a64p_variants[vi];
        if (!a64p_variant_selected(vlist, v))
            continue;
        if (!variant_ok(v) || v->install != 0 || (v->no_ctr && opt_allow_ctr))
            continue;
        if (strcmp(v->name, "nocas") == 0)
            continue; /* instrumentation inside exclusive monitors needs ldstex2cas */
        p4_args_t a = { v, seed0, n, native, pn };
        int f = a64p_in_child("instr", v, p4_child, &a);
        long traced = a64p_prog->stat[ST_INSTR_TRACED],
             untraced = a64p_prog->stat[ST_INSTR_UNTRACED];
        collect_stats();
        nrun++;
        if (verbose || print_summary())
            printf("instr variant %-12s: %s (%d failing blocks; %ld traced, %ld untraced "
                   "checked)\n",
                   v->name, f ? "FAIL" : "ok", f, traced, untraced);
        total += f;
        if (f == 0) {
            total += a64p_floor("instr", v->name, traced, ntraced);
            total += a64p_floor("instr", v->name, traced + untraced, nvalid);
        }
    }
    a64p_counts_t c = { n,
                        nvalid,
                        g_stat[ST_RUNS],
                        g_stat[ST_RUNS_CHECKED],
                        masked_total(),
                        gen_fail + gen_bugs + trace_fail };
    a64p_counts_print(stdout, "instr", &c);
    printf("instr: blocks checked with a native trace %ld, without %ld; addresses "
           "compared %ld\n",
           g_stat[ST_INSTR_TRACED], g_stat[ST_INSTR_UNTRACED], g_stat[ST_INSTR_ADDRS]);
    total += print_kdevs("instr");
    /* Floors: half the seeds valid, and most of the seeds meant to be traced
     * (every other one) traced.
     */
    total += a64p_floor("instr", "natively valid blocks", nvalid, (n + 1) / 2);
    total += a64p_floor("instr", "traced blocks", ntraced, (ntrace_wanted * 3 + 3) / 4);
    *nvariants += nrun;
    free(t.steps);
    return total;
}

/***************************************************************************
 * main
 */
int
main(int argc, const char *argv[])
{
    const char *mode = argc > 1 ? argv[1] : "transparency";
    uint64_t seed = 1;
    int n = -1, runs = 300;
    const char *vlist = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc)
            seed = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            n = atoi(argv[++i]);
        else if (strcmp(argv[i], "-runs") == 0 && i + 1 < argc)
            runs = atoi(argv[++i]);
        else if (strcmp(argv[i], "-variants") == 0 && i + 1 < argc)
            vlist = argv[++i];
        else if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "-noctr") == 0)
            opt_allow_ctr = 0;
        else if (strcmp(argv[i], "-quota") == 0 && i + 1 < argc)
            sig_quota = atoi(argv[++i]);
        else if (strcmp(argv[i], "-max_extra") == 0 && i + 1 < argc)
            sig_max_extra = atoi(argv[++i]);
        else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if (vlist != NULL && a64p_unknown_variant(vlist) != NULL) {
        fprintf(stderr, "unknown variant '%s' in -variants %s; variants are:",
                a64p_unknown_variant(vlist), vlist);
        for (int i = 0; i < a64p_num_variants; i++)
            fprintf(stderr, " %s", a64p_variants[i].name);
        fprintf(stderr, "\n");
        return 2;
    }
    dczva_ok = a64p_init_features();
    if (getenv("A64_DR_PROP_IDISABLE") != NULL)
        g_instr_disable = atoi(getenv("A64_DR_PROP_IDISABLE"));
    /* Known deviations (see kdevs[]). */
    a64p_fault_pstate_ignore = PSTATE_BTYPE | PSTATE_SSBS;
    if (strcmp(mode, "ssbs") == 0) {
        a64p_fault_pstate_ignore &= ~PSTATE_SSBS;
        async_pstate_masked &= ~PSTATE_SSBS;
    }
    if (getenv("A64_DR_PROP_STRICT") != NULL) {
        async_pstate_masked = 0;
        a64p_fault_pstate_ignore = 0;
    }
    g_prctl_ssb_native = prctl_ssb();
#ifdef A64_DR_PROP_DEBUG_DR
    is_debug_build = 1;
#endif
    {
        /* Allow overriding: our own build flags may not match DR's. */
        const char *e = getenv("A64_DR_PROP_DEBUG_DR");
        if (e != NULL)
            is_debug_build = atoi(e);
    }
    a64p_progress_init("a64_dr_prop");
    a64p_worker_init(&g_w);
    a64p_setup_maps();
    /* We use printf for the summary; keep it unbuffered relative to stderr. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    int fails, nvariants = 0;
    if (strcmp(mode, "regress") == 0)
        fails = mode_regress(vlist, &nvariants);
    else if (strcmp(mode, "transparency") == 0) {
        fails = mode_regress(vlist, &nvariants);
        fails += mode_transparency(mode, mode, seed, n < 0 ? 300 : n, vlist, &nvariants);
        if (a64p_variant_selected(vlist, variant_named("smc_fakectr"))) {
            /* -fake_ctr_dic deliberately changes CTR_EL0: generate without CTR reads. */
            opt_allow_ctr = 0;
            fails += mode_transparency(mode, "transparency (no CTR reads)", seed,
                                       n < 0 ? 100 : n, "smc_fakectr", &nvariants);
        }
    } else if (strcmp(mode, "ssbs") == 0) {
        /* The focused check of PSTATE.SSBS (masked as fault-ssbs elsewhere):
         * how often native frames report it set, then DR frames compared
         * strictly.  A diagnostic: both are expected to be non-zero
         * occasionally (the kernel sets SSBS on some context switches).
         */
        printf("ssbs: PR_GET_SPECULATION_CTRL(PR_SPEC_STORE_BYPASS) natively %d\n",
               g_prctl_ssb_native);
        long nssbs = native_ssbs_frames(1000000);
        printf("ssbs: native SIGILL frames with PSTATE.SSBS set: %ld of 1000000\n",
               nssbs);
        fails = mode_transparency("transparency", mode, seed, n < 0 ? 100 : n, vlist,
                                  &nvariants);
    } else if (strcmp(mode, "signals") == 0)
        fails = mode_signals(seed, n < 0 ? 6 : n, vlist, runs, &nvariants);
    else if (strcmp(mode, "instr") == 0)
        fails = mode_instr(seed, n < 0 ? 120 : n, vlist, &nvariants);
    else if (strcmp(mode, "dbisect") == 0) {
        return mode_dbisect(getenv("A64_DR_PROP_GMODE") == NULL
                                ? "transparency"
                                : getenv("A64_DR_PROP_GMODE"),
                            seed, vlist == NULL ? "default" : vlist);
    } else if (strcmp(mode, "bisect") == 0) {
        return mode_bisect(getenv("A64_DR_PROP_GMODE") == NULL
                               ? "transparency"
                               : getenv("A64_DR_PROP_GMODE"),
                           seed, vlist == NULL ? "default" : vlist);
    } else if (strcmp(mode, "dump") == 0) {
        block_t *b = malloc(sizeof(*b));
        for (int i = 0; i < (n < 0 ? 1 : n); i++) {
            make_block(b, "transparency", seed + i, i);
            for (int k = b->block_start; k < b->exit_start; k++) {
                if (!b->a.isdata[k])
                    printf("0x%08x %s\n", b->a.w[k], b->a.txt[k]);
            }
        }
        return 0;
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    fails += a64p_floor(mode, "variants run", nvariants, 1);
    /* Only printed when every check and every coverage floor passed. */
    printf("%s: %s\n", mode, fails == 0 ? "all properties hold" : "FAILURES");
    return fails == 0 ? 0 : 1;
}

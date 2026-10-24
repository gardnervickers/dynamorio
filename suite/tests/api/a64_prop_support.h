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

/* Shared mechanics for the AArch64 differential property tests that run
 * generated code natively and under (static) DR: block generation with
 * retries, code installation, running a block from a fixed initial state,
 * capturing the final state and every fault frame, comparing two runs,
 * single-step (ptrace) tracing of the native run, asynchronous signal
 * sources and logging, forked-child supervision with a shared progress page,
 * and replay records.  Each property test is its own executable that links
 * this module and keeps its own oracle; nothing here decides what a property
 * accepts beyond comparing captured states.
 *
 * Mutable execution state lives in an a64p_worker_t rather than in globals.
 * The signal handlers reach the worker of the thread they interrupt through a
 * thread-local pointer (a64p_worker_bind()).  Each worker owns one of the
 * generator's layout slots (a64_dr_prop_gen.h): slot 0 is the original fixed
 * layout; workers in distinct slots can generate, install and run code in one
 * process concurrently, each on a thread bound to it.
 */

#ifndef A64_PROP_SUPPORT_H
#define A64_PROP_SUPPORT_H

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <ucontext.h>

#include "a64_dr_prop_gen.h"

/***************************************************************************
 * DR option variants.
 */
typedef struct {
    const char *name;
    const char *dr_ops;
    int altstack;
    /* 0 remap, 1 rwx + ic ivau, 2 mprotect + ic ivau, 3 honour CTR_EL0.DIC */
    int install;
    int debug_only;
    int no_ctr; /* the variant changes CTR_EL0 as seen by the app */
} variant_t;

extern const variant_t a64p_variants[];
extern const int a64p_num_variants;

/* Whether a comma-separated -variants list names v exactly (NULL selects
 * everything).
 */
int
a64p_variant_selected(const char *vlist, const variant_t *v);

/* Returns NULL if every name in vlist is a variant, else the first unknown
 * name (in a static buffer).
 */
const char *
a64p_unknown_variant(const char *vlist);

/***************************************************************************
 * Captured state.
 */
typedef struct {
    int signo, code;
    uint64_t addr, pc, sp, pstate, fault_address, esr;
    int has_esr, has_fp;
    uint64_t x[31];
    uint32_t fpsr, fpcr;
    __uint128_t v[32];
} fault_rec_t;

/* Fault frames recorded and compared per run: every one.  The generator aims
 * for at most about 24 dynamic faults but underestimates loops (instr seed
 * 346 has 41); a run with more than MAXF is a harness failure
 * (a64p_check_planned() rejects it natively, and the fault count comparison
 * rejects it under DR).
 */
#define MAXF 64
/* Faults after which the sync handler abandons the block. */
#define MAXF_RUN 64

typedef struct {
    cpu_state_t out;
    uint8_t d[D_SIZE];
    uint8_t stk[STK_CMP];
    int nf;
    fault_rec_t f[MAXF];
} result_t;

/* One asynchronous signal's interrupted context. */
typedef struct {
    int sig, run, applied;
    uint64_t pc, sp, pstate;
    uint64_t x[31];
    uint32_t fpsr, fpcr;
    uint64_t vhash, dhash, vres_lo;
} arec_t;
#define MAXA 8192

/* One single-stepped native instruction (state before it executes). */
typedef struct {
    uint64_t pc, sp, pstate;
    uint64_t x[31];
    uint32_t fpsr, fpcr;
    uint64_t vhash, dhash;
    int sig; /* the signal executing it raised (a fault), else 0 */
} tstep_t;

typedef struct {
    tstep_t *steps;
    int n, cap;
    int want_dhash;
} trace_t;

/***************************************************************************
 * Per-worker execution state.
 */
typedef struct {
    /* Read by the signal handlers. */
    volatile int in_block;
    volatile uint64_t blk_lo, blk_hi, exit_pc, code_hi;
    volatile int nf;
    fault_rec_t flog[MAXF];
    /* Asynchronous signal log. */
    arec_t *alog;
    volatile int na;
    volatile int async_on;
    volatile int xres, vres;
    volatile uint64_t delta_sum;
    /* Code installation. */
    int code_mapped_mode;
    harn_t *harn;
    stack_t altstk;
    /* The generator layout slot and its bases (a64g_slot_*_base()). */
    int slot;
    uint64_t code_base, data_base;
} a64p_worker_t;

/* Allocates the worker's logs; the worker uses layout slot 0. */
void
a64p_worker_init(a64p_worker_t *w);

/* Like a64p_worker_init() but for layout slot slot (0..A64G_MAX_SLOTS-1). */
void
a64p_worker_init_slot(a64p_worker_t *w, int slot);

/* Makes w the worker the signal handlers on this thread use, and selects w's
 * layout slot for the generator and the support module on this thread.
 */
void
a64p_worker_bind(a64p_worker_t *w);

/***************************************************************************
 * Setup, installation and running.
 */
/* Fills in the generator's CPU features from HWCAPs; returns whether DC ZVA
 * has the 64-byte block size the generator assumes.
 */
int
a64p_init_features(void);

/* Maps the data region (data buffer, guard page, stack, harness) of the
 * calling thread's layout slot.
 */
void
a64p_setup_maps(void);

void
a64p_install_handlers(a64p_worker_t *w, int altstack);

void
a64p_sync_icache(uint64_t start, uint64_t len, int honour_dic);

void
a64p_install_code(a64p_worker_t *w, block_t *b, int mode);

void
a64p_prepare_run(a64p_worker_t *w, block_t *b);

void
a64p_run_block(a64p_worker_t *w, block_t *b, result_t *res);

/* Generates b from seed, retrying with derived seeds. */
int
a64p_make_block(block_t *b, const gen_opts_t *o, uint64_t seed);

/* Host-side entry trampoline (in a64_prop_support.c): sets h->run_id to run
 * for exactly the time between its first and last instruction.
 */
void
run_code(uint64_t entry, harn_t *h, int64_t run);
extern const char run_code_end[];

/* The current run id, or -1 between runs. */
static inline int
a64p_run_id(a64p_worker_t *w)
{
    return (int)__atomic_load_n(&w->harn->run_id, __ATOMIC_ACQUIRE);
}

/* Whether pc is host code that legitimately runs inside a run: the
 * trampoline itself.  (The generated code's entry/exit stubs are in
 * [CODE_BASE, code_hi).)
 */
static inline int
a64p_pc_in_trampoline(uint64_t pc)
{
    return pc >= (uint64_t)(uintptr_t)run_code && pc < (uint64_t)(uintptr_t)run_code_end;
}

/* Runs b with h->run_id = run. */
void
a64p_run_block_id(a64p_worker_t *w, block_t *b, result_t *res, int run);

/***************************************************************************
 * Comparison and reporting.
 */
/* PSTATE bits ignored when comparing fault frames.  When native and DR frames
 * differ only in ignored bits, a64p_on_masked_pstate (if set) is called, so
 * that the test can count and report each masked difference.
 */
extern uint64_t a64p_fault_pstate_ignore;
extern void (*a64p_on_masked_pstate)(int i, fault_rec_t *n, fault_rec_t *d);

/* If set, called by the synchronous handler after it records fault n of a
 * run in the block, before it resumes: it may change the frame (e.g., to
 * perturb a register to test whether it is live).
 */
extern void (*a64p_fault_hook)(a64p_worker_t *w, int n, ucontext_t *uc);

int
a64p_cmp_fault(FILE *o, int i, fault_rec_t *n, fault_rec_t *d);

int
a64p_cmp_state(FILE *o, const char *what, cpu_state_t *n, cpu_state_t *d, int xres,
               uint64_t xadj, int vres, uint64_t vadj);

int
a64p_cmp_mem(FILE *o, block_t *b, result_t *n, result_t *d);

int
a64p_cmp_results(FILE *o, block_t *b, result_t *n, result_t *d);

void
a64p_print_faults(FILE *o, const char *who, result_t *r);

/* Faults the generator did not plan are generator bugs, not DR bugs; so are
 * more faults than a run can record.
 */
int
a64p_check_planned(block_t *b, result_t *r);

/***************************************************************************
 * Counts.  Every property reports how many cases were generated, accepted
 * (valid oracle), executed, independently checked, suppressed (compared
 * with a known-deviation mask that hid a difference) and inconclusive
 * (skipped for a reason other than a pass), and enforces floors on them.
 */
typedef struct {
    long generated, accepted, executed, checked, suppressed, inconclusive;
} a64p_counts_t;

void
a64p_counts_print(FILE *o, const char *label, const a64p_counts_t *c);

/* Reports and returns 1 if have < floor. */
int
a64p_floor(const char *label, const char *what, long have, long floor);

/***************************************************************************
 * Replay records: what a seed alone cannot reproduce (the raw words and
 * initial state from this generator version, the DR options and the host's
 * page size and features).  Written to stderr; with A64P_REPLAY_DIR set, the
 * data buffer and stack contents go to a file there too.
 */
void
a64p_print_replay(FILE *o, const char *prog, const char *mode, const variant_t *v,
                  block_t *b);

/* The data buffer and stack contents, as hex. */
void
a64p_print_replay_data(FILE *f, block_t *b);

/***************************************************************************
 * Signal frames and hashing.
 */
struct a64p_rec_head {
    uint32_t magic, size;
};
#define FPSIMD_MAGIC_ 0x46508001
#define ESR_MAGIC_ 0x45535201
#define EXTRA_MAGIC_ 0x45585401
struct a64p_fpsimd_rec {
    struct a64p_rec_head h;
    uint32_t fpsr, fpcr;
    __uint128_t v[32];
};
struct a64p_esr_rec {
    struct a64p_rec_head h;
    uint64_t esr;
};
struct a64p_extra_rec {
    struct a64p_rec_head h;
    uint64_t datap;
    uint32_t size;
};

struct a64p_rec_head *
a64p_find_rec(ucontext_t *uc, uint32_t magic);

uint64_t
a64p_hash_bytes(const void *p, size_t n, uint64_t h);

uint64_t
a64p_vhash(const __uint128_t *v, int vres);

/***************************************************************************
 * Native single-step tracing with ptrace.
 */
/* Returns the number of in-block steps, or -1 on failure/overflow. */
int
a64p_trace_block(a64p_worker_t *w, block_t *b, trace_t *t);

/* a64p_trace_run() flags. */
/* Record every instruction of the run, entry and exit stubs included, until
 * control returns to the trampoline (instead of [block_start, exit_start]).
 * Signal handlers (outside the code) are run but not recorded.
 */
#define A64P_TRACE_WHOLE_RUN 1
/* Also record the head of each exclusive retry loop (its state before the
 * exclusive load) before running to the loop's end: the step after the head
 * is then the instruction after the loop.  Only pc, sp, pstate and x[] are
 * filled in for the head.
 */
#define A64P_TRACE_EXCL_HEAD 2

/* Like a64p_trace_block() with flags A64P_TRACE_*. */
int
a64p_trace_run(a64p_worker_t *w, block_t *b, trace_t *t, int flags);

/***************************************************************************
 * Asynchronous signal sources: 0 itimer (SIGALRM), 1 POSIX timer
 * (SIGRTMIN+2, to the main thread), 2 another thread's tgkill (SIGUSR1).
 */
typedef struct {
    a64p_worker_t *w;
    int period_scale;
    timer_t posix_timer;
    int posix_timer_ok;
    volatile int helper_on, helper_ready;
    volatile int helper_spin_max;
    pid_t main_tid;
    pthread_t helper;
    uint64_t helper_seed;
} a64p_sigsrc_t;

void
a64p_sigsrc_init(a64p_sigsrc_t *s, a64p_worker_t *w);

/* Returns 0 (after reporting) if the source cannot be armed. */
int
a64p_sigsrc_arm(a64p_sigsrc_t *s, int src, rng_t *r);

void
a64p_sigsrc_disarm(a64p_sigsrc_t *s, int src);

/* Sets the helper's spin to roughly the block's duration. */
void
a64p_sigsrc_calibrate(a64p_sigsrc_t *s, block_t *b);

const char *
a64p_sigsrc_name(int src);

/***************************************************************************
 * DR and child processes.
 */
void
a64p_start_dr(const char *dr_ops);

void
a64p_stop_dr(void);

/* Shared with the parent for crash reports. */
#define A64P_NSTAT 32
typedef struct {
    volatile int block, run;
    volatile uint64_t seed;
    char phase[64];
    /* Counters the child reports to the parent (meaning set by the test). */
    volatile long stat[A64P_NSTAT];
} progress_t;
extern progress_t *a64p_prog;

/* Maps the shared progress page; prog_name is used in reproducer lines. */
void
a64p_progress_init(const char *prog_name);

/* Runs fn in a forked child; returns its failure count, reporting crashes. */
int
a64p_in_child(const char *mode, const variant_t *v, int (*fn)(void *), void *arg);

static inline uint64_t
a64p_xpacd(uint64_t v)
{
    register uint64_t x0 __asm__("x0") = v;
    __asm__ volatile(".inst 0xdac147e0" : "+r"(x0)); /* xpacd x0 */
    return x0;
}

/***************************************************************************
 * Additions for the signal ABI property (a64_prop_signal.c).
 */
/* Like a64p_in_child(), but kills the child after timeout_s seconds and
 * reports a hang (with the child's progress phase) instead of waiting forever.
 */
int
a64p_in_child_timeout(const char *mode, const variant_t *v, int (*fn)(void *), void *arg,
                      int timeout_s);

/* Independently validates the record list of a signal frame against the
 * kernel's AArch64 sigcontext ABI (arch/arm64/include/uapi/asm/sigcontext.h):
 * FPSIMD first and 528 bytes, every record 16-byte aligned with a size that is
 * a nonzero multiple of 16 and fits, sizes that match each known record's
 * contents (ESR, EXTRA, SVE/ZA for their vector lengths, TPIDR2, FPMR, ZT), no
 * duplicates, an EXTRA record pointing at 16-byte aligned space with its own
 * terminator, and a zero terminator.  Returns 0 if valid, else writes why to
 * err.  *layout gets a hash of the record kinds, sizes and vector lengths, and
 * *sve_vl / *za_vl the vector lengths of those records (-1 if absent).
 */
int
a64p_check_frame_records(const ucontext_t *uc, uint64_t *layout, int *sve_vl, int *za_vl,
                         char *err, size_t errlen);

#endif /* A64_PROP_SUPPORT_H */

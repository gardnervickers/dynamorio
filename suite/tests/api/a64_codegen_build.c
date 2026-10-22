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
 * Benchmarks and guards for building and running instrumented AArch64 blocks
 * under DR (suite/tests/a64_codegen/README.md).
 *
 * The test generates a chain of distinct blocks (pseudo-random ALU, flags,
 * load/store and move instructions on x1-x17 and a scratch area at x0, each
 * block ending in a CBNZ to the next), runs it natively for the expected
 * result, then in a child per configuration (a client mode and a set of DR
 * options) under static DR with this file's client:
 *
 *   build    the first run of a fresh copy of the chain, so DR builds every
 *            block: (time under DR - native time) per block and per
 *            application instruction.  Best of several copies, and every
 *            copy's, in order: a cost that grows with the size of the code
 *            cache makes later copies dearer.
 *   exec     repeated runs of a built copy: time per block, against native.
 *
 * Client modes:
 *   dr          no client events: DR's own decode, mangle and emit only
 *   bbhook      an empty drmgr insertion event, which makes DR fully decode
 *               every block and record translations
 *   progress    a charge point per block in the shape of Seedbox's progress
 *               client (client-interface/a64_progress_like.dll.c): drreg,
 *               raw TLS, SUB, TBZ, and a redirecting clean call to refill
 *   progress4   four charge points per block
 *   cleancall   a clean call to an empty function at the start of each block
 *   cleancall_ool  the same with DR_CLEANCALL_ALWAYS_OUT_OF_LINE: the whole
 *               context is saved and restored by DR's clean_call_{save,restore}
 *               routines, and the callee returns
 *
 * DR option sets:
 *   default     -disable_traces (traces would rebuild the hot chain)
 *   seedbox     Seedbox's options, as in the a64_smoke tests
 *   private     thread-private caches (-thread_private)
 *   traces      traces on, every block a trace head (with -scale only)
 *
 * Guards, in every configuration (failures fail the test):
 *   result      every run, native and under DR, leaves the same registers
 *               and scratch memory
 *   fragments   after a build, every block of the copy has a fragment, and
 *               DR's basic block count rose by at least the number of blocks
 *   size        the code-cache bytes of the chain's fragments
 *               (dr_fragment_size()) are within the budget for the
 *               configuration (budgets[] below), so a change that makes the
 *               generated code bigger has to update the budget; a change that
 *               makes it smaller is told it can lower it
 *   verbatim    on a copy built with a marker (the client stores each block's
 *               code-cache address to a table; all modes but dr), every
 *               application instruction
 *               of every block is in the fragment, bit for bit, at a
 *               code-cache address dr_app_pc_from_cache_pc() translates to
 *               its own application address
 *   provenance  (all modes but dr) emit puts what the IR says into the cache, not
 *               the app code it was decoded from, when the client changes an app
 *               instruction behind the decoder's back: it resets the instr and
 *               decodes it again, or destroys it and decodes into a new instr at
 *               the same address, while the app code holds another word (written
 *               through a second, writable mapping) that it puts back before the
 *               emit; and encoding a decoded B.EQ whose predicate the client set to
 *               NE gives B.NE
 *
 * Scaling mode (-scale N): instead of the above, each configuration builds N
 * distinct blocks, as -slice-sized chains run one after another, and reports
 * the cost per block of each -bucket of them: thread CPU time, and with a
 * KSTATS build of DR each phase of block building (read with dr_kstat_get()).
 * A cost that grows with the size of the code cache shows as a later bucket
 * dearer than the first; any metric whose last bucket costs more than -limit
 * times its first is flagged, and with -scale-guard a CPU cost that does so
 * fails the test.  -layout picks how the code is laid out (sparse: a
 * separate mapping per page, so DR tracks many regions; rwx: writable code,
 * as a JIT's; onemap: all chains in one mapping, as a JIT's code cache; hub:
 * every block also has an exit to one never-run block, which collects an
 * incoming link from each; reverse: blocks in reverse order, so each is a
 * trace head).  -flushes K makes the app invalidate one line in each of K
 * chains, from the newest to the oldest, after each bucket, as a JIT does
 * after changing code (IC IVAU under the seedbox options, which DR handles
 * itself; with hardware cache consistency, a write to writable code, or else
 * an mprotect), and reports the cost of each flush and how many blocks the
 * flushed chains and the bucket's then build again.
 *
 * Usage: api.a64_codegen_build [-blocks N] [-len N] [-reps N] [-runs N]
 *                              [-modes m1,m2,...] [-ops o1,o2,...|all]
 *                              [-scale N [-bucket N] [-slice N] [-limit X]
 *                               [-scale-guard] [-layout l1,l2,...]
 *                               [-flushes K]]
 * With A64_CODEGEN_TRACE set in the environment, each child reports its
 * phases on stderr.
 */

#include "configure.h"
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"

#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/***************************************************************************
 * Configurations
 */

enum {
    MODE_DR,
    MODE_BBHOOK,
    MODE_PROGRESS,
    MODE_PROGRESS4,
    MODE_CLEANCALL,
    MODE_CLEANCALL_OOL,
    NUM_MODES
};
static const char *const mode_names[NUM_MODES] = { "dr",        "bbhook",
                                                   "progress",  "progress4",
                                                   "cleancall", "cleancall_ool" };

enum { OPS_DEFAULT, OPS_SEEDBOX, OPS_PRIVATE, OPS_TRACES, NUM_OPS };
static const char *const ops_names[NUM_OPS] = { "default", "seedbox", "private",
                                                "traces" };
static const char *const ops_values[NUM_OPS] = {
    "-disable_traces",
    "-opt_speed -disable_traces -ldstex2cas -no_hw_cache_consistency -fake_ctr_dic",
    "-disable_traces -thread_private",
    /* Every block is a trace head (LAYOUT_REVERSE), and becomes a trace once it
     * passes -trace_threshold (50) runs.
     */
    "-enable_traces",
};
/* Runs of each chain in the scaling mode: enough to build the traces. */
static const int ops_scale_runs[NUM_OPS] = { 1, 1, 1, 52 };

/* Code-cache bytes per block of the default chain (DEFAULT_BLOCKS blocks of
 * DEFAULT_LEN instructions from DEFAULT_SEED), by option set and mode.  0 is no
 * budget.  Lower a budget when a change makes the code smaller; raise one only
 * for a deliberate increase.
 */
/* The clean-call modes include the queued-signal check that a5878f53c inserts
 * after every AArch64 clean call: 564 bytes per call (141 instructions, most of
 * them its slow path's inline save and restore of every register).  Without it
 * they would be 212.0, 470.1, 320.0 and 168.0.
 */
static const double budgets[NUM_OPS][NUM_MODES] = {
    /* dr, bbhook, progress, progress4, cleancall, cleancall_ool */
    { 124.0, 124.0, 772.0, 2710.1, 880.0, 728.0 }, /* default */
    { 124.0, 124.0, 772.0, 2710.1, 880.0, 728.0 }, /* seedbox */
    { 0, 0, 0, 0, 0, 0 },                          /* private */
    { 0, 0, 0, 0, 0, 0 },                          /* traces */
};

#define TESTANY(mask, var) (((mask) & (var)) != 0)

#define DEFAULT_BLOCKS 4000
#define DEFAULT_LEN 8
#define DEFAULT_SEED 0x5eedb0c5ULL
#define PROGRESS_BUDGET 50000 /* Seedbox's instructions per progress call. */

/* Layouts of a chain (-layout), which may be combined but for hub with sparse
 * or reverse.
 */
enum {
    /* A mapping of its own for each page of blocks, between inaccessible
     * pages, so DR tracks a region for each.
     */
    LAYOUT_SPARSE = 0x1,
    /* Writable code, as a JIT's. */
    LAYOUT_RWX = 0x2,
    /* Each block ends in a CBZ to a hub block that never runs, and falls
     * through to the next block: the hub's (future) fragment collects an
     * incoming link from every block.
     */
    LAYOUT_HUB = 0x4,
    /* The blocks are in reverse order, so each branches backward to the
     * next, which makes each a trace head.
     */
    LAYOUT_REVERSE = 0x8,
    /* All the chains in one mapping, as a JIT's code cache. */
    LAYOUT_ONEMAP = 0x10,
};
static const char *const layout_names[] = { "sparse", "rwx", "hub", "reverse", "onemap" };
#define NUM_LAYOUT_FLAGS (sizeof(layout_names) / sizeof(layout_names[0]))

/***************************************************************************
 * The chain of blocks
 */

/* Scratch area at x0: x1-x17 are loaded from and stored to words 0-16, and
 * blocks load and store words WORK_FIRST..WORK_LAST.
 */
#define NUM_DATA_REGS 17
#define WORK_FIRST 20
#define WORK_LAST 59
#define SCRATCH_WORDS 64

#define PAGE_WORDS 1024
#define ENTRY_WORDS (2 + NUM_DATA_REGS + 2)
#define EXIT_WORDS (NUM_DATA_REGS + 1)

typedef struct {
    uint32_t *code; /* The mapping. */
    size_t words;
    size_t map_bytes;
    int prot;
    uint32_t *first_block; /* The chain proper, blocks of stride words. */
    int blocks;
    int stride;
    /* Blocks are in regions of per_region blocks, region_words apart. */
    int per_region;
    size_t region_words;
    bool reverse;
    uint32_t *hub;
} chain_t;

static uint64_t
xorshift64(uint64_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

static uint
rnd(uint64_t *s, uint n)
{
    return (uint)(xorshift64(s) % n);
}

/* A data register, x1-x17. */
static uint
dreg(uint64_t *s)
{
    return 1 + rnd(s, NUM_DATA_REGS);
}

#define XZR 31
#define REG_BASE 0

static uint32_t
gen_body_instr(uint64_t *s)
{
    uint d = dreg(s), n = dreg(s), m = dreg(s), a = dreg(s);
    uint work = WORK_FIRST + rnd(s, WORK_LAST - WORK_FIRST);
    switch (rnd(s, 18)) {
    /* add, sub (immediate) */
    case 0: return 0x91000000 | rnd(s, 4096) << 10 | n << 5 | d;
    case 1: return 0xd1000000 | rnd(s, 4096) << 10 | n << 5 | d;
    /* add (shifted register, lsl #0-7), eor, orr, and, madd */
    case 2: return 0x8b000000 | m << 16 | rnd(s, 8) << 10 | n << 5 | d;
    case 3: return 0xca000000 | m << 16 | n << 5 | d;
    case 4: return 0xaa000000 | m << 16 | n << 5 | d;
    case 5: return 0x8a000000 | m << 16 | n << 5 | d;
    case 6: return 0x9b000000 | m << 16 | a << 10 | n << 5 | d;
    /* adds and cmp write the flags, csel reads them */
    case 7: return 0xab000000 | m << 16 | n << 5 | d;
    case 8: return 0xeb000000 | m << 16 | n << 5 | XZR;
    case 9: return 0x9a800000 | m << 16 | rnd(s, 14) << 12 | n << 5 | d;
    /* movz or movk, lslv */
    case 10:
        return (rnd(s, 2) ? 0xd2800000 : 0xf2800000) | rnd(s, 4) << 21 |
            rnd(s, 65536) << 5 | d;
    case 11: return 0x9ac02000 | m << 16 | n << 5 | d;
    /* ldr, str (unsigned offset) */
    case 12:
    case 13: return 0xf9400000 | work << 10 | REG_BASE << 5 | d;
    case 14:
    case 15: return 0xf9000000 | work << 10 | REG_BASE << 5 | d;
    /* ldp (of two different registers), stp */
    case 16:
        if (m == d)
            m = d % NUM_DATA_REGS + 1;
        return 0xa9400000 | work << 15 | m << 10 | REG_BASE << 5 | d;
    default: return 0xa9000000 | work << 15 | m << 10 | REG_BASE << 5 | d;
    }
}

#define BRK 0xd4200020
#define RET 0xd65f03c0

/* A branch at from to to: cbnz x0, cbz x0 (imm19) or b (imm26). */
static uint32_t
branch(uint32_t op, int bits, uint32_t *from, uint32_t *to)
{
    ptrdiff_t off = to - from;
    if (off >= (ptrdiff_t)1 << (bits - 1) || off < -((ptrdiff_t)1 << (bits - 1))) {
        fprintf(stderr, "branch out of range\n");
        exit(1);
    }
    uint32_t imm = (uint32_t)off & ((1u << bits) - 1);
    return bits == 26 ? op | imm : op | imm << 5 | REG_BASE;
}
#define CBNZ_X0(from, to) branch(0xb5000000, 19, from, to)
#define CBZ_X0(from, to) branch(0xb4000000, 19, from, to)
#define B(from, to) branch(0x14000000, 26, from, to)

/* The mapping that LAYOUT_ONEMAP chains are made in. */
static byte *arena;
static size_t arena_bytes, arena_used;

static void
arena_make(size_t bytes)
{
    arena_bytes = bytes;
    arena = mmap(NULL, bytes, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
}

static uint32_t *
block_at(const chain_t *c, int pos)
{
    return c->first_block + (size_t)(pos / c->per_region) * c->region_words +
        (size_t)(pos % c->per_region) * c->stride;
}

/* The chain: an entry block that sets the flags and loads x1-x17, the blocks,
 * and an exit block that stores x1-x17 and returns.  Every block ends in a
 * CBNZ on x0 (never zero) to the next, followed by a BRK for the
 * fall-through, which never runs (with LAYOUT_HUB, a CBZ on x0 to the hub, and
 * the fall-through is the next block).  Copies made from the same seed are the
 * same code at different addresses.  Without layout flags the chain is one
 * contiguous mapping: entry, blocks, exit.
 */
static void
chain_make(chain_t *c, int blocks, int len, uint64_t seed, uint layout)
{
    bool sparse = TESTANY(LAYOUT_SPARSE, layout), hub = TESTANY(LAYOUT_HUB, layout);
    c->blocks = blocks;
    c->stride = len + (hub ? 1 : 2);
    c->reverse = TESTANY(LAYOUT_REVERSE, layout);
    if (sparse) {
        c->per_region = PAGE_WORDS / c->stride;
        c->region_words = 2 * PAGE_WORDS;
    } else {
        c->per_region = blocks;
        c->region_words = (size_t)blocks * c->stride;
    }
    size_t regions = (blocks + c->per_region - 1) / c->per_region;
    /* The entry block, and the exit block in reverse order, come first; with
     * sparse, in a page of their own.
     */
    size_t head = sparse ? PAGE_WORDS : ENTRY_WORDS + (c->reverse ? EXIT_WORDS : 0);
    size_t body = sparse ? regions * c->region_words : (size_t)blocks * c->stride;
    c->words = head + body + (c->reverse ? 0 : EXIT_WORDS) + (hub ? 1 : 0);
    c->map_bytes = (c->words * 4 + 4095) & ~(size_t)4095;
    if (TESTANY(LAYOUT_ONEMAP, layout)) {
        if (arena_used + c->map_bytes > arena_bytes) {
            fprintf(stderr, "the chains do not fit in the arena\n");
            exit(1);
        }
        c->code = (uint32_t *)(arena + arena_used);
        arena_used += c->map_bytes;
        if (mprotect(c->code, c->map_bytes, PROT_READ | PROT_WRITE) != 0) {
            perror("mprotect");
            exit(1);
        }
    } else {
        c->code = mmap(NULL, c->map_bytes, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (c->code == MAP_FAILED) {
            perror("mmap");
            exit(1);
        }
    }
    for (size_t i = 0; i < c->words; i++)
        c->code[i] = BRK;
    c->first_block = c->code + head;
    uint32_t *exit_block = c->reverse ? c->code + ENTRY_WORDS : c->first_block + body;
    c->hub = hub ? exit_block + EXIT_WORDS : NULL;
    uint32_t *p = c->code;
    /* cmp x0, x0; ldr xr, [x0, #8*(r-1)] for x1-x17; nop; branch; brk */
    *p++ = 0xeb000000 | REG_BASE << 16 | REG_BASE << 5 | XZR;
    for (uint r = 1; r <= NUM_DATA_REGS; r++)
        *p++ = 0xf9400000 | (r - 1) << 10 | REG_BASE << 5 | r;
    *p++ = 0xd503201f;
    uint32_t *block0 = block_at(c, c->reverse ? blocks - 1 : 0);
    *p = c->reverse ? B(p, block0) : CBNZ_X0(p, block0);
    p++;
    *p++ = BRK;
    for (int b = 0; b < blocks; b++) {
        p = block_at(c, c->reverse ? blocks - 1 - b : b);
        for (int i = 0; i < len; i++)
            *p++ = gen_body_instr(&seed);
        uint32_t *next = b + 1 == blocks
            ? exit_block
            : block_at(c, c->reverse ? blocks - 2 - b : b + 1);
        if (hub) {
            if (next != p + 1) {
                fprintf(stderr, "hub layout needs each block to fall through\n");
                exit(1);
            }
            *p = CBZ_X0(p, c->hub);
        } else
            *p = CBNZ_X0(p, next);
    }
    /* str xr, [x0, #8*(r-1)] for x1-x17 */
    p = exit_block;
    for (uint r = 1; r <= NUM_DATA_REGS; r++)
        *p++ = 0xf9000000 | (r - 1) << 10 | REG_BASE << 5 | r;
    *p++ = RET;
    c->prot = PROT_READ | PROT_EXEC | (TESTANY(LAYOUT_RWX, layout) ? PROT_WRITE : 0);
    if (mprotect(c->code, c->map_bytes, c->prot) != 0) {
        perror("mprotect");
        exit(1);
    }
    /* Before the guard pages, which the cache maintenance cannot touch. */
    __builtin___clear_cache((char *)c->code, (char *)(c->code + c->words));
    for (size_t r = 0; sparse && r < regions; r++) {
        if (mprotect(c->first_block + r * c->region_words + PAGE_WORDS, PAGE_WORDS * 4,
                     PROT_NONE) != 0) {
            perror("mprotect");
            exit(1);
        }
    }
}

static uint64_t scratch_init[SCRATCH_WORDS];

static uint64_t
chain_run(chain_t *c)
{
    uint64_t scratch[SCRATCH_WORDS];
    memcpy(scratch, scratch_init, sizeof(scratch));
    ((void (*)(uint64_t *))c->code)(scratch);
    uint64_t h = 0xcbf29ce484222325ULL;
    for (int i = 0; i < SCRATCH_WORDS; i++)
        h = (h ^ scratch[i]) * 0x100000001b3ULL;
    return h;
}

static app_pc
block_tag(chain_t *c, int b)
{
    return (app_pc)block_at(c, c->reverse ? c->blocks - 1 - b : b);
}

static double
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + ts.tv_nsec;
}

static double
cpu_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return (double)ts.tv_sec * 1e9 + ts.tv_nsec;
}

/***************************************************************************
 * The provenance guard's code
 */

#define MOVZ_X0(imm) (0xd2800000 | (uint32_t)(imm) << 5) /* movz x0, #imm */
#define CMP_X0_X0 0xeb00001f                             /* cmp x0, x0 */
#define B_EQ_12 0x54000060                               /* b.eq pc+12 */
#define B_NE_12 0x54000061                               /* b.ne pc+12 */

/* Functions in a page mapped twice: run at prov_x, written through prov_w, as a
 * JIT may.  PROV_REDECODE and PROV_REUSE return 1 natively.  The client makes their
 * first instruction MOVZ_X0(2) in the IR, with the app code holding MOVZ_X0(1)
 * again by the emit, so they return 2 under DR.  PROV_PRED returns 2 (its B.EQ is
 * taken) natively and under DR.
 */
enum { PROV_REDECODE = 0, PROV_REUSE = 4, PROV_PRED = 8, PROV_WORDS = 14 };
static const uint32_t prov_code[PROV_WORDS] = {
    MOVZ_X0(1), RET,     0,          0,   /* PROV_REDECODE */
    MOVZ_X0(1), RET,     0,          0,   /* PROV_REUSE */
    CMP_X0_X0,  B_EQ_12, MOVZ_X0(1), RET, /* PROV_PRED */
    MOVZ_X0(2), RET,
};
static uint32_t *volatile prov_x, *prov_w;
/* What the client saw: whether it got the destroyed instr's memory back, and what
 * the B.NE encoded to.
 */
static volatile bool prov_reused;
static volatile uint32_t prov_pred_word;

static void
prov_make(void)
{
    int fd = (int)syscall(SYS_memfd_create, "a64_codegen_prov", 0);
    if (fd < 0 || ftruncate(fd, 4096) != 0) {
        perror("memfd");
        exit(1);
    }
    prov_w = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    uint32_t *x = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (prov_w == MAP_FAILED || x == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    close(fd);
    memcpy(prov_w, prov_code, sizeof(prov_code));
    __builtin___clear_cache((char *)x, (char *)(x + PROV_WORDS));
    prov_x = x;
}

static uint64_t
prov_run(int fn)
{
    return ((uint64_t (*)(void))(prov_x + fn))();
}

/***************************************************************************
 * The client
 */

static int client_mode;
static reg_id_t tls_seg;
static uint tls_offs;

/* The marker: once marker_chain is set, its blocks are instrumented with code
 * that stores their code-cache address to marker_table[block].
 */
static chain_t *volatile marker_chain;
static app_pc *marker_table;

static ptr_int_t *
budget_slot(void)
{
    return (ptr_int_t *)((byte *)dr_get_dr_segment_base(tls_seg) + tls_offs);
}

static void
refill_and_resume(app_pc resume, ptr_int_t charged)
{
    ptr_int_t *left = budget_slot();
    do
        *left += PROGRESS_BUDGET;
    while (*left < 0);
    *left += charged;
    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    DR_ASSERT(dr_get_mcontext(dr_get_current_drcontext(), &mc));
    mc.pc = resume;
    dr_redirect_execution(&mc);
    DR_ASSERT_MSG(false, "dr_redirect_execution returned");
}

static void
empty_callee(void)
{
}

static void
event_thread_init(void *drcontext)
{
    *budget_slot() = PROGRESS_BUDGET;
}

static void
reserve(void *drcontext, instrlist_t *bb, instr_t *where, reg_id_t *reg)
{
    if (drreg_reserve_register(drcontext, bb, where, NULL, reg) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drreg_reserve_register failed");
}

static void
unreserve(void *drcontext, instrlist_t *bb, instr_t *where, reg_id_t reg)
{
    if (drreg_unreserve_register(drcontext, bb, where, reg) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drreg_unreserve_register failed");
}

/* As a64_progress_like.dll.c's insert_charge(). */
static void
insert_charge(void *drcontext, instrlist_t *bb, instr_t *where, uint count)
{
    instr_t *skip = INSTR_CREATE_label(drcontext);
    reg_id_t scratch;
    reserve(drcontext, bb, where, &scratch);
    dr_insert_read_raw_tls(drcontext, bb, where, tls_seg, tls_offs, scratch);
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_sub(drcontext, opnd_create_reg(scratch),
                                              opnd_create_reg(scratch),
                                              OPND_CREATE_INT(count)));
    dr_insert_write_raw_tls(drcontext, bb, where, tls_seg, tls_offs, scratch);
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_tbz(drcontext, opnd_create_instr(skip),
                                              opnd_create_reg(scratch),
                                              OPND_CREATE_INT(63)));
    dr_insert_clean_call_ex(drcontext, bb, where, (void *)refill_and_resume,
                            DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_MULTIPATH, 2,
                            OPND_CREATE_INTPTR((ptr_int_t)instr_get_app_pc(where)),
                            OPND_CREATE_INTPTR((ptr_int_t)count));
    instrlist_meta_preinsert(bb, where, skip);
    if (drreg_get_app_value(drcontext, bb, where, scratch, scratch) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drreg_get_app_value failed");
    unreserve(drcontext, bb, where, scratch);
}

/* Stores the code-cache address of the code inserted here to *slot. */
static void
insert_marker(void *drcontext, instrlist_t *bb, instr_t *where, app_pc *slot)
{
    instr_t *here = INSTR_CREATE_label(drcontext);
    reg_id_t pc_reg, slot_reg;
    instrlist_meta_preinsert(bb, where, here);
    reserve(drcontext, bb, where, &pc_reg);
    reserve(drcontext, bb, where, &slot_reg);
    instrlist_meta_preinsert(
        bb, where,
        INSTR_CREATE_adr(drcontext, opnd_create_reg(pc_reg), opnd_create_instr(here)));
    instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)slot,
                                     opnd_create_reg(slot_reg), bb, where, NULL, NULL);
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_str(drcontext, OPND_CREATE_MEMPTR(slot_reg, 0),
                                              opnd_create_reg(pc_reg)));
    unreserve(drcontext, bb, where, slot_reg);
    unreserve(drcontext, bb, where, pc_reg);
}

/* The block index of a tag in the marker chain, or -1. */
static int
marker_block(app_pc tag)
{
    chain_t *c = marker_chain;
    if (c == NULL || (uint32_t *)tag < c->first_block)
        return -1;
    size_t off = (uint32_t *)tag - c->first_block;
    size_t within = off % c->region_words;
    if (within % c->stride != 0 || within / c->stride >= (size_t)c->per_region)
        return -1;
    size_t pos = off / c->region_words * c->per_region + within / c->stride;
    if (pos >= (size_t)c->blocks)
        return -1;
    return (int)(c->reverse ? c->blocks - 1 - pos : pos);
}

/* The provenance guard's PROV_REDECODE and PROV_REUSE (see prov_code[]): makes
 * the block's first instruction MOVZ_X0(2) in the IR, decoded from the app code,
 * which holds MOVZ_X0(1) before and after.
 */
static void
prov_redecode(void *drcontext, instrlist_t *bb, int fn, bool reuse)
{
    instr_t *in = instrlist_first_app(bb);
    app_pc pc = instr_get_app_pc(in);
    DR_ASSERT(pc == (app_pc)(prov_x + fn));
    instr_t *next = instr_get_next(in);
    instrlist_remove(bb, in);
    prov_w[fn] = MOVZ_X0(2);
    if (reuse) {
        /* Destroy it, then make instrs until one gets its memory. */
        uintptr_t old = (uintptr_t)in;
        instr_t *spare[16];
        int n = 0;
        instr_destroy(drcontext, in);
        in = instr_create(drcontext);
        while ((uintptr_t)in != old && n < 16) {
            spare[n++] = in;
            in = instr_create(drcontext);
        }
        prov_reused = (uintptr_t)in == old;
        while (n > 0)
            instr_destroy(drcontext, spare[--n]);
    } else
        instr_reset(drcontext, in);
    if (decode(drcontext, pc, in) == NULL)
        DR_ASSERT_MSG(false, "decode failed");
    instr_set_translation(in, pc);
    prov_w[fn] = MOVZ_X0(1);
    instrlist_preinsert(bb, next, in);
}

/* The provenance guard's PROV_PRED: encodes its B.EQ with the predicate NE. */
static void
prov_predicate(void *drcontext, instrlist_t *bb)
{
    for (instr_t *in = instrlist_first_app(bb); in != NULL; in = instr_get_next_app(in)) {
        if (instr_get_opcode(in) != OP_bcond)
            continue;
        uint32_t word = 0;
        instr_set_predicate(in, DR_PRED_NE);
        byte *end =
            instr_encode_to_copy(drcontext, in, (byte *)&word, instr_get_app_pc(in));
        prov_pred_word = end == (byte *)&word + 4 ? word : 0;
        instr_set_predicate(in, DR_PRED_EQ);
    }
}

static dr_emit_flags_t
event_app2app(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
              bool translating)
{
    uint32_t *x = prov_x;
    if (x == NULL)
        return DR_EMIT_DEFAULT;
    if (tag == (void *)(x + PROV_REDECODE))
        prov_redecode(drcontext, bb, PROV_REDECODE, false);
    else if (tag == (void *)(x + PROV_REUSE))
        prov_redecode(drcontext, bb, PROV_REUSE, true);
    else if (tag == (void *)(x + PROV_PRED))
        prov_predicate(drcontext, bb);
    return DR_EMIT_DEFAULT;
}

typedef struct {
    uint length, points, index, next;
} plan_t;

static uint
point_start(const plan_t *plan, uint point)
{
    return (uint)((uint64)point * plan->length / plan->points);
}

static dr_emit_flags_t
event_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
               bool translating, void **user_data)
{
    plan_t *plan = dr_thread_alloc(drcontext, sizeof(*plan));
    plan->length = 0;
    for (instr_t *in = instrlist_first_app(bb); in != NULL; in = instr_get_next_app(in))
        plan->length++;
    uint want = client_mode == MODE_PROGRESS4 ? 4 : client_mode == MODE_PROGRESS ? 1 : 0;
    plan->points = plan->length < want ? plan->length : want;
    plan->index = 0;
    plan->next = 0;
    *user_data = plan;
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_insertion(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                bool for_trace, bool translating, void *user_data)
{
    plan_t *plan = user_data;
    if (instr_is_app(inst)) {
        if (plan->index == 0) {
            int b = marker_block(tag);
            if (b >= 0)
                insert_marker(drcontext, bb, inst, &marker_table[b]);
            if (client_mode == MODE_CLEANCALL)
                dr_insert_clean_call(drcontext, bb, inst, (void *)empty_callee, false, 0);
            else if (client_mode == MODE_CLEANCALL_OOL) {
                dr_insert_clean_call_ex(drcontext, bb, inst, (void *)empty_callee,
                                        DR_CLEANCALL_ALWAYS_OUT_OF_LINE, 0);
            }
        }
        if (plan->next < plan->points && plan->index == point_start(plan, plan->next)) {
            plan->next++;
            insert_charge(drcontext, bb, inst,
                          point_start(plan, plan->next) - plan->index);
        }
        plan->index++;
    }
    if (drmgr_is_last_instr(drcontext, inst))
        dr_thread_free(drcontext, plan, sizeof(*plan));
    return DR_EMIT_DEFAULT;
}

static void
event_exit(void)
{
    dr_raw_tls_cfree(tls_offs, 1);
    drreg_exit();
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    if (client_mode == MODE_DR)
        return;
    drreg_options_t ops = { sizeof(ops), 3, true };
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drmgr/drreg init failed");
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, 1, 0))
        DR_ASSERT_MSG(false, "dr_raw_tls_calloc failed");
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_bb_app2app_event(event_app2app, NULL) ||
        !drmgr_register_bb_instrumentation_event(event_analysis, event_insertion, NULL))
        DR_ASSERT_MSG(false, "event registration failed");
    dr_register_exit_event(event_exit);
}

/***************************************************************************
 * The test
 */

static int num_blocks = DEFAULT_BLOCKS, block_len = DEFAULT_LEN, reps = 5, runs = 200;
static bool default_chain;
static uint64_t expected_hash;
static double native_ns_per_block;
static uint64_t failures;

/* The scaling mode (-scale). */
static int scale_blocks, slice_blocks = 10000, bucket_blocks;
static double scale_limit = 1.5;
static bool scale_guard;
static uint scale_layout;
static int scale_flushes;

#define FAIL(...)                                  \
    do {                                           \
        failures++;                                \
        printf("FAIL %s/%s: ", cfg_ops, cfg_mode); \
        printf(__VA_ARGS__);                       \
        printf("\n");                              \
    } while (0)

static const char *cfg_ops, *cfg_mode;

#define TRACE(what)                                \
    do {                                           \
        if (getenv("A64_CODEGEN_TRACE") != NULL) { \
            fprintf(stderr, "trace: %s\n", what);  \
            fflush(stderr);                        \
        }                                          \
    } while (0)

static void
check_result(chain_t *c, uint64_t h, const char *what)
{
    if (h != expected_hash)
        FAIL("%s: result %016llx, expected %016llx", what, (unsigned long long)h,
             (unsigned long long)expected_hash);
}

static uint64
bbs_built(void)
{
    dr_stats_t stats = { sizeof(dr_stats_t) };
    if (!dr_get_stats(&stats))
        return 0;
    return stats.basic_block_count;
}

/* Sum of the fragment sizes of c's blocks, checking they all exist. */
static size_t
fragment_bytes(chain_t *c)
{
    void *drcontext = dr_get_current_drcontext();
    size_t sum = 0;
    int missing = 0;
    for (int b = 0; b < c->blocks; b++) {
        if (!dr_fragment_exists_at(drcontext, block_tag(c, b))) {
            missing++;
            continue;
        }
        sum += dr_fragment_size(drcontext, block_tag(c, b));
    }
    if (missing > 0)
        FAIL("%d of %d blocks have no fragment after a run", missing, c->blocks);
    return sum;
}

/* The provenance guard, run under DR. */
static void
check_provenance(void)
{
    uint64_t r = prov_run(PROV_REDECODE);
    if (r != 2) {
        FAIL("a reset and decoded again instr: the block returned %llu, not 2: emit "
             "copied the app code it was first decoded from",
             (unsigned long long)r);
    }
    r = prov_run(PROV_REUSE);
    if (!prov_reused)
        FAIL("the allocator did not give a destroyed instr's memory to a new one");
    else if (r != 2) {
        FAIL("a new instr in a destroyed one's memory: the block returned %llu, not "
             "2: emit copied the app code the old instr was decoded from",
             (unsigned long long)r);
    }
    r = prov_run(PROV_PRED);
    if (r != 2)
        FAIL("the B.EQ block returned %llu, not 2", (unsigned long long)r);
    if (prov_pred_word != B_NE_12) {
        FAIL("a decoded B.EQ with the predicate set to NE encoded to %08x, not %08x",
             prov_pred_word, B_NE_12);
    }
}

/* The verbatim guard, on a chain built with the marker. */
static void
check_verbatim(chain_t *c)
{
    void *drcontext = dr_get_current_drcontext();
    int reported = 0;
    for (int b = 0; b < c->blocks && reported < 10; b++) {
        app_pc tag = block_tag(c, b);
        byte *cache = marker_table[b];
        if (cache == NULL) {
            FAIL("block %d did not run its marker", b);
            reported++;
            continue;
        }
        /* The marker is at the start of the block's instrumentation, so its
         * application instructions follow it in the fragment.
         */
        byte *end = cache + dr_fragment_size(drcontext, tag);
        byte *cp = cache;
        for (int i = 0; i < block_len; i++) {
            app_pc pc = tag + 4 * i;
            uint32_t want = *(uint32_t *)pc;
            while (cp < end &&
                   (*(uint32_t *)cp != want || dr_app_pc_from_cache_pc(cp) != pc))
                cp += 4;
            if (cp >= end) {
                FAIL("block %d (tag %p, cache %p): instruction %d (%08x) is not in the "
                     "fragment verbatim at a code-cache address translating to %p",
                     b, tag, cache, i, want, pc);
                reported++;
                break;
            }
            cp += 4;
        }
    }
}

static int
cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

static double
median(const double *v, int n)
{
    double *s = malloc(n * sizeof(*s));
    memcpy(s, v, n * sizeof(*s));
    qsort(s, n, sizeof(*s), cmp_double);
    double m = n % 2 == 1 ? s[n / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
    free(s);
    return m;
}

/* Starts DR with the configuration's options plus extra; returns the thread's
 * drcontext, or NULL.
 */
static void *
start_dr(int ops, const char *extra)
{
    char buf[1024];
    const char *base = getenv("DYNAMORIO_OPTIONS");
    snprintf(buf, sizeof(buf), "%s %s %s", base == NULL ? "" : base, ops_values[ops],
             extra);
    setenv("DYNAMORIO_OPTIONS", buf, 1);
    if (dr_app_setup() != 0) {
        FAIL("could not set up DR");
        return NULL;
    }
    void *drcontext = dr_get_current_drcontext();
    dr_app_start();
    if (!dr_app_running_under_dynamorio()) {
        FAIL("could not start DR");
        return NULL;
    }
    return drcontext;
}

static int
child(int mode, int ops)
{
    cfg_mode = mode_names[mode];
    cfg_ops = ops_names[ops];
    client_mode = mode;
    /* The chains are made before DR starts, as code the app had loaded. */
    chain_t *build = malloc(reps * sizeof(*build));
    for (int r = 0; r < reps; r++)
        chain_make(&build[r], num_blocks, block_len, DEFAULT_SEED, 0);
    chain_t marked;
    chain_make(&marked, num_blocks, block_len, DEFAULT_SEED, 0);
    marker_table = calloc(num_blocks, sizeof(*marker_table));
    if (mode != MODE_DR)
        prov_make();

    if (start_dr(ops, "") == NULL)
        return 1;

    /* build: the first run of each fresh copy. */
    TRACE("started");
    double *build_t = malloc(reps * sizeof(*build_t));
    for (int r = 0; r < reps; r++) {
        uint64 before = bbs_built();
        double t = now_ns();
        uint64_t h = chain_run(&build[r]);
        t = now_ns() - t;
        check_result(&build[r], h, "first run");
        uint64 built = bbs_built() - before;
        if (built < (uint64)num_blocks)
            FAIL("a first run built %llu blocks, fewer than the chain's %d",
                 (unsigned long long)built, num_blocks);
        build_t[r] = t / num_blocks - native_ns_per_block;
    }
    TRACE("built");
    /* exec: runs of a built copy. */
    double best_exec = 1e300;
    for (int k = 0; k < 3; k++) {
        double t = now_ns();
        uint64_t h = 0;
        for (int i = 0; i < runs; i++)
            h |= chain_run(&build[0]) ^ expected_hash;
        t = now_ns() - t;
        if (h != 0)
            FAIL("a run of a built copy gave a wrong result");
        if (t < best_exec)
            best_exec = t;
    }
    TRACE("executed");
    /* verbatim: a copy built with the marker, which needs client events. */
    if (mode != MODE_DR) {
        /* Left set: translation instruments the blocks again, and must see
         * the same marker.
         */
        marker_chain = &marked;
        check_result(&marked, chain_run(&marked), "marked run");
        check_provenance();
    }

    /* The fragment queries take DR locks, so they are made with the thread
     * native: under DR, this (static) DR's own code would run from the code
     * cache, and building its next block would wait for a lock it holds.  The
     * fragments stay until the cleanup.
     */
    dr_app_stop();
    TRACE("stopped");
    size_t bytes = 0;
    for (int r = 0; r < reps; r++) {
        size_t b = fragment_bytes(&build[r]);
        if (r > 0 && b != bytes)
            FAIL("copy %d has %zu code-cache bytes, copy 0 has %zu", r, b, bytes);
        bytes = b;
    }
    if (mode != MODE_DR)
        check_verbatim(&marked);
    TRACE("checked");
    dr_app_cleanup();

    double best_build = build_t[0];
    for (int r = 1; r < reps; r++) {
        if (build_t[r] < best_build)
            best_build = build_t[r];
    }
    double exec_ns = best_exec / ((double)runs * num_blocks);
    double per_block = (double)bytes / num_blocks;
    /* Every copy's cost, in order: a cost that grows with the code cache makes
     * each copy dearer than the one before, which the best hides.
     */
    printf("build %-9s %-7s %9.0f ns/block %7.0f ns/instr; first %.0f median %.0f last "
           "%.0f; reps",
           cfg_mode, cfg_ops, best_build, best_build / block_len, build_t[0],
           median(build_t, reps), build_t[reps - 1]);
    for (int r = 0; r < reps; r++)
        printf(" %.0f", build_t[r]);
    printf("\n");
    if (reps > 1 && build_t[reps - 1] > scale_limit * build_t[0]) {
        printf("note %s/%s: the last copy's build cost %.0f ns/block is over %.1fx the "
               "first's %.0f: run with -scale to see whether it grows with the cache\n",
               cfg_ops, cfg_mode, build_t[reps - 1], scale_limit, build_t[0]);
    }
    printf("exec  %-9s %-7s %9.2f ns/block (%.1fx native)\n", cfg_mode, cfg_ops, exec_ns,
           exec_ns / native_ns_per_block);
    printf("size  %-9s %-7s %9.1f bytes/block", cfg_mode, cfg_ops, per_block);
    double budget = default_chain ? budgets[ops][mode] : 0;
    if (budget > 0) {
        printf(" (budget %.1f)\n", budget);
        if (per_block > budget + 0.05) {
            FAIL("%.1f code-cache bytes per block is over the budget of %.1f: if the "
                 "increase is deliberate, raise budgets[] in %s",
                 per_block, budget, __FILE__);
        } else if (per_block < budget - 0.05) {
            printf("note %s/%s: %.1f bytes/block is under the budget of %.1f: lower "
                   "budgets[] to lock in the gain\n",
                   cfg_ops, cfg_mode, per_block, budget);
        }
    } else
        printf("\n");
    fflush(stdout);
    return failures > 0 ? 1 : 0;
}

/***************************************************************************
 * The scaling mode
 */

/* In a KSTATS build of DR (core/stats.c), the calling thread's totals for a
 * kstat; absent otherwise.
 */
extern bool
dr_kstat_get(void *drcontext, const char *name, uint64 *count, uint64 *ticks,
             uint64 *ticks_per_ms) __attribute__((weak));

/* The kstats reported, all within bb_building but the last three, and
 * trace_building, which is beside it.  "other" is the CPU time outside
 * bb_building: dispatch, linking a block in, the context switches.
 */
static const char *const phase_names[] = {
    "bb_building", "bb_decoding",    "bb_client",    "mangling",      "emit",
    "trace_building", "flush_region", "synchall_flush",
};
#define NUM_PHASES (sizeof(phase_names) / sizeof(phase_names[0]))
#define PHASE_BB_BUILDING 0
#define PHASE_FLUSH 6
#define PHASE_SYNCHALL 7
static const char *const phase_short[NUM_PHASES] = {
    "bb", "decode", "client", "mangle", "emit", "trace", "flush", "synchall",
};

typedef struct {
    double cpu, wall;
    uint64 ticks[NUM_PHASES];
} snap_t;

static void *scale_drcontext;
static bool have_kstats;
static uint64 ticks_per_ms;

static void
take_snap(snap_t *s)
{
    s->wall = now_ns();
    s->cpu = cpu_ns();
    for (uint p = 0; have_kstats && p < NUM_PHASES; p++) {
        if (!dr_kstat_get(scale_drcontext, phase_names[p], NULL, &s->ticks[p], NULL))
            s->ticks[p] = 0;
    }
}

/* The costs of one slice or flush. */
typedef struct {
    double cpu, wall; /* ns */
    double ticks[NUM_PHASES];
} cost_t;

static void
snap_diff(const snap_t *a, const snap_t *b, double per, cost_t *c)
{
    c->cpu = (b->cpu - a->cpu) / per;
    c->wall = (b->wall - a->wall) / per;
    for (uint p = 0; p < NUM_PHASES; p++)
        c->ticks[p] = (double)(b->ticks[p] - a->ticks[p]) / per;
}

/* dc cvau, x0; dsb ish; ic ivau, x0; dsb ish; isb; ret: what a JIT does after
 * writing code at x0, and which DR handles itself without
 * -hw_cache_consistency.
 */
static void (*icache_sync)(void *);

static void
make_icache_sync(void)
{
    static const uint32_t code[] = { 0xd50b7b20, 0xd5033b9f, 0xd50b7520,
                                     0xd5033b9f, 0xd5033fdf, RET };
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
                   0);
    if (p == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    memcpy(p, code, sizeof(code));
    if (mprotect(p, 4096, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        exit(1);
    }
    __builtin___clear_cache((char *)p, (char *)p + sizeof(code));
    icache_sync = (void (*)(void *))p;
}

/* Makes DR flush the code at pc as an app would after changing it. */
static void
flush_line(chain_t *c, app_pc pc, int ops)
{
    if (ops == OPS_SEEDBOX) {
        icache_sync(pc);
        return;
    }
    /* With hardware cache consistency, DR makes writable code read-only and is
     * told of a write by its fault.
     */
    if (TESTANY(PROT_WRITE, c->prot)) {
        *(volatile uint32_t *)pc = *(uint32_t *)pc;
        icache_sync(pc);
        return;
    }
    /* Read-only code: the app changes its protection to write it. */
    void *page = (void *)((ptr_uint_t)pc & ~(ptr_uint_t)4095);
    if (mprotect(page, 4096, c->prot & ~PROT_EXEC) != 0 ||
        mprotect(page, 4096, c->prot) != 0)
        FAIL("mprotect for a flush failed");
}

/* Removes the directory path and what is in it. */
static void
remove_tree(const char *path)
{
    DIR *dir = opendir(path);
    if (dir != NULL) {
        struct dirent *e;
        while ((e = readdir(dir)) != NULL) {
            char sub[1024];
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
            if (e->d_type == DT_DIR)
                remove_tree(sub);
            else
                unlink(sub);
        }
        closedir(dir);
    }
    rmdir(path);
}

static void
print_cost(const char *what, double cpu, const double *ticks, double ns_per_tick)
{
    printf("%s cpu %7.0f", what, cpu);
    if (!have_kstats) {
        printf("\n");
        return;
    }
    printf(" |");
    for (uint p = 0; p < NUM_PHASES; p++) {
        if (p == PHASE_FLUSH || p == PHASE_SYNCHALL)
            continue;
        printf(" %s %.1f", phase_short[p], ticks[p]);
    }
    printf(" | other %.0f\n", cpu - ticks[PHASE_BB_BUILDING] * ns_per_tick);
}

/* Reports whether late is over the limit times early, by more than floor. */
static bool
grows(const char *what, double early, double late, double floor, bool *any)
{
    if (late > scale_limit * early && late - early > floor) {
        printf("scale %s/%s: GROWS: %s %.1f -> %.1f per block (%.2fx)\n", cfg_ops,
               cfg_mode, what, early, late, late / early);
        *any = true;
        return true;
    }
    return false;
}

static int
scale_child(int mode, int ops)
{
    cfg_mode = mode_names[mode];
    cfg_ops = ops_names[ops];
    client_mode = mode;
    uint layout = scale_layout | (ops == OPS_TRACES ? LAYOUT_REVERSE : 0);
    int slices = scale_blocks / slice_blocks;
    int per_bucket = bucket_blocks / slice_blocks;
    int buckets = slices / per_bucket;
    int runs_per_slice = ops_scale_runs[ops];
    /* The chains are made before DR starts, as code the app had loaded. */
    chain_t *ch = malloc(slices * sizeof(*ch));
    if (TESTANY(LAYOUT_ONEMAP, layout)) {
        chain_t probe;
        chain_make(&probe, slice_blocks, block_len, DEFAULT_SEED, layout & ~LAYOUT_ONEMAP);
        munmap(probe.code, probe.map_bytes);
        arena_make(probe.map_bytes * slices);
    }
    for (int i = 0; i < slices; i++)
        chain_make(&ch[i], slice_blocks, block_len, DEFAULT_SEED, layout);
    make_icache_sync();

    char extra[512] = "";
    char logdir[] = "/tmp/a64_codegen_kstats.XXXXXX";
    have_kstats = dr_kstat_get != NULL;
    if (have_kstats) {
        if (mkdtemp(logdir) == NULL) {
            perror("mkdtemp");
            have_kstats = false;
        } else
            snprintf(extra, sizeof(extra), "-kstats -logdir %s", logdir);
    }
    scale_drcontext = start_dr(ops, extra);
    if (scale_drcontext == NULL)
        return 1;
    if (have_kstats &&
        !dr_kstat_get(scale_drcontext, "bb_building", NULL, NULL, &ticks_per_ms))
        have_kstats = false;
    double ns_per_tick = have_kstats ? 1e6 / ticks_per_ms : 0;

    printf("scale %s/%s: %d blocks in buckets of %d, chains of %d, layout", cfg_ops,
           cfg_mode, slices * slice_blocks, bucket_blocks, slice_blocks);
    for (uint f = 0; f < NUM_LAYOUT_FLAGS; f++) {
        if (TESTANY(1u << f, layout))
            printf(" %s", layout_names[f]);
    }
    printf("%s; ns per block", layout == 0 ? " contiguous" : "");
    if (have_kstats) {
        printf(", and KSTATS ticks per block (%.1f ns each; bb includes the next 4)",
               ns_per_tick);
    }
    printf("\n");
    fflush(stdout);

    cost_t *slice_cost = calloc(slices, sizeof(*slice_cost));
    double *slice_cpu = calloc(slices, sizeof(*slice_cpu));
    cost_t *bucket_cost = calloc(buckets, sizeof(*bucket_cost));
    double *bucket_median = calloc(buckets, sizeof(*bucket_median));
    double *flush_cpu = calloc(buckets, sizeof(*flush_cpu));
    double *flush_ticks = calloc(buckets, sizeof(*flush_ticks));
    int flushes = scale_flushes < per_bucket ? scale_flushes : per_bucket;
    int *flushed = calloc(flushes > 0 ? flushes : 1, sizeof(*flushed));
    for (int k = 0; k < buckets; k++) {
        for (int i = k * per_bucket; i < (k + 1) * per_bucket; i++) {
            uint64 before = bbs_built();
            snap_t a, b;
            uint64_t h = 0;
            take_snap(&a);
            for (int r = 0; r < runs_per_slice; r++)
                h |= chain_run(&ch[i]) ^ expected_hash;
            take_snap(&b);
            if (h != 0)
                FAIL("chain %d gave a wrong result", i);
            uint64 built = bbs_built() - before;
            if (built < (uint64)slice_blocks)
                FAIL("chain %d built %llu blocks, fewer than its %d", i,
                     (unsigned long long)built, slice_blocks);
            snap_diff(&a, &b, slice_blocks, &slice_cost[i]);
            slice_cpu[i] = slice_cost[i].cpu;
            bucket_cost[k].cpu += slice_cost[i].cpu / per_bucket;
            for (uint p = 0; p < NUM_PHASES; p++)
                bucket_cost[k].ticks[p] += slice_cost[i].ticks[p] / per_bucket;
        }
        bucket_median[k] = median(&slice_cpu[k * per_bucket], per_bucket);
        /* Flushes of a line in each of chains spread from the newest to the oldest
         * (blocks of different ages are at different places in lists such as a
         * hub's incoming links).
         */
        int built_chains = (k + 1) * per_bucket;
        for (int j = 0; j < flushes; j++) {
            flushed[j] = built_chains - 1 - (int)((int64)j * built_chains / flushes);
            chain_t *c = &ch[flushed[j]];
            snap_t a, b;
            cost_t f;
            take_snap(&a);
            flush_line(c, block_tag(c, (k * 7919 + j * 104729) % slice_blocks), ops);
            take_snap(&b);
            snap_diff(&a, &b, flushes, &f);
            flush_cpu[k] += f.cpu;
            flush_ticks[k] += f.ticks[PHASE_FLUSH];
        }
        /* How much each flush took with it: the blocks that the flushed chains and
         * the bucket's build again, and what that costs.
         */
        double rebuilt = 0, rebuild_cpu = 0;
        for (int n = 0; flushes > 0 && n < per_bucket + flushes; n++) {
            int i = n < per_bucket ? k * per_bucket + n : flushed[n - per_bucket];
            if (n >= per_bucket && i >= k * per_bucket)
                continue; /* in the bucket */
            uint64 before = bbs_built();
            double t = cpu_ns();
            check_result(&ch[i], chain_run(&ch[i]), "a run after a flush");
            rebuild_cpu += cpu_ns() - t;
            rebuilt += bbs_built() - before;
        }
        char what[128];
        snprintf(what, sizeof(what), "scale %s/%s: bucket %2d (%7d blocks): median",
                 cfg_ops, cfg_mode, k, (k + 1) * bucket_blocks);
        printf("%s %7.0f", what, bucket_median[k]);
        print_cost(" mean", bucket_cost[k].cpu, bucket_cost[k].ticks, ns_per_tick);
        if (flushes > 0) {
            printf("scale %s/%s: bucket %2d flush: %.1f us per flush", cfg_ops, cfg_mode,
                   k, flush_cpu[k] / 1000);
            if (have_kstats)
                printf(", flush_region %.0f ticks", flush_ticks[k]);
            printf("; the flushed and the bucket's chains then rebuild %.0f blocks per "
                   "flush, at %.0f ns each\n",
                   rebuilt / flushes, rebuilt > 0 ? rebuild_cpu / rebuilt : 0);
        }
        fflush(stdout);
    }
    dr_app_stop_and_cleanup();
    if (have_kstats)
        remove_tree(logdir);

    /* Growth from the first bucket to the last.  Floors keep noise in small
     * numbers from being flagged.
     */
    bool any = false;
    int last = buckets - 1;
    if (buckets > 1) {
        grows("cpu ns (median)", bucket_median[0], bucket_median[last], 300, &any);
        grows("cpu ns (mean)", bucket_cost[0].cpu, bucket_cost[last].cpu, 300, &any);
        for (uint p = 0; have_kstats && p < NUM_PHASES; p++) {
            char what[64];
            snprintf(what, sizeof(what), "%s ticks", phase_names[p]);
            grows(what, bucket_cost[0].ticks[p], bucket_cost[last].ticks[p], 3, &any);
        }
        if (flushes > 0)
            grows("flush ns", flush_cpu[0], flush_cpu[last], 20000, &any);
    }
    /* The guard: every chain of the last bucket against the first bucket's
     * median, which noise (that only adds time) cannot make fail.
     */
    double late_min = 1e300;
    for (int i = last * per_bucket; i < buckets * per_bucket; i++) {
        if (slice_cpu[i] < late_min)
            late_min = slice_cpu[i];
    }
    double ratio = late_min / bucket_median[0];
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("scale %s/%s: %s: last bucket's cheapest chain %.0f ns/block, %.2fx the first "
           "bucket's median %.0f; peak RSS %ld MB\n",
           cfg_ops, cfg_mode, any ? "grows" : "flat", late_min, ratio, bucket_median[0],
           ru.ru_maxrss / 1024);
    if (scale_guard && buckets > 1 && ratio > scale_limit) {
        FAIL("block building costs %.2fx as much per block with %d blocks built as "
             "with %d: a cost grows with the size of the code cache",
             ratio, scale_blocks, bucket_blocks);
    }
    fflush(stdout);
    return failures > 0 ? 1 : 0;
}

static int
parse_list(const char *list, const char *const *names, int num, uint *mask)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", list);
    for (char *tok = strtok(buf, ","); tok != NULL; tok = strtok(NULL, ",")) {
        int m;
        for (m = 0; m < num && strcmp(tok, names[m]) != 0; m++)
            ;
        if (m == num) {
            fprintf(stderr, "unknown name %s\n", tok);
            return 0;
        }
        *mask |= 1u << m;
    }
    return 1;
}

static int
usage(const char *name)
{
    fprintf(stderr,
            "usage: %s [-blocks N] [-len N] [-reps N] [-runs N] "
            "[-modes m1,m2,...] [-ops o1,o2,...|all]\n"
            "       [-scale N [-bucket N] [-slice N] [-limit X] [-scale-guard] "
            "[-layout sparse,rwx,onemap,hub,reverse] [-flushes K]]\n",
            name);
    return 1;
}

int
main(int argc, char *argv[])
{
    uint want_mode = 0, want_ops = 1u << OPS_DEFAULT | 1u << OPS_SEEDBOX;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-blocks") == 0 && i + 1 < argc)
            num_blocks = atoi(argv[++i]);
        else if (strcmp(argv[i], "-len") == 0 && i + 1 < argc)
            block_len = atoi(argv[++i]);
        else if (strcmp(argv[i], "-reps") == 0 && i + 1 < argc)
            reps = atoi(argv[++i]);
        else if (strcmp(argv[i], "-runs") == 0 && i + 1 < argc)
            runs = atoi(argv[++i]);
        else if (strcmp(argv[i], "-modes") == 0 && i + 1 < argc) {
            if (!parse_list(argv[++i], mode_names, NUM_MODES, &want_mode))
                return 1;
        } else if (strcmp(argv[i], "-ops") == 0 && i + 1 < argc) {
            const char *o = argv[++i];
            want_ops = 0;
            if (strcmp(o, "all") == 0)
                want_ops = 1u << OPS_DEFAULT | 1u << OPS_SEEDBOX;
            else if (!parse_list(o, ops_names, NUM_OPS, &want_ops))
                return 1;
        } else if (strcmp(argv[i], "-scale") == 0 && i + 1 < argc)
            scale_blocks = atoi(argv[++i]);
        else if (strcmp(argv[i], "-bucket") == 0 && i + 1 < argc)
            bucket_blocks = atoi(argv[++i]);
        else if (strcmp(argv[i], "-slice") == 0 && i + 1 < argc)
            slice_blocks = atoi(argv[++i]);
        else if (strcmp(argv[i], "-limit") == 0 && i + 1 < argc)
            scale_limit = atof(argv[++i]);
        else if (strcmp(argv[i], "-scale-guard") == 0)
            scale_guard = true;
        else if (strcmp(argv[i], "-layout") == 0 && i + 1 < argc) {
            if (!parse_list(argv[++i], layout_names, NUM_LAYOUT_FLAGS, &scale_layout))
                return 1;
        } else if (strcmp(argv[i], "-flushes") == 0 && i + 1 < argc)
            scale_flushes = atoi(argv[++i]);
        else
            return usage(argv[0]);
    }
    if (num_blocks < 1 || block_len < 1 || reps < 1 || runs < 1 || scale_blocks < 0 ||
        slice_blocks < 1 || scale_limit <= 1)
        return usage(argv[0]);
    if (want_mode == 0)
        want_mode = (1u << NUM_MODES) - 1;
    if (scale_blocks > 0) {
        /* The native run is of one chain, as the scaling mode runs them. */
        num_blocks = slice_blocks;
        if (bucket_blocks <= 0)
            bucket_blocks = scale_blocks / 10;
        bucket_blocks = bucket_blocks / slice_blocks * slice_blocks;
        if (bucket_blocks < slice_blocks)
            bucket_blocks = slice_blocks;
        if (scale_blocks < bucket_blocks)
            return usage(argv[0]);
        if (TESTANY(LAYOUT_HUB, scale_layout) &&
            (TESTANY(LAYOUT_SPARSE | LAYOUT_REVERSE, scale_layout) ||
             TESTANY(1u << OPS_TRACES, want_ops))) {
            fprintf(stderr, "the hub layout cannot be sparse or reversed (traces)\n");
            return 1;
        }
    } else if (TESTANY(1u << OPS_TRACES, want_ops)) {
        fprintf(stderr, "the traces options are for the scaling mode\n");
        return 1;
    }
    default_chain = num_blocks == DEFAULT_BLOCKS && block_len == DEFAULT_LEN;

    uint64_t seed = 0x1234567;
    for (int i = 0; i < SCRATCH_WORDS; i++)
        scratch_init[i] = xorshift64(&seed);

    /* The native result and time, on a warm copy. */
    chain_t native;
    chain_make(&native, num_blocks, block_len, DEFAULT_SEED, 0);
    expected_hash = chain_run(&native);
    double best = 1e300;
    for (int k = 0; k < 20; k++) {
        double t = now_ns();
        uint64_t h = chain_run(&native);
        t = now_ns() - t;
        if (h != expected_hash) {
            printf("FAIL: native runs disagree\n");
            return 1;
        }
        if (t < best)
            best = t;
    }
    native_ns_per_block = best / num_blocks;
    printf("chain: %d blocks of %d instructions, native %.2f ns/block\n", num_blocks,
           block_len, native_ns_per_block);
    fflush(stdout);

    int failed = 0;
    for (int o = 0; o < NUM_OPS; o++) {
        for (int m = 0; m < NUM_MODES; m++) {
            if (!TESTANY(1u << o, want_ops) || !TESTANY(1u << m, want_mode))
                continue;
            pid_t pid = fork();
            if (pid == 0)
                _exit(scale_blocks > 0 ? scale_child(m, o) : child(m, o));
            int st;
            waitpid(pid, &st, 0);
            if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                printf("FAIL %s/%s: child %s %d\n", ops_names[o], mode_names[m],
                       WIFEXITED(st) ? "exited with" : "died with signal",
                       WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
                failed++;
            }
        }
    }
    if (failed > 0) {
        printf("FAIL: %d configurations failed\n", failed);
        return 1;
    }
    printf("a64_codegen_build: done\n");
    return 0;
}

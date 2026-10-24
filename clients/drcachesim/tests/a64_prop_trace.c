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

/* End-to-end property of the offline drmemtrace pipeline on AArch64 (tracer ->
 * raw files -> raw2trace -> reader), with an oracle independent of DR's
 * decoder: random blocks from a64_dr_prop's generator run under static DR
 * with the drmemtrace tracer linked in, in a forked child per variant, and the
 * final trace must equal, after the normalisation below, what the native CPU
 * did and what the generator's access model says.
 *
 * The expected execution of each block comes from:
 * + the native CPU, single-stepped with ptrace over the whole run (entry stub,
 *   block, exit stub): the sequence of pcs, and the register state before each
 *   instruction;
 * + the generator's memory model (meminfo_t: base, index, offset, writeback,
 *   access kind and size of every memory instruction it emits, a64_dr_prop_gen.h),
 *   applied to that native state;
 * + the installed instruction words, and a branch classifier written from the
 *   A64 encoding tables (below), with the taken/not-taken outcome from the
 *   native pc sequence (or, for a branch to the next instruction, from its
 *   condition evaluated on the native state);
 * + the native run's faults (signal, pc) for blocks with planned faults; the
 *   handler resumes after the faulting instruction.
 * DR's decoder, drutil and drmemtrace's own operand logic play no part in it.
 *
 * Property, per run of a block (blocks run twice each, in order):
 * T1 the trace has one "run" per executed run, from the trampoline's "br x0"
 *    (an indirect jump to the entry) to its return point, and no instruction
 *    of the code region outside runs;
 * T2 the run's instructions are exactly the native ones: same pcs in the same
 *    order and number, length 4, encoding equal to the installed word;
 * T3 instruction types follow the documented taxonomy (trace_entry.h): B is a
 *    direct jump, BL a direct call, B.cond/CBZ/CBNZ/TBZ/TBNZ a taken or untaken
 *    jump as the native pc sequence says, BR/BRAA/BRAAZ (and the B forms) an
 *    indirect jump, BLR/BLRAA/BLRAAZ an indirect call, RET/RETAA/RETAB a return,
 *    everything else (SVC included) a plain instruction; indirect branches,
 *    calls and returns carry their actual target (the next native pc);
 * T4 encoding_is_new is set on the first record of a pc in the trace and
 *    whenever the encoding at that pc differs from the one last seen there
 *    (each block is installed at the same address);
 * T5 each instruction's data records are exactly the modelled ones, in order;
 * T6 no instruction anywhere in the trace has a pc outside the executable
 *    file mappings, the vdso and the code region (e.g. in DR's code cache), and
 *    the trace has one thread;
 * T7 signal deliveries inside a run (N9, N10) are bracketed by KERNEL_EVENT
 *    and KERNEL_XFER markers, with only handler code (outside the code
 *    region) in between, and the event's pc is the next instruction to run;
 *    each planned fault is such a delivery, preceded by an
 *    UNCOMPLETED_INSTRUCTION marker holding the faulting instruction's
 *    encoding, with that fault's signal number, and the instruction has no
 *    records;
 * and the final state of every DR run equals the native one (transparency;
 * a run that differs is reported and not compared further).  A fault frame
 * may differ from the native one in registers that are dead there: see
 * drreg-dead-dest below, and cmp_dr_run().
 *
 * Normalisation (the documented record semantics, and where the docs are
 * silent the convention this test encodes and checks; see
 * clients/drcachesim/docs/drcachesim.dox.in "Trace Format" and
 * common/trace_entry.h):
 * N1 one record per memory operand: a contiguous access is one record whose
 *    size is the whole access: LDP/STP/LDNP/STNP/LDPSW (2 x element), SIMD
 *    LD1-4/ST1-4 multiple structures (registers x 8 or 16 bytes), single
 *    structure and replicate forms (registers x element), LDXP/STXP and
 *    CASP (2 x element);
 * N2 a load is a READ, a store a WRITE; an atomic read-modify-write (LSE
 *    LD<op>/ST<op>/SWP, CAS, CASP) is a READ followed by a WRITE of the same
 *    address and size, whether or not a CAS compare succeeds (the record is
 *    of the attempted access, not of whether memory changed); a store-exclusive
 *    is a WRITE whether or not it succeeds; LDAR/LDAPR/STLR as plain loads
 *    and stores;
 * N3 PRFM: one prefetch record whose type is decoded from prfop as the
 *    architecture defines it (PLD/PLI/PST x L1/L2/L3 x KEEP/STRM ->
 *    TRACE_TYPE_PREFETCH_{READ,INSTR,WRITE}_L{1,2,3}[_NT]); prfops with no
 *    such meaning (type 0b11, or the SLC target) give the generic
 *    TRACE_TYPE_PREFETCH; the size of a prefetch is not checked;
 * N4 DC ZVA: one WRITE of the DCZID_EL0 block (address aligned down to it,
 *    size the block size) (raw2trace's i#4400 workaround);
 * N5 DC CVAU/CIVAC: one TRACE_TYPE_DATA_FLUSH, IC IVAU one
 *    TRACE_TYPE_INSTR_FLUSH, whose pc is the instruction's, starting at the
 *    operand address (not aligned to the line the architecture maintains: the
 *    convention drmemtrace follows, i#4406) and as long as the minimum line
 *    of that cache (CTR_EL0.DminLine, IminLine);
 * N6 LDRAA/LDRAB access the authenticated (PAC-stripped) address;
 * N7 markers may appear between records (timestamps, cpu ids, syscall
 *    markers around SVC) and are not compared; kernel event/xfer,
 *    signal-number, rseq-abort, skipped-memref and uncompleted-instruction
 *    markers only as N9/N10 allow;
 * N8 exclusive retry loops: the CPU may fail a store-exclusive spuriously and
 *    single-stepping always fails it, so a loop (LDXR..CBNZ) is expected k >= 1
 *    times, every iteration with the modelled records, CBNZ taken in all
 *    iterations but the last;
 * N9 a planned (synchronous) fault removes the faulting instruction and its
 *    records (trace_entry.h, TRACE_MARKER_TYPE_UNCOMPLETED_INSTRUCTION, i#7050):
 *    UNCOMPLETED_INSTRUCTION (its encoding), KERNEL_EVENT (its pc), the
 *    handler, KERNEL_XFER, then the instruction after it;
 * N10 an asynchronous signal (the signals variants) may be delivered before
 *    any instruction (DR delivers at block boundaries): optionally
 *    UNCOMPLETED_INSTRUCTION for that instruction, KERNEL_EVENT with its pc,
 *    the handler, KERNEL_XFER, then that instruction; deliveries may nest.
 *
 * Known deviations (2026-10-14), counted and reported as suppressed, failures
 * with A64PT_STRICT=1:
 * + cbr-target-next: a conditional branch whose target is the next instruction
 *   is recorded as taken whether or not its condition held.  raw2trace infers
 *   taken/untaken from the next pc (raw2trace.cpp, "target == next_instr_pc"),
 *   which cannot tell these apart; the raw trace has no direction bit.  The
 *   oracle evaluates the condition from the native state.
 * + async-loop-drop: a loop iteration missing from the trace where an
 *   asynchronous signal was delivered at a loop's back-edge into the block
 *   just executed, with no address recorded after that pc in the block.
 *   raw2trace reads the KERNEL_EVENT at a pc of the completed block as an
 *   interruption there and drops the block from that pc (UNCOMPLETED marker).
 *   When later instructions of the block recorded addresses raw2trace now
 *   tells the cases apart (interrupted_by_kernel_event()); otherwise the raw
 *   records cannot, short of the tracer marking deliveries between blocks.
 *   Accepted when skipping one iteration at such a delivery makes the run
 *   match, or when, at the loop's exit, the missing iterations are no more
 *   than the uncompleted deliveries seen inside the loop (one chain of
 *   back-to-back deliveries can drop several: common on a loaded machine).
 *   Repro: the signals variants (timing dependent; dozens per run of 128
 *   blocks; A64PT_ASYNC_US=30 makes chains more frequent).
 * + syscall-signal-dup: a signal DR delivers just before an SVC that the
 *   tracer has already recorded (instruction and syscall marker) shows the SVC
 *   twice: KERNEL_EVENT at the SVC's pc after its first record, then the SVC
 *   again (it executes once, after the handler).  The tracer records a
 *   syscall DR then defers (upstream i#5934/i#6102 work around neighbours of
 *   this).  Accepted when the delivery's pc is the SVC just matched.
 * + frame-pstate: PSTATE.BTYPE/SSBS differences in DR's fault frames (DR's
 *   own known deviations, see api.a64_prop_bti and a64_dr_prop).
 * + drreg-dead-dest: the drmemtrace tracer uses drreg in its default
 *   non-conservative mode, which documents (drreg.h, conservative) that a dead
 *   register may hold another value in a fault's frame.  A faulting load's
 *   destination is dead at the fault if the load were to complete; our handler
 *   skips the load, so the application later reads the tool's value.
 *   Accepted when a native rerun that gives each fault's frame DR's values for
 *   those destinations ends exactly as the DR run did (the run's trace is then
 *   not compared, as its control flow may differ).  Other dead-register
 *   differences in fault frames are accepted (counted as "dead registers")
 *   when a native rerun with DR's value has the same outcome.
 *
 * Variants (one child each): default, noopt (-disable_optimizations: no
 * address elision in the tracer), maxbb3 (DR -max_bb_instrs 3: many block
 * boundaries for raw2trace to reassemble), faults (blocks with planned
 * faults: guard-page accesses, UDF, misaligned SP or exclusives, FPAC
 * authentication failures), signals (a 50 us ITIMER_REAL while the blocks
 * run) and faultsig (both).  The signals variants require at least 20
 * deliveries inside runs.
 *
 * Usage: a64_prop_trace [-seed S] [-n blocks] [-runs R] [-variants a,b] [-keep]
 *                       [-v]
 * Trace directories go to $A64PT_DIR (default .) and are removed unless the
 * variant failed or -keep was given.
 */

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include "dr_api.h"

#include <errno.h>
#include <ftw.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "a64_prop_support.h"
#pragma GCC diagnostic pop
#include "a64_prop_trace.h"

static int verbose;
static int keep_dirs;
/* A64PT_STRICT=1: known deviations are failures. */
static int strict;

/* Block sets. */
enum {
    BS_PLAIN,  /* deterministic, non-faulting */
    BS_FAULTS, /* with planned synchronous faults (resumed after) */
    BS_N
};

typedef struct {
    const char *name;
    const char *dr_ops;
    const char *tracer_ops;
    int blockset;
    int async_us; /* interval of an itimer (SIGALRM) while the blocks run, or 0 */
} tvariant_t;

static const tvariant_t tvariants[] = {
    { "default", "", "", BS_PLAIN, 0 },
    { "noopt", "", "-disable_optimizations", BS_PLAIN, 0 },
    { "maxbb3", "-max_bb_instrs 3", "", BS_PLAIN, 0 },
    { "faults", "", "", BS_FAULTS, 0 },
    { "signals", "", "", BS_PLAIN, 50 },
    { "faultsig", "", "", BS_FAULTS, 50 },
};
#define NTVARIANTS ((int)(sizeof(tvariants) / sizeof(tvariants[0])))

/***************************************************************************
 * The expected execution.
 */
typedef struct {
    uint16_t type; /* A64PT_T_* */
    uint8_t chk_size;
    uint32_t size;
    uint64_t addr;
} xref_t;

typedef struct {
    uint64_t pc;
    uint32_t word;
    int idx;
    uint16_t itype; /* A64PT_T_*; for a conditional branch the taken/untaken type */
    /* The first instruction of an exclusive retry loop: the loop is the
     * instructions idx..loop_end-1 (these entries), repeated k >= 1 times.
     */
    uint8_t loop;
    int loop_end;
    uint64_t next; /* the pc executed next */
    int nref, ref0;
    /* A planned fault: the signal executing this instruction raises natively
     * (the instruction does not complete; the handler resumes at next).
     */
    int sig;
} xinstr_t;

typedef struct {
    int valid;
    block_t *b;
    xinstr_t *ins;
    int nins, cap_ins;
    int nfaults; /* entries with sig != 0 */
    xref_t *refs;
    int nrefs, cap_refs;
    result_t native;
} xblock_t;

/* Coverage of the expected model, over all valid blocks. */
enum {
    CV_READ,
    CV_WRITE,
    CV_RMW,
    CV_PRFM,
    CV_ZVA,
    CV_DFLUSH,
    CV_IFLUSH,
    CV_PAIR,
    CV_SIMD_STRUCT,
    CV_X28_BASE,
    CV_SP_BASE,
    CV_WRITEBACK,
    CV_INDEX,
    CV_LITERAL,
    CV_LDRAA,
    CV_EXCL_LOOP,
    CV_TAKEN,
    CV_UNTAKEN,
    CV_INDIRECT,
    CV_CALL,
    CV_RETURN,
    CV_SVC,
    CV_N
};
static const char *const cv_names[CV_N] = {
    "read",     "write",   "rmw",         "prfm",      "dc_zva",  "dc_flush",
    "ic_ivau",  "pair",    "simd_struct", "x28_base",  "sp_base", "writeback",
    "index",    "literal", "ldraa",       "excl_loop", "taken",   "untaken",
    "indirect", "call",    "return",      "svc"
};
static long coverage[CV_N];

static uint64_t dczva_bytes;
/* Set on a defect of the generator's model or of this test: always a failure. */
static int harness_bugs;
/* CTR_EL0.DminLine and IminLine in bytes. */
static uint64_t dline_bytes, iline_bytes;

/* Branch classes, from the A64 encoding tables (C4.1.65 "Branches, Exception
 * Generating and System instructions"), independent of DR's decoder.
 */
enum { BR_NONE, BR_DIRECT, BR_CALL, BR_COND, BR_IND, BR_INDCALL, BR_RET };

static int
branch_class(uint32_t w)
{
    if ((w & 0xfc000000u) == 0x14000000u)
        return BR_DIRECT; /* B */
    if ((w & 0xfc000000u) == 0x94000000u)
        return BR_CALL; /* BL */
    if ((w & 0xff000000u) == 0x54000000u)
        return BR_COND; /* B.cond, BC.cond */
    if ((w & 0x7e000000u) == 0x34000000u)
        return BR_COND; /* CBZ, CBNZ */
    if ((w & 0x7e000000u) == 0x36000000u)
        return BR_COND; /* TBZ, TBNZ */
    if ((w & 0xfffffc1fu) == 0xd61f0000u)
        return BR_IND; /* BR */
    if ((w & 0xfffff81fu) == 0xd61f081fu)
        return BR_IND; /* BRAAZ, BRABZ */
    if ((w & 0xfffff800u) == 0xd71f0800u)
        return BR_IND; /* BRAA, BRAB */
    if ((w & 0xfffffc1fu) == 0xd63f0000u)
        return BR_INDCALL; /* BLR */
    if ((w & 0xfffff81fu) == 0xd63f081fu)
        return BR_INDCALL; /* BLRAAZ, BLRABZ */
    if ((w & 0xfffff800u) == 0xd73f0800u)
        return BR_INDCALL; /* BLRAA, BLRAB */
    if ((w & 0xfffffc1fu) == 0xd65f0000u)
        return BR_RET; /* RET */
    if ((w & 0xfffffbffu) == 0xd65f0bffu)
        return BR_RET; /* RETAA, RETAB */
    return BR_NONE;
}

static int
is_svc(uint32_t w)
{
    return (w & 0xffe0001fu) == 0xd4000001u;
}

/* The target of the conditional branch w at pc. */
static uint64_t
cond_target(uint32_t w, uint64_t pc)
{
    int64_t off;
    if ((w & 0x7e000000u) == 0x36000000u) /* TBZ/TBNZ: imm14 */
        off = (int64_t)((int32_t)(w << 13) >> 18);
    else /* B.cond, CBZ/CBNZ: imm19 */
        off = (int64_t)((int32_t)(w << 8) >> 13);
    return pc + (uint64_t)(off * 4);
}

/* Whether the conditional branch w is taken in state s (pseudocode of B.cond,
 * CBZ/CBNZ and TBZ/TBNZ with ConditionHolds()).  The native pc sequence alone
 * cannot tell when the target is the next instruction.
 */
static int
cond_taken(uint32_t w, tstep_t *s)
{
    if ((w & 0xff000000u) == 0x54000000u) {
        uint32_t c = w & 15, nzcv = (uint32_t)(s->pstate >> 28) & 15;
        int n = (nzcv >> 3) & 1, z = (nzcv >> 2) & 1, cf = (nzcv >> 1) & 1, v = nzcv & 1;
        int r;
        switch (c >> 1) {
        case 0: r = z; break;
        case 1: r = cf; break;
        case 2: r = n; break;
        case 3: r = v; break;
        case 4: r = cf && !z; break;
        case 5: r = n == v; break;
        case 6: r = n == v && !z; break;
        default: r = 1; break;
        }
        if ((c & 1) && c != 15)
            r = !r;
        return r;
    }
    int rt = w & 31;
    uint64_t val = rt == 31 ? 0 : s->x[rt];
    if ((w & 0x7e000000u) == 0x34000000u) {
        if (!(w >> 31))
            val = (uint32_t)val;
        int nz = (w >> 24) & 1; /* CBNZ */
        return nz ? val != 0 : val == 0;
    }
    /* TBZ/TBNZ */
    int bit = (int)(((w >> 31) << 5) | ((w >> 19) & 31));
    int set = (val >> bit) & 1;
    return (w >> 24) & 1 ? set : !set;
}

static uint16_t
expected_itype(uint32_t w, uint64_t pc, uint64_t next, tstep_t *s)
{
    switch (branch_class(w)) {
    case BR_DIRECT: return A64PT_T_DIRECT_JUMP;
    case BR_CALL: return A64PT_T_DIRECT_CALL;
    case BR_COND:
        if (next != pc + 4)
            return A64PT_T_TAKEN_JUMP;
        return cond_taken(w, s) ? A64PT_T_TAKEN_JUMP : A64PT_T_UNTAKEN_JUMP;
    case BR_IND: return A64PT_T_INDIRECT_JUMP;
    case BR_INDCALL: return A64PT_T_INDIRECT_CALL;
    case BR_RET: return A64PT_T_RETURN;
    default: return A64PT_T_INSTR;
    }
}

static int
itype_is_indirect(uint16_t t)
{
    return t == A64PT_T_INDIRECT_JUMP || t == A64PT_T_INDIRECT_CALL ||
        t == A64PT_T_RETURN;
}

/* PRFM prfop<4:0> = type<4:3> (PLD, PLI, PST), target<2:1> (L1, L2, L3, SLC),
 * policy<0> (KEEP, STRM).
 */
static uint16_t
prefetch_type(uint32_t prfop)
{
    uint32_t type = (prfop >> 3) & 3, target = (prfop >> 1) & 3, strm = prfop & 1;
    if (type == 3 || target == 3)
        return A64PT_T_PREFETCH;
    return (uint16_t)(A64PT_T_PF_BASE + 6 * type + 2 * target + strm);
}

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

static void
add_ref(xblock_t *x, uint16_t type, uint64_t addr, uint32_t size, int chk_size)
{
    if (x->nrefs >= x->cap_refs) {
        x->cap_refs = x->cap_refs == 0 ? 256 : 2 * x->cap_refs;
        x->refs = realloc(x->refs, sizeof(xref_t) * x->cap_refs);
    }
    xref_t *r = &x->refs[x->nrefs++];
    r->type = type;
    r->addr = addr;
    r->size = size;
    r->chk_size = (uint8_t)chk_size;
}

static int
is_simd_struct(uint32_t w)
{
    return (w & 0xbf800000u) == 0x0c000000u || (w & 0xbf800000u) == 0x0c800000u ||
        (w & 0xbf800000u) == 0x0d000000u || (w & 0xbf800000u) == 0x0d800000u;
}

static int
is_pair(uint32_t w)
{
    return (w & 0x3a000000u) == 0x28000000u;
}

/* Appends the expected instruction at index idx executed in state s, followed
 * by next.  Returns 0 if the generator's model is incomplete (a harness bug).
 */
static int
add_instr(xblock_t *x, int idx, tstep_t *s, uint64_t next, int count)
{
    block_t *b = x->b;
    if (x->nins >= x->cap_ins) {
        x->cap_ins = x->cap_ins == 0 ? 512 : 2 * x->cap_ins;
        x->ins = realloc(x->ins, sizeof(xinstr_t) * x->cap_ins);
    }
    xinstr_t *xi = &x->ins[x->nins++];
    memset(xi, 0, sizeof(*xi));
    xi->idx = idx;
    xi->pc = pc_of(idx);
    xi->word = b->a.w[idx];
    xi->next = next;
    xi->itype = expected_itype(xi->word, xi->pc, next, s);
    if (branch_class(xi->word) == BR_COND && next != xi->pc + 4 &&
        !cond_taken(xi->word, s)) {
        harness_bugs++;
        fprintf(stderr,
                "HARNESS BUG: seed %llu: %s at index %d branched natively but "
                "its condition does not hold\n",
                (unsigned long long)b->seed, b->a.txt[idx], idx);
        return 0;
    }
    xi->ref0 = x->nrefs;
    if (count) {
        switch (xi->itype) {
        case A64PT_T_TAKEN_JUMP: coverage[CV_TAKEN]++; break;
        case A64PT_T_UNTAKEN_JUMP: coverage[CV_UNTAKEN]++; break;
        case A64PT_T_INDIRECT_JUMP: coverage[CV_INDIRECT]++; break;
        case A64PT_T_INDIRECT_CALL:
        case A64PT_T_DIRECT_CALL: coverage[CV_CALL]++; break;
        case A64PT_T_RETURN: coverage[CV_RETURN]++; break;
        }
        if (is_svc(xi->word))
            coverage[CV_SVC]++;
    }
    meminfo_t *m = &b->a.mi[idx];
    if (!m->valid)
        return 1;
    uint64_t addr = model_addr(m, s);
    int in_block = idx >= b->block_start && idx < b->exit_start;
    if (count && in_block) {
        if (m->base == 28 && !m->lit)
            coverage[CV_X28_BASE]++;
        if (m->base == 31 && !m->lit)
            coverage[CV_SP_BASE]++;
        if (m->wb)
            coverage[CV_WRITEBACK]++;
        if (m->idx >= 0)
            coverage[CV_INDEX]++;
        if (m->lit)
            coverage[CV_LITERAL]++;
        if (m->pac)
            coverage[CV_LDRAA]++;
        if (is_pair(xi->word))
            coverage[CV_PAIR]++;
        if (is_simd_struct(xi->word))
            coverage[CV_SIMD_STRUCT]++;
    }
    switch (m->acc) {
    case MA_R:
        add_ref(x, A64PT_T_READ, addr, m->size, 1);
        if (count && in_block)
            coverage[CV_READ]++;
        break;
    case MA_W:
        add_ref(x, A64PT_T_WRITE, addr, m->size, 1);
        if (count && in_block)
            coverage[CV_WRITE]++;
        break;
    case MA_RW:
        add_ref(x, A64PT_T_READ, addr, m->size, 1);
        add_ref(x, A64PT_T_WRITE, addr, m->size, 1);
        if (count && in_block)
            coverage[CV_RMW]++;
        break;
    case MA_PRFM:
        add_ref(x, prefetch_type(xi->word & 31), addr, 0, 0);
        if (count)
            coverage[CV_PRFM]++;
        break;
    case MA_ZVA:
        add_ref(x, A64PT_T_WRITE, addr & ~(dczva_bytes - 1), (uint32_t)dczva_bytes, 1);
        if (count)
            coverage[CV_ZVA]++;
        break;
    case MA_DFLUSH:
        add_ref(x, A64PT_T_DATA_FLUSH, addr, (uint32_t)dline_bytes, 1);
        if (count)
            coverage[CV_DFLUSH]++;
        break;
    case MA_IFLUSH:
        add_ref(x, A64PT_T_INSTR_FLUSH, addr, (uint32_t)iline_bytes, 1);
        if (count)
            coverage[CV_IFLUSH]++;
        break;
    default:
        harness_bugs++;
        fprintf(stderr, "HARNESS BUG: seed %llu: no access model for %s at index %d\n",
                (unsigned long long)b->seed, b->a.txt[idx], idx);
        return 0;
    }
    xi->nref = x->nrefs - xi->ref0;
    return 1;
}

/* Builds the expected execution of b from a whole-run native trace.  Returns 0
 * if the trace or the model cannot be used.
 */
static int
build_expected(xblock_t *x, trace_t *t, uint64_t host_ret)
{
    block_t *b = x->b;
    for (int s = 0; s < t->n; s++) {
        tstep_t *st = &t->steps[s];
        int idx = (int)((st->pc - CODE_BASE) / 4);
        uint64_t next = s + 1 < t->n ? t->steps[s + 1].pc : host_ret;
        int skip = b->a.excl_skip[idx];
        if (skip != 0 && next == pc_of(skip)) {
            /* An exclusive retry loop LDXR ... CBNZ, idx..skip-1: its registers
             * other than the ones it writes are those at its head.
             */
            int first = x->nins;
            for (int j = idx; j < skip; j++) {
                uint64_t nx = j + 1 < skip ? pc_of(j + 1) : next;
                if (!add_instr(x, j, st, nx, 1))
                    return 0;
            }
            x->ins[first].loop = 1;
            x->ins[first].loop_end = skip;
            coverage[CV_EXCL_LOOP]++;
            continue;
        }
        if (st->sig != 0) {
            /* A planned fault: no records, but a kernel event (see N9). */
            if (!add_instr(x, idx, st, next, 0))
                return 0;
            xinstr_t *xi = &x->ins[x->nins - 1];
            x->nrefs = xi->ref0;
            xi->nref = 0;
            xi->sig = st->sig;
            x->nfaults++;
            continue;
        }
        if (!add_instr(x, idx, st, next, 1))
            return 0;
    }
    /* The faults the trace saw must be the ones the run recorded. */
    if (x->nfaults != x->native.nf) {
        fprintf(stderr,
                "NOTE: seed %llu: %d faults while single-stepping, %d in the run; "
                "skipped\n",
                (unsigned long long)b->seed, x->nfaults, x->native.nf);
        return 0;
    }
    for (int i = 0, k = 0; i < x->nins; i++) {
        if (x->ins[i].sig == 0)
            continue;
        if (x->ins[i].pc != x->native.f[k].pc || x->ins[i].sig != x->native.f[k].signo) {
            fprintf(stderr,
                    "NOTE: seed %llu: fault %d differs between the traced and "
                    "the plain native run; skipped\n",
                    (unsigned long long)b->seed, k);
            return 0;
        }
        k++;
    }
    return 1;
}

/***************************************************************************
 * Comparison of a run in the trace against the expected execution.
 */
typedef struct {
    long instrs, refs, markers, loops, loop_iters, runs, enc_changes;
    long kd_cbr_next;
    long faults; /* planned faults matched to their kernel events */
    long kd_async_drop;
    long drop_skipped; /* expected entries skipped as dropped iterations */
    long kd_syscall_dup;
    long async_exc; /* asynchronous signal deliveries inside runs */
    long uncompleted;
} cmp_stats_t;

static uint32_t *last_word; /* per code index, as last seen in the trace */
static uint8_t *seen_word;

static const char *
rec_str(a64pt_rec_t *r, char *buf, size_t len)
{
    switch (r->kind) {
    case A64PT_INSTR:
        snprintf(buf, len, "instr %s pc=0x%llx size=%u enc=%08x%s ibt=0x%llx",
                 a64pt_type_name(r->raw_type), (unsigned long long)r->pc, r->size, r->enc,
                 r->enc_new ? " new" : "", (unsigned long long)r->addr);
        break;
    case A64PT_DATA:
    case A64PT_FLUSH:
        snprintf(buf, len, "%s addr=0x%llx size=%u pc=0x%llx",
                 a64pt_type_name(r->raw_type), (unsigned long long)r->addr, r->size,
                 (unsigned long long)r->pc);
        break;
    case A64PT_MARKER:
        snprintf(buf, len, "marker %u value=0x%llx", r->raw_type,
                 (unsigned long long)r->addr);
        break;
    case A64PT_NONE: snprintf(buf, len, "(start of trace)"); break;
    default: snprintf(buf, len, "other type %u", r->raw_type); break;
    }
    return buf;
}

static void
print_context(FILE *o, a64pt_rec_t *r, long n, long at)
{
    char buf[160];
    /* A64PT_CONTEXT=N: N records after the divergence (default 6). */
    static long after = -1;
    if (after < 0)
        after = getenv("A64PT_CONTEXT") != NULL ? atol(getenv("A64PT_CONTEXT")) : 6;
    long before = after > 12 ? after : 12;
    long lo = at - before < 0 ? 0 : at - before, hi = at + after > n ? n : at + after;
    for (long i = lo; i < hi; i++) {
        fprintf(o, "    %s[%ld] %s", i == at ? "=>" : "  ", i,
                rec_str(&r[i], buf, sizeof(buf)));
        if (r[i].kind == A64PT_INSTR && r[i].pc >= CODE_BASE &&
            r[i].pc < CODE_BASE + CODE_SIZE)
            fprintf(o, "   (index %llu)",
                    (unsigned long long)((r[i].pc - CODE_BASE) / 4));
        fprintf(o, "\n");
    }
}

static int
is_event_marker(a64pt_rec_t *r)
{
    if (r->kind != A64PT_MARKER)
        return 0;
    switch (r->type) {
    case A64PT_M_KERNEL_EVENT:
    case A64PT_M_KERNEL_XFER:
    case A64PT_M_UNCOMPLETED_INSTRUCTION:
    case A64PT_M_RSEQ_ABORT:
    case A64PT_M_SIGNAL_NUMBER:
    case A64PT_M_SKIPPED_MEMREF: return 1;
    }
    return 0;
}

/* Skips markers other than event markers from *p. */
static void
skip_markers(a64pt_rec_t *r, long n, long *p, cmp_stats_t *cs)
{
    while (*p < n && r[*p].kind == A64PT_MARKER && !is_event_marker(&r[*p])) {
        cs->markers++;
        (*p)++;
    }
}

/* The next instruction record at or after p outside signal deliveries. */
static long
peek_instr(a64pt_rec_t *r, long n, long p)
{
    int depth = 0;
    for (; p < n; p++) {
        if (r[p].kind == A64PT_MARKER && r[p].type == A64PT_M_KERNEL_EVENT)
            depth++;
        else if (r[p].kind == A64PT_MARKER && r[p].type == A64PT_M_KERNEL_XFER)
            depth--;
        else if (r[p].kind == A64PT_INSTR && depth <= 0)
            return p;
    }
    return n;
}

/* At *p, consumes the signal deliveries that interrupt the run before the
 * instruction at pc (encoding word): each is an optional
 * UNCOMPLETED_INSTRUCTION marker whose value is that encoding, a KERNEL_EVENT
 * marker whose value is pc, then the handler (instructions outside the code,
 * nested deliveries included) up to the matching KERNEL_XFER marker.  Returns
 * the number consumed, or -1 (after reporting); *last_sig and *last_unc get
 * the signal number and whether the last one had an uncompleted marker.
 */
static int
consume_deliveries(FILE *o, uint64_t pc, uint32_t word, a64pt_rec_t *r, long n, long *p,
                   cmp_stats_t *cs, int *last_sig, int *last_unc, int *any_unc)
{
    char buf[160];
    int count = 0;
    *last_sig = 0;
    *last_unc = 0;
    if (any_unc != NULL)
        *any_unc = 0;
    for (;;) {
        skip_markers(r, n, p, cs);
        if (*p >= n || !is_event_marker(&r[*p]))
            return count;
        /* A delivery at another pc belongs to a later instruction (after a
         * fault here, the handler resumes past it): leave it to that one.
         */
        long q = *p;
        while (q < n && r[q].kind == A64PT_MARKER && r[q].type != A64PT_M_KERNEL_EVENT &&
               r[q].type != A64PT_M_KERNEL_XFER)
            q++;
        if (q < n && r[q].kind == A64PT_MARKER && r[q].type == A64PT_M_KERNEL_EVENT &&
            r[q].addr != pc)
            return count;
        int unc = 0;
        if (r[*p].type == A64PT_M_UNCOMPLETED_INSTRUCTION) {
            if ((uint32_t)r[*p].addr != word) {
                fprintf(o,
                        "  uncompleted-instruction marker value 0x%llx before the "
                        "instruction at 0x%llx, expected its encoding %08x\n",
                        (unsigned long long)r[*p].addr, (unsigned long long)pc, word);
                return -1;
            }
            unc = 1;
            cs->uncompleted++;
            (*p)++;
            skip_markers(r, n, p, cs);
        }
        if (*p >= n || r[*p].kind != A64PT_MARKER || r[*p].type != A64PT_M_KERNEL_EVENT) {
            fprintf(
                o, "  expected a kernel event before the instruction at 0x%llx, got %s\n",
                (unsigned long long)pc,
                *p >= n ? "end of trace" : rec_str(&r[*p], buf, sizeof(buf)));
            return -1;
        }
        if (r[*p].addr != pc) {
            fprintf(o,
                    "  kernel event at 0x%llx where the next instruction is 0x%llx (the "
                    "interruption point must be the next instruction)\n",
                    (unsigned long long)r[*p].addr, (unsigned long long)pc);
            return -1;
        }
        (*p)++;
        int depth = 1, sig = 0;
        while (depth > 0) {
            if (*p >= n) {
                fprintf(o, "  signal delivery at 0x%llx has no kernel xfer\n",
                        (unsigned long long)pc);
                return -1;
            }
            a64pt_rec_t *q = &r[*p];
            if (q->kind == A64PT_MARKER && q->type == A64PT_M_KERNEL_EVENT)
                depth++;
            else if (q->kind == A64PT_MARKER && q->type == A64PT_M_KERNEL_XFER)
                depth--;
            else if (q->kind == A64PT_MARKER && q->type == A64PT_M_SIGNAL_NUMBER) {
                if (depth == 1 && sig == 0)
                    sig = (int)q->addr;
            } else if (q->kind == A64PT_INSTR && q->pc >= CODE_BASE &&
                       q->pc < CODE_BASE + CODE_SIZE) {
                fprintf(o,
                        "  instruction in the code inside the signal delivery at "
                        "0x%llx: %s\n",
                        (unsigned long long)pc, rec_str(q, buf, sizeof(buf)));
                return -1;
            }
            (*p)++;
        }
        count++;
        *last_sig = sig;
        *last_unc = unc;
        if (any_unc != NULL && unc)
            (*any_unc)++;
    }
}

/* Matches one instruction and its data records at *p (after any signal
 * deliveries before it).
 */
static int
match_instr(FILE *o, xblock_t *x, xinstr_t *xi, uint16_t itype, a64pt_rec_t *r, long n,
            long *p, cmp_stats_t *cs, int *async_unc, long *at)
{
    block_t *b = x->b;
    char buf[160];
    int last_sig, last_unc, any_unc;
    int ndel = consume_deliveries(o, xi->pc, xi->word, r, n, p, cs, &last_sig, &last_unc,
                                  &any_unc);
    if (ndel < 0)
        return 0;
    if (async_unc != NULL) /* how many: one chain of deliveries can drop several */
        *async_unc = xi->sig == 0 ? any_unc : 0;
    if (at != NULL)
        *at = *p;
    if (xi->sig != 0) {
        /* A planned fault (N9): it never completes; its delivery is the last
         * one here (earlier ones were asynchronous, before it ran).
         */
        if (ndel == 0 || !last_unc || last_sig != xi->sig) {
            fprintf(o,
                    "  instruction 0x%llx (index %d: %s) faults natively with signal %d: "
                    "expected an uncompleted marker and a kernel event with that signal, "
                    "got %d deliveries (last: signal %d, %suncompleted)\n",
                    (unsigned long long)xi->pc, xi->idx, b->a.txt[xi->idx], xi->sig, ndel,
                    last_sig, last_unc ? "" : "not ");
            return 0;
        }
        cs->faults++;
        cs->async_exc += ndel - 1;
        return 1;
    }
    cs->async_exc += ndel;
    if (*p >= n || r[*p].kind != A64PT_INSTR) {
        fprintf(o, "  expected instruction 0x%llx (index %d: %s), got %s\n",
                (unsigned long long)xi->pc, xi->idx, b->a.txt[xi->idx],
                *p >= n ? "end of trace" : rec_str(&r[*p], buf, sizeof(buf)));
        return 0;
    }
    a64pt_rec_t *ri = &r[*p];
    if (ri->pc != xi->pc) {
        fprintf(o, "  expected instruction 0x%llx (index %d: %s), got %s\n",
                (unsigned long long)xi->pc, xi->idx, b->a.txt[xi->idx],
                rec_str(ri, buf, sizeof(buf)));
        return 0;
    }
    if (ri->size != 4 || ri->enc != xi->word) {
        fprintf(o,
                "  instruction 0x%llx (index %d: %s): expected size 4 encoding %08x, "
                "got %s\n",
                (unsigned long long)xi->pc, xi->idx, b->a.txt[xi->idx], xi->word,
                rec_str(ri, buf, sizeof(buf)));
        return 0;
    }
    if (ri->type != itype && itype == A64PT_T_UNTAKEN_JUMP &&
        ri->type == A64PT_T_TAKEN_JUMP && cond_target(xi->word, xi->pc) == xi->pc + 4 &&
        !strict) {
        /* Known deviation cbr-target-next: see the file comment. */
        cs->kd_cbr_next++;
    } else if (ri->type != itype) {
        fprintf(o, "  instruction 0x%llx (index %d: %s): expected type %d, got %s\n",
                (unsigned long long)xi->pc, xi->idx, b->a.txt[xi->idx], itype,
                rec_str(ri, buf, sizeof(buf)));
        return 0;
    }
    if (itype_is_indirect(itype) && ri->addr != xi->next) {
        fprintf(o,
                "  instruction 0x%llx (index %d: %s): expected indirect branch target "
                "0x%llx, got %s\n",
                (unsigned long long)xi->pc, xi->idx, b->a.txt[xi->idx],
                (unsigned long long)xi->next, rec_str(ri, buf, sizeof(buf)));
        return 0;
    }
    int ci = (int)((xi->pc - CODE_BASE) / 4);
    if ((!seen_word[ci] || last_word[ci] != ri->enc) && !ri->enc_new) {
        fprintf(o,
                "  instruction 0x%llx (index %d: %s): encoding %08x %s at this pc but "
                "encoding_is_new is not set\n",
                (unsigned long long)xi->pc, xi->idx, b->a.txt[xi->idx], ri->enc,
                seen_word[ci] ? "changed" : "is the first");
        return 0;
    }
    if (seen_word[ci] && last_word[ci] != ri->enc)
        cs->enc_changes++;
    seen_word[ci] = 1;
    last_word[ci] = ri->enc;
    (*p)++;
    cs->instrs++;
    /* Its data records, up to the next instruction. */
    for (int k = 0; k < xi->nref; k++) {
        xref_t *xr = &x->refs[xi->ref0 + k];
        skip_markers(r, n, p, cs);
        if (*p >= n || (r[*p].kind != A64PT_DATA && r[*p].kind != A64PT_FLUSH)) {
            fprintf(o,
                    "  instruction 0x%llx (index %d: %s): expected data record %d of %d "
                    "(type %d addr 0x%llx size %u), got %s\n",
                    (unsigned long long)xi->pc, xi->idx, b->a.txt[xi->idx], k + 1,
                    xi->nref, xr->type, (unsigned long long)xr->addr, xr->size,
                    *p >= n ? "end of trace" : rec_str(&r[*p], buf, sizeof(buf)));
            return 0;
        }
        a64pt_rec_t *rd = &r[*p];
        if (rd->type != xr->type || rd->addr != xr->addr ||
            (xr->chk_size && rd->size != xr->size) || rd->pc != xi->pc) {
            fprintf(o,
                    "  instruction 0x%llx (index %d: %s): data record %d of %d: expected "
                    "type %d addr 0x%llx size %u%s, got %s\n",
                    (unsigned long long)xi->pc, xi->idx, b->a.txt[xi->idx], k + 1,
                    xi->nref, xr->type, (unsigned long long)xr->addr, xr->size,
                    xr->chk_size ? "" : " (unchecked)", rec_str(rd, buf, sizeof(buf)));
            return 0;
        }
        (*p)++;
        cs->refs++;
    }
    skip_markers(r, n, p, cs);
    if (*p < n && r[*p].kind != A64PT_INSTR && !is_event_marker(&r[*p])) {
        fprintf(o, "  instruction 0x%llx (index %d: %s): unexpected extra record %s\n",
                (unsigned long long)xi->pc, xi->idx, b->a.txt[xi->idx],
                rec_str(&r[*p], buf, sizeof(buf)));
        return 0;
    }
    return 1;
}

/* An asynchronous delivery with an uncompleted marker before expected entry i,
 * whose instruction record is at trace position p.
 */
typedef struct {
    int i;
    long p;
} drop_cand_t;
#define MAX_DROP_CANDS 64

/* For known deviation async-loop-drop: the entry after one iteration of the
 * loop that starts at entry ci (the next entry with the same pc, reached by a
 * branch back to it), or -1.  (Whether raw2trace can tell depends on which
 * addresses the tracer elided, which the oracle does not model: the skipped
 * iteration may have data records.)
 */
static int
next_iteration(xblock_t *x, int ci)
{
    for (int j = ci + 1; j < x->nins; j++) {
        xinstr_t *xj = &x->ins[j];
        if (xj->loop || xj->sig != 0)
            return -1;
        if (xj->pc == x->ins[ci].pc)
            return x->ins[j - 1].next == xj->pc ? j : -1;
    }
    return -1;
}

/* Known deviation async-loop-drop, at the loop's exit: the trace leaves the
 * loop whose back-edge is entry i (a conditional branch expected taken, seen
 * untaken) m iterations early.  Returns the entry of the branch's untaken
 * execution, after which matching continues, if there are at least m unused
 * asynchronous deliveries with uncompleted markers inside the loop (pcs
 * drop_pc[*nused..ndrop-1]), consuming them; else -1.  Unlike the retries in
 * match_from() this costs no backtracking, so any number of dropped
 * iterations is handled (a loaded machine gets many deliveries per loop).
 */
static int
skip_dropped_iterations(xblock_t *x, int i, a64pt_rec_t *rec, const uint64_t *drop_pc,
                        int ndrop, int *nused, int *m_out)
{
    xinstr_t *xi = &x->ins[i];
    if (rec->kind != A64PT_INSTR || rec->pc != xi->pc ||
        branch_class(xi->word) != BR_COND || xi->itype != A64PT_T_TAKEN_JUMP ||
        rec->type != A64PT_T_UNTAKEN_JUMP)
        return -1;
    uint64_t head = cond_target(xi->word, xi->pc);
    if (head > xi->pc)
        return -1;
    int m = 0, j;
    for (j = i; j < x->nins; j++) {
        xinstr_t *xj = &x->ins[j];
        if (xj->loop || xj->sig != 0 || xj->pc < head || xj->pc > xi->pc)
            return -1;
        if (xj->pc == xi->pc) {
            if (xj->itype == A64PT_T_UNTAKEN_JUMP)
                break;
            m++;
        }
    }
    if (j >= x->nins || m == 0)
        return -1;
    int avail = 0;
    for (int k = *nused; k < ndrop; k++) {
        if (drop_pc[k] >= head && drop_pc[k] <= xi->pc)
            avail++;
    }
    if (avail < m)
        return -1;
    *nused = ndrop;
    *m_out = m;
    return j;
}

/* Matches entries i0.. of x and the end of the run at r[*p].  On a mismatch it
 * retries, before reporting it, every earlier asynchronous uncompleted delivery
 * as a dropped loop iteration (known deviation async-loop-drop).
 */
static int
match_from(FILE *out, xblock_t *x, a64pt_rec_t *r, long n, long *p, int i0,
           uint64_t host_ret, cmp_stats_t *cs, int depth)
{
    char buf[160];
    char *mbuf = NULL;
    size_t msize = 0;
    FILE *o = open_memstream(&mbuf, &msize);
    drop_cand_t cand[MAX_DROP_CANDS];
    int ncand = 0, ok = 1;
    uint64_t *drop_pc = NULL;
    int ndrop = 0, cap_drop = 0, nused = 0;
    for (int i = i0; i < x->nins && ok;) {
        xinstr_t *xi = &x->ins[i];
        if (!xi->loop) {
            int async_unc = 0;
            long at = -1;
            if (!match_instr(o, x, xi, xi->itype, r, n, p, cs, &async_unc, &at)) {
                int m = 0;
                int j = strict || *p >= n
                    ? -1
                    : skip_dropped_iterations(x, i, &r[*p], drop_pc, ndrop, &nused, &m);
                if (j >= 0) {
                    cs->kd_async_drop += m;
                    cs->drop_skipped += j - i;
                    i = j;
                    continue;
                }
                print_context(o, r, n, *p);
                ok = 0;
                break;
            }
            for (int k = 0; k < async_unc; k++) {
                if (ndrop >= cap_drop) {
                    cap_drop = cap_drop == 0 ? 64 : 2 * cap_drop;
                    drop_pc = realloc(drop_pc, sizeof(uint64_t) * cap_drop);
                }
                drop_pc[ndrop++] = xi->pc;
            }
            if (async_unc && ncand < MAX_DROP_CANDS) {
                cand[ncand].i = i;
                cand[ncand].p = at;
                ncand++;
            }
            if (is_svc(xi->word) && !strict) {
                /* Known deviation syscall-signal-dup: a delivery at the svc
                 * just recorded, after which the svc runs (again).
                 */
                long q = *p;
                skip_markers(r, n, &q, cs);
                while (q < n && r[q].kind == A64PT_MARKER &&
                       r[q].type == A64PT_M_UNCOMPLETED_INSTRUCTION)
                    q++;
                if (q < n && r[q].kind == A64PT_MARKER &&
                    r[q].type == A64PT_M_KERNEL_EVENT && r[q].addr == xi->pc) {
                    cs->kd_syscall_dup++;
                    continue; /* match the svc again, after the delivery */
                }
            }
            i++;
            continue;
        }
        int len = xi->loop_end - xi->idx;
        cs->loops++;
        for (int iter = 0; ok; iter++) {
            if (iter > 100000) {
                fprintf(o, "  exclusive loop at 0x%llx never ends\n",
                        (unsigned long long)xi->pc);
                ok = 0;
                break;
            }
            int done = 0;
            for (int j = 0; j < len; j++) {
                xinstr_t *xj = &x->ins[i + j];
                uint16_t t = xj->itype;
                if (j == len - 1) {
                    /* The CBNZ: taken back to the head, or not, in this
                     * iteration; the trace decides which, and then must agree
                     * with itself.
                     */
                    long q = peek_instr(r, n, *p);
                    if (q < n && r[q].pc == xj->pc && r[q].type == A64PT_T_TAKEN_JUMP)
                        t = A64PT_T_TAKEN_JUMP;
                    else {
                        t = A64PT_T_UNTAKEN_JUMP;
                        done = 1;
                    }
                }
                if (!match_instr(o, x, xj, t, r, n, p, cs, NULL, NULL)) {
                    fprintf(o, "  (in iteration %d of an exclusive loop)\n", iter + 1);
                    print_context(o, r, n, *p);
                    ok = 0;
                    break;
                }
            }
            if (!ok)
                break;
            cs->loop_iters++;
            if (done)
                break;
        }
        i += len;
    }
    if (ok) {
        int last_sig, last_unc;
        if (consume_deliveries(o, host_ret, *(uint32_t *)host_ret, r, n, p, cs, &last_sig,
                               &last_unc, NULL) < 0) {
            print_context(o, r, n, *p);
            ok = 0;
        } else if (*p >= n || r[*p].kind != A64PT_INSTR || r[*p].pc != host_ret) {
            fprintf(o,
                    "  expected the return to the trampoline (0x%llx) after the run, "
                    "got %s\n",
                    (unsigned long long)host_ret,
                    *p >= n ? "end of trace" : rec_str(&r[*p], buf, sizeof(buf)));
            print_context(o, r, n, *p);
            ok = 0;
        } else
            (*p)++;
    }
    if (!ok && !strict && depth < 8) {
        for (int k = ncand - 1; k >= 0; k--) {
            int j = next_iteration(x, cand[k].i);
            if (j < 0)
                continue;
            long pp = cand[k].p;
            if (match_from(NULL, x, r, n, &pp, j, host_ret, cs, depth + 1)) {
                cs->kd_async_drop++;
                cs->drop_skipped += j - cand[k].i;
                *p = pp;
                ok = 1;
                break;
            }
        }
    }
    fclose(o);
    if (!ok && out != NULL)
        fputs(mbuf, out);
    free(mbuf);
    free(drop_pc);
    return ok;
}

/* Matches one run starting at r[*p] (the trampoline's br into the code).
 * Returns 1 if it matches.
 */
static int
match_run(FILE *o, xblock_t *x, a64pt_rec_t *r, long n, long *p, uint64_t host_ret,
          cmp_stats_t *cs)
{
    char buf[160];
    if (r[*p].kind != A64PT_INSTR || r[*p].pc != host_ret - 4 ||
        r[*p].type != A64PT_T_INDIRECT_JUMP || r[*p].addr != CODE_BASE) {
        fprintf(o,
                "  the run does not start with the trampoline's br x0 to the entry: %s\n",
                rec_str(&r[*p], buf, sizeof(buf)));
        print_context(o, r, n, *p);
        return 0;
    }
    (*p)++;
    if (!match_from(o, x, r, n, p, 0, host_ret, cs, 0))
        return 0;
    cs->runs++;
    return 1;
}

/* Skips to after the run's return to the trampoline, noting the encodings seen
 * (for T4 in later runs).
 */
static long
skip_run(a64pt_rec_t *r, long n, long p, uint64_t host_ret)
{
    for (; p < n && !(r[p].kind == A64PT_INSTR && r[p].pc == host_ret); p++) {
        if (r[p].kind == A64PT_INSTR && r[p].pc >= CODE_BASE &&
            r[p].pc < CODE_BASE + CODE_SIZE) {
            int ci = (int)((r[p].pc - CODE_BASE) / 4);
            seen_word[ci] = 1;
            last_word[ci] = r[p].enc;
        }
    }
    return p < n ? p + 1 : p;
}

/***************************************************************************
 * The DR child.
 */
enum {
    ST_RUNS,            /* runs executed under DR */
    ST_RUNS_CHECKED,    /* runs whose trace was compared */
    ST_TRANSPARENCY,    /* runs whose final state differed from native */
    ST_INSTRS,          /* instruction records compared */
    ST_REFS,            /* data records compared */
    ST_MARKERS,         /* markers skipped inside runs */
    ST_LOOPS,           /* exclusive loops matched */
    ST_LOOP_ITERS,      /* ...and their iterations */
    ST_TRACE_INSTRS,    /* instructions in the whole trace */
    ST_TRACE_DATA,      /* data records in the whole trace */
    ST_ENC_CHANGES,     /* instruction records whose encoding changed at their pc */
    ST_SELFCHECK,       /* perturbed expectations the comparison rejected */
    ST_KD_CBR_NEXT,     /* known deviation cbr-target-next */
    ST_FAULTS,          /* planned faults matched to their deliveries */
    ST_ASYNC,           /* asynchronous deliveries inside runs */
    ST_UNCOMPLETED,     /* uncompleted-instruction markers */
    ST_DEAD_REGS,       /* dead-register differences in fault frames (drreg) */
    ST_KD_FRAME_PSTATE, /* known DR deviation: BTYPE/SSBS in fault frames */
    ST_KD_DEAD_DEST,    /* known drreg deviation: skipped faulting load's dests */
    ST_KD_ASYNC_DROP,   /* known raw2trace deviation: async-loop-drop */
    ST_DROP_SKIPPED,    /* ...and the expected instructions it skipped */
    ST_KD_SYSCALL_DUP,  /* known tracer deviation: syscall-signal-dup */
};

typedef struct {
    const tvariant_t *v;
    a64p_worker_t *w;
    xblock_t *xb;
    int n, runs;
    uint64_t host_ret;
} child_args_t;

static int
rm_cb(const char *path, const struct stat *sb, int flag, struct FTW *ftw)
{
    (void)sb;
    (void)flag;
    (void)ftw;
    return remove(path);
}

/* Liveness by perturbation: a native rerun that, at fault hook_fault, puts
 * hook_val into register hook_reg of the frame (31: NZCV) before resuming.
 */
static int hook_fault = -1, hook_reg = -1;
static uint64_t hook_val;

static void
perturb_hook(a64p_worker_t *w, int n, ucontext_t *uc)
{
    (void)w;
    if (n != hook_fault)
        return;
    if (hook_reg < 31)
        uc->uc_mcontext.regs[hook_reg] = hook_val;
    else
        uc->uc_mcontext.pstate = (uc->uc_mcontext.pstate & ~0xf0000000ULL) | hook_val;
}

/* Whether giving register reg (31: NZCV) the value val in the frame of fault
 * k leaves the native run's outcome unchanged, i.e. the register is dead
 * there.
 */
static int
dead_at_fault(a64p_worker_t *w, xblock_t *x, int k, int reg, uint64_t val)
{
    static result_t pert;
    static FILE *null;
    if (null == NULL)
        null = fopen("/dev/null", "w");
    hook_fault = k;
    hook_reg = reg;
    hook_val = val;
    a64p_fault_hook = perturb_hook;
    a64p_run_block(w, x->b, &pert);
    a64p_fault_hook = NULL;
    hook_fault = -1;
    /* The outcome: final state, memory and where later faults happen.  (A
     * later fault's frame may show the value: that is not a read by the
     * application, which is what drreg's liveness is about.)
     */
    int bad = a64p_cmp_state(null, "final", &x->native.out, &pert.out, -1, 0, -1, 0);
    bad += a64p_cmp_mem(null, x->b, &x->native, &pert);
    if (pert.nf != x->native.nf)
        bad++;
    for (int i = k + 1; i < x->native.nf && i < pert.nf && i < MAXF; i++) {
        if (pert.f[i].pc != x->native.f[i].pc ||
            pert.f[i].signo != x->native.f[i].signo ||
            pert.f[i].addr != x->native.f[i].addr)
            bad++;
    }
    return bad == 0;
}

/* The general registers a faulting memory instruction w (with access model m)
 * would have written had it completed: a load's Rt (and Rt2 for a pair), an
 * LSE atomic's Rt, a CAS's Rs (CASP: Rs, Rs+1).  SIMD loads write no general
 * register.  Returns a bit mask.
 */
static uint32_t
load_dest_gprs(uint32_t w, meminfo_t *m)
{
    uint32_t rt = w & 31, rt2 = (w >> 10) & 31, rs = (w >> 16) & 31, mask = 0;
    int v = (w >> 26) & 1;
    if (!m->valid)
        return 0;
    if (m->acc == MA_R && !v) {
        if (rt != 31)
            mask |= 1u << rt;
        /* LDP/LDNP/LDPSW, and LDXP/LDAXP (exclusive pair: bit 21). */
        if ((is_pair(w) || ((w & 0x3f000000u) == 0x08000000u && ((w >> 21) & 1))) &&
            rt2 != 31)
            mask |= 1u << rt2;
    } else if (m->acc == MA_RW) {
        if ((w & 0x3f800000u) == 0x08800000u && ((w >> 21) & 1)) {
            /* CAS (bit 31 set) or CASP (bit 31 clear): Rs, Rs+1. */
            mask |= 1u << rs;
            if (!(w >> 31))
                mask |= 1u << (rs + 1);
        } else if (rt != 31)
            mask |= 1u << rt; /* LD<op>, SWP */
    }
    return mask & 0x7fffffffu;
}

static uint32_t dd_mask[MAXF];
static uint64_t dd_val[MAXF][31];

static void
dead_dest_hook(a64p_worker_t *w, int n, ucontext_t *uc)
{
    (void)w;
    if (n >= MAXF)
        return;
    for (int r = 0; r < 31; r++) {
        if (dd_mask[n] & (1u << r))
            uc->uc_mcontext.regs[r] = dd_val[n][r];
    }
}

/* drreg's documented dead-register latitude also covers the destinations of a
 * faulting load, which are dead at the fault if the load were to complete; a
 * handler that skips the load (as ours does) then lets the application read
 * them.  Whether that explains all of d: a native rerun that gives each
 * fault's frame DR's values for those registers must end exactly as d did.
 */
static int
explained_by_dead_dests(a64p_worker_t *w, xblock_t *x, result_t *d)
{
    static result_t rr;
    static FILE *null;
    if (null == NULL)
        null = fopen("/dev/null", "w");
    result_t *n = &x->native;
    if (n->nf != d->nf || n->nf > MAXF)
        return 0;
    int any = 0;
    for (int k = 0; k < n->nf; k++) {
        if (n->f[k].pc != d->f[k].pc || n->f[k].signo != d->f[k].signo ||
            n->f[k].addr != d->f[k].addr)
            return 0;
        int idx = (int)((n->f[k].pc - CODE_BASE) / 4);
        uint32_t dests = load_dest_gprs(x->b->a.w[idx], &x->b->a.mi[idx]);
        dd_mask[k] = 0;
        for (int r = 0; r < 31; r++) {
            if ((dests & (1u << r)) && n->f[k].x[r] != d->f[k].x[r]) {
                dd_mask[k] |= 1u << r;
                dd_val[k][r] = d->f[k].x[r];
                any = 1;
            }
        }
    }
    if (!any)
        return 0;
    a64p_fault_hook = dead_dest_hook;
    a64p_run_block(w, x->b, &rr);
    a64p_fault_hook = NULL;
    memset(dd_mask, 0, sizeof(dd_mask));
    int bad = a64p_cmp_state(null, "final", &rr.out, &d->out, -1, 0, -1, 0);
    bad += a64p_cmp_mem(null, x->b, &rr, d);
    if (rr.nf != d->nf)
        bad++;
    for (int k = 0; k < rr.nf && k < d->nf && k < MAXF; k++) {
        if (rr.f[k].pc != d->f[k].pc || rr.f[k].signo != d->f[k].signo)
            bad++;
    }
    return bad == 0;
}

/* Compares a DR run with the native one.  drmemtrace's tracer uses drreg in
 * its default, non-conservative mode, which documents (drreg.h,
 * drreg_options_t.conservative) that a dead register (or dead NZCV) may hold
 * another value in a fault's frame: a register difference in a fault frame is
 * accepted (and counted in *ndead) if a native rerun with DR's value in that
 * frame has the same outcome.  Returns the number of differences.
 */
static int
cmp_dr_run(FILE *o, a64p_worker_t *w, xblock_t *x, result_t *d, long *ndead)
{
    result_t *n = &x->native;
    int bad = a64p_cmp_state(o, "final", &n->out, &d->out, -1, 0, -1, 0);
    bad += a64p_cmp_mem(o, x->b, n, d);
    if (n->nf != d->nf) {
        fprintf(o, "    fault count native %d  dr %d\n", n->nf, d->nf);
        return bad + 1;
    }
    if (bad != 0)
        return bad;
    for (int i = 0; i < n->nf && i < MAXF; i++) {
        fault_rec_t df = d->f[i];
        for (int r = 0; r < 31; r++) {
            if (df.x[r] != n->f[i].x[r] && dead_at_fault(w, x, i, r, df.x[r])) {
                df.x[r] = n->f[i].x[r];
                (*ndead)++;
            }
        }
        if (((df.pstate ^ n->f[i].pstate) & 0xf0000000ULL) != 0 &&
            dead_at_fault(w, x, i, 31, df.pstate & 0xf0000000ULL)) {
            df.pstate = (df.pstate & ~0xf0000000ULL) | (n->f[i].pstate & 0xf0000000ULL);
            (*ndead)++;
        }
        bad += a64p_cmp_fault(o, i, &n->f[i], &df);
    }
    return bad;
}

/* PSTATE.BTYPE and SSBS in DR's fault frames: known DR deviations (see
 * api.a64_prop_bti and a64_dr_prop), not drmemtrace's: counted.
 */
#define PSTATE_BTYPE_ (3ULL << 10)
#define PSTATE_SSBS_ (1ULL << 12)
static long masked_pstate;

static void
on_masked_pstate(int i, fault_rec_t *n, fault_rec_t *d)
{
    (void)i;
    (void)n;
    (void)d;
    masked_pstate++;
}

/* Executable file mappings and the vdso, from /proc/self/maps. */
static int
exec_ranges(uint64_t *ranges, int max)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (f == NULL)
        return 0;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), f) != NULL && n < max) {
        unsigned long long lo, hi;
        char perms[8], path[256] = "";
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %255s", &lo, &hi, perms, path) < 3)
            continue;
        if (perms[2] != 'x')
            continue;
        if (path[0] != '/' && strcmp(path, "[vdso]") != 0)
            continue;
        ranges[2 * n] = lo;
        ranges[2 * n + 1] = hi;
        n++;
    }
    fclose(f);
    return n;
}

static int
trace_child(void *arg)
{
    child_args_t *ca = arg;
    const tvariant_t *v = ca->v;
    progress_t *prog = a64p_prog;
    a64p_worker_t *w = ca->w;
    if (!strict) {
        a64p_fault_pstate_ignore = PSTATE_BTYPE_ | PSTATE_SSBS_;
        a64p_on_masked_pstate = on_masked_pstate;
    }
    const char *base = getenv("A64PT_DIR");
    char outdir[512];
    snprintf(outdir, sizeof(outdir), "%s/a64_prop_trace.%s.%d", base == NULL ? "." : base,
             v->name, (int)getpid());
    if (mkdir(outdir, 0755) != 0) {
        fprintf(stderr, "ERROR: cannot create %s\n", outdir);
        return 1;
    }
    char ops[2048];
    const char *env = getenv("DYNAMORIO_OPTIONS");
    snprintf(ops, sizeof(ops),
             "%s -stderr_mask 0xc -client_lib ';;-offline -outdir %s %s' %s",
             env == NULL ? "" : env, outdir, v->tracer_ops, v->dr_ops);
    setenv("DYNAMORIO_OPTIONS", ops, 1);
    result_t *res = malloc(sizeof(result_t) * (size_t)ca->n * ca->runs);
    snprintf(prog->phase, sizeof(prog->phase), "dr start");
    a64p_start_dr("");
    if (v->async_us > 0) {
        /* The handler (a64_prop_support's async_handler) does nothing while
         * async_on is 0: each delivery is a pure excursion.
         */
        w->async_on = 0;
        w->xres = w->vres = -1;
        /* A64PT_ASYNC_US overrides the interval (a shorter one approximates
         * a loaded machine: more deliveries per block).
         */
        long us = getenv("A64PT_ASYNC_US") != NULL ? atol(getenv("A64PT_ASYNC_US"))
                                                   : v->async_us;
        struct itimerval it = { { 0, us }, { 0, us } };
        if (setitimer(ITIMER_REAL, &it, NULL) != 0) {
            fprintf(stderr, "ERROR: setitimer failed\n");
            return 1;
        }
    }
    for (int i = 0; i < ca->n; i++) {
        xblock_t *x = &ca->xb[i];
        if (!x->valid)
            continue;
        prog->block = i;
        prog->seed = x->b->seed;
        snprintf(prog->phase, sizeof(prog->phase), "run");
        a64p_install_code(w, x->b, 0);
        for (int r = 0; r < ca->runs; r++) {
            prog->run = r;
            a64p_run_block(w, x->b, &res[(size_t)i * ca->runs + r]);
            prog->stat[ST_RUNS]++;
        }
    }
    if (v->async_us > 0) {
        struct itimerval it = { { 0, 0 }, { 0, 0 } };
        setitimer(ITIMER_REAL, &it, NULL);
    }
    snprintf(prog->phase, sizeof(prog->phase), "dr stop");
    a64p_stop_dr();
    prog->block = -1;
    uint64_t ranges[2 * 64];
    int nranges = exec_ranges(ranges, 64);
    int fails = 0;
    /* Transparency first: a run whose state differs is not compared further
     * (diverged 1), nor one whose difference is the known drreg deviation
     * (diverged 2: its control flow may differ from the native one).
     */
    uint8_t *diverged = calloc((size_t)ca->n * ca->runs, 1);
    FILE *devnull = fopen("/dev/null", "w");
    long ndead = 0;
    for (int i = 0; i < ca->n; i++) {
        xblock_t *x = &ca->xb[i];
        if (!x->valid)
            continue;
        a64p_install_code(w, x->b, 0);
        for (int r = 0; r < ca->runs; r++) {
            result_t *d = &res[(size_t)i * ca->runs + r];
            if (cmp_dr_run(devnull, w, x, d, &ndead) != 0 && !strict &&
                explained_by_dead_dests(w, x, d)) {
                /* Known deviation drreg-dead-dest: see the file comment. */
                prog->stat[ST_KD_DEAD_DEST]++;
                diverged[(size_t)i * ca->runs + r] = 2;
            } else if (cmp_dr_run(stderr, w, x, d, &ndead) != 0) {
                fprintf(stderr,
                        "FAIL [trace] variant=%s seed %llu run %d: final state differs "
                        "from native (transparency, not a tracer property)\n",
                        v->name, (unsigned long long)x->b->seed, r);
                diverged[(size_t)i * ca->runs + r] = 1;
                prog->stat[ST_TRANSPARENCY]++;
                fails++;
            }
        }
    }
    prog->stat[ST_DEAD_REGS] = ndead;
    prog->stat[ST_KD_FRAME_PSTATE] = masked_pstate;
    snprintf(prog->phase, sizeof(prog->phase), "raw2trace");
    char tdir[1024], err[1024];
    if (!a64pt_post_process(outdir, tdir, sizeof(tdir), err, sizeof(err))) {
        fprintf(stderr, "FAIL [trace] variant=%s: %s (raw files in %s)\n", v->name, err,
                outdir);
        return fails + 1;
    }
    snprintf(prog->phase, sizeof(prog->phase), "read");
    a64pt_rec_t *recs;
    a64pt_stats_t st;
    long n = a64pt_read(tdir, CODE_BASE, CODE_BASE + CODE_SIZE, ca->host_ret - 4,
                        ca->host_ret, ranges, nranges, &recs, &st, err, sizeof(err));
    if (n < 0) {
        fprintf(stderr, "FAIL [trace] variant=%s: %s (trace in %s)\n", v->name, err,
                tdir);
        return fails + 1;
    }
    prog->stat[ST_TRACE_INSTRS] = st.ninstrs;
    prog->stat[ST_TRACE_DATA] = st.ndata;
    if (st.nthreads != 1) {
        fprintf(stderr, "FAIL [trace] variant=%s: %d threads in the trace, expected 1\n",
                v->name, st.nthreads);
        fails++;
    }
    if (st.ncode_outside_runs != 0) {
        fprintf(stderr,
                "FAIL [trace] variant=%s: %ld instructions in the code outside runs "
                "(first at 0x%llx)\n",
                v->name, st.ncode_outside_runs,
                (unsigned long long)st.first_code_outside_runs);
        fails++;
    }
    if (st.nbad_pc != 0) {
        fprintf(stderr,
                "FAIL [trace] variant=%s: %ld instructions outside the application's "
                "code (first at 0x%llx)\n",
                v->name, st.nbad_pc, (unsigned long long)st.first_bad_pc);
        fails++;
    }
    snprintf(prog->phase, sizeof(prog->phase), "compare");
    last_word = calloc(CODE_SIZE / 4, sizeof(uint32_t));
    seen_word = calloc(CODE_SIZE / 4, 1);
    cmp_stats_t cs;
    memset(&cs, 0, sizeof(cs));
    long p = 0;
    int nfail_reported = 0;
    xblock_t *first_ok = NULL;
    long first_ok_at = -1;
    for (int i = 0; i < ca->n; i++) {
        xblock_t *x = &ca->xb[i];
        if (!x->valid)
            continue;
        prog->block = i;
        prog->seed = x->b->seed;
        for (int r = 0; r < ca->runs; r++) {
            prog->run = r;
            if (p >= n) {
                fprintf(stderr,
                        "FAIL [trace] variant=%s seed %llu run %d: the trace has no run "
                        "for it\n",
                        v->name, (unsigned long long)x->b->seed, r);
                fails++;
                goto done;
            }
            long start = p;
            FILE *o = nfail_reported < 3 ? stderr : fopen("/dev/null", "w");
            if (diverged[(size_t)i * ca->runs + r] != 0) {
                /* Skip to the end of this run. */
                p = skip_run(recs, n, p + 1, ca->host_ret);
            } else if (!match_run(o, x, recs, n, &p, ca->host_ret, &cs)) {
                fprintf(
                    o,
                    "FAIL [trace] variant=%s seed %llu run %d (trace records from "
                    "%ld; trace in %s)\n  repro: a64_prop_trace -seed %llu -n 1 "
                    "-variants %s -keep -v\n",
                    v->name, (unsigned long long)x->b->seed, r, start, tdir,
                    /* -seed is the base before the set's offset. */
                    (unsigned long long)(x->b->seed - (uint64_t)v->blockset * 1000000),
                    v->name);
                if (o == stderr && verbose)
                    print_block(stderr, x->b);
                fails++;
                nfail_reported++;
                /* Resynchronise at the next return to the trampoline. */
                p = skip_run(recs, n, p, ca->host_ret);
            } else {
                prog->stat[ST_RUNS_CHECKED]++;
                if (first_ok == NULL) {
                    first_ok = x;
                    first_ok_at = start;
                }
            }
            if (o != stderr)
                fclose(o);
        }
    }
    if (p < n) {
        char buf[160];
        fprintf(stderr, "FAIL [trace] variant=%s: %ld records after the last run: %s\n",
                v->name, n - p, rec_str(&recs[p], buf, sizeof(buf)));
        fails++;
    }
    /* The comparison must be able to fail: perturbed expectations of the first
     * matching run (a data address, an instruction type, an encoding) are
     * rejected.
     */
    if (first_ok != NULL) {
        FILE *null = fopen("/dev/null", "w");
        xblock_t *x = first_ok;
        int nperturbed = 0, rejected = 0;
        for (int kind = 0; kind < 3; kind++) {
            int at = -1;
            for (int i = x->nins / 3; i < x->nins && at < 0; i++) {
                if (x->ins[i].loop)
                    break;
                if (kind != 0 || x->ins[i].nref > 0)
                    at = i;
            }
            if (at < 0)
                continue;
            xinstr_t save = x->ins[at];
            xref_t rsave;
            memset(&rsave, 0, sizeof(rsave));
            if (kind == 0) {
                rsave = x->refs[save.ref0];
                x->refs[save.ref0].addr += 8;
            } else if (kind == 1) {
                x->ins[at].itype =
                    save.itype == A64PT_T_INSTR ? A64PT_T_DIRECT_JUMP : A64PT_T_INSTR;
            } else
                x->ins[at].word ^= 1u << 12;
            cmp_stats_t scratch;
            memset(&scratch, 0, sizeof(scratch));
            long q = first_ok_at;
            nperturbed++;
            if (!match_run(null, x, recs, n, &q, ca->host_ret, &scratch))
                rejected++;
            x->ins[at] = save;
            if (kind == 0)
                x->refs[save.ref0] = rsave;
        }
        fclose(null);
        prog->stat[ST_SELFCHECK] = rejected;
        if (nperturbed == 0 || rejected != nperturbed) {
            fprintf(stderr,
                    "FAIL [trace] variant=%s: self-check: %d of %d perturbed "
                    "expectations were accepted\n",
                    v->name, nperturbed - rejected, nperturbed);
            fails++;
        }
    }
done:
    prog->stat[ST_ENC_CHANGES] = cs.enc_changes;
    prog->stat[ST_KD_CBR_NEXT] = cs.kd_cbr_next;
    prog->stat[ST_KD_ASYNC_DROP] = cs.kd_async_drop;
    prog->stat[ST_DROP_SKIPPED] = cs.drop_skipped;
    prog->stat[ST_KD_SYSCALL_DUP] = cs.kd_syscall_dup;
    prog->stat[ST_FAULTS] = cs.faults;
    prog->stat[ST_ASYNC] = cs.async_exc;
    prog->stat[ST_UNCOMPLETED] = cs.uncompleted;
    prog->stat[ST_INSTRS] = cs.instrs;
    prog->stat[ST_REFS] = cs.refs;
    prog->stat[ST_MARKERS] = cs.markers;
    prog->stat[ST_LOOPS] = cs.loops;
    prog->stat[ST_LOOP_ITERS] = cs.loop_iters;
    free(recs);
    if (fails == 0 && !keep_dirs)
        nftw(outdir, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
    else
        fprintf(stderr, "  [trace] variant=%s: trace kept in %s\n", v->name, outdir);
    return fails;
}

/***************************************************************************
 * Driver.
 */
static void
opts_for(gen_opts_t *o, int bs)
{
    memset(o, 0, sizeof(*o));
    o->allow_excl = 1;
    o->allow_svc = 1;
    o->allow_fpcr = 1;
    o->allow_faults = bs == BS_FAULTS;
    o->len = 50;
    o->dyn_max = 2000;
}

static const char *const bs_names[BS_N] = { "plain", "faults" };

typedef struct {
    xblock_t *xb;
    a64p_counts_t c;
    long nexp_instrs, nexp_refs, nexp_faults;
} blockset_t;

/* Generates n blocks of set bs, runs each natively twice (it must be
 * deterministic) and single-steps it.  Returns 0 on a generator or harness
 * bug.
 */
static int
make_blockset(blockset_t *set, int bs, uint64_t seed, int n, a64p_worker_t *w,
              uint64_t *host_ret)
{
    set->xb = calloc((size_t)n, sizeof(xblock_t));
    trace_t t;
    memset(&t, 0, sizeof(t));
    t.cap = 200000;
    t.steps = malloc(sizeof(tstep_t) * t.cap);
    result_t *again = malloc(sizeof(result_t));
    FILE *devnull = fopen("/dev/null", "w");
    a64p_counts_t *c = &set->c;
    for (int i = 0; i < n; i++) {
        xblock_t *x = &set->xb[i];
        x->b = malloc(sizeof(block_t));
        gen_opts_t o;
        opts_for(&o, bs);
        c->generated++;
        if (!a64p_make_block(x->b, &o, seed + (uint64_t)i)) {
            c->inconclusive++;
            fprintf(stderr, "NOTE: seed %llu: generation failed\n",
                    (unsigned long long)(seed + i));
            continue;
        }
        if (x->b->wild_branch) {
            /* A wild (PAC-failed) branch ends the block from outside the code:
             * not modelled here.
             */
            c->inconclusive++;
            continue;
        }
        a64p_install_code(w, x->b, 0);
        a64p_run_block(w, x->b, &x->native);
        if (!a64p_check_planned(x->b, &x->native) ||
            (bs == BS_PLAIN && x->native.nf != 0)) {
            fprintf(stderr, "GENERATOR BUG: seed %llu: unplanned native fault\n",
                    (unsigned long long)x->b->seed);
            a64p_print_faults(stderr, "native", &x->native);
            print_block(stderr, x->b);
            return 0;
        }
        *host_ret = w->harn->host_ret;
        a64p_run_block(w, x->b, again);
        if (a64p_cmp_results(devnull, x->b, &x->native, again) != 0) {
            fprintf(stderr, "NOTE: seed %llu: not deterministic natively; skipped\n",
                    (unsigned long long)x->b->seed);
            c->inconclusive++;
            continue;
        }
        int steps =
            a64p_trace_run(w, x->b, &t, A64P_TRACE_WHOLE_RUN | A64P_TRACE_EXCL_HEAD);
        if (steps <= 0) {
            fprintf(stderr, "NOTE: seed %llu: native trace failed; skipped\n",
                    (unsigned long long)x->b->seed);
            c->inconclusive++;
            continue;
        }
        if (!build_expected(x, &t, *host_ret)) {
            c->inconclusive++;
            continue;
        }
        x->valid = 1;
        c->accepted++;
        set->nexp_instrs += x->nins - x->nfaults;
        set->nexp_refs += x->nrefs;
        set->nexp_faults += x->nfaults;
        if (verbose)
            print_block(stdout, x->b);
    }
    fclose(devnull);
    free(again);
    free(t.steps);
    printf("trace %s blocks: %ld generated, %ld accepted: %ld instructions, %ld data "
           "records and %ld faults expected per run\n",
           bs_names[bs], c->generated, c->accepted, set->nexp_instrs, set->nexp_refs,
           set->nexp_faults);
    return 1;
}

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

int
main(int argc, const char *argv[])
{
    uint64_t seed = 1;
    int n = 128, runs = 2;
    const char *vlist = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc)
            seed = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            n = atoi(argv[++i]);
        else if (strcmp(argv[i], "-runs") == 0 && i + 1 < argc)
            runs = atoi(argv[++i]);
        else if (strcmp(argv[i], "-variants") == 0 && i + 1 < argc)
            vlist = argv[++i];
        else if (strcmp(argv[i], "-keep") == 0)
            keep_dirs = 1;
        else if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if (vlist != NULL) {
        for (const char *p = vlist; *p != '\0';) {
            const char *e = strchr(p, ',');
            size_t len = e == NULL ? strlen(p) : (size_t)(e - p);
            int ok = 0;
            for (int i = 0; i < NTVARIANTS; i++) {
                if (strlen(tvariants[i].name) == len &&
                    strncmp(tvariants[i].name, p, len) == 0)
                    ok = 1;
            }
            if (!ok) {
                fprintf(stderr, "unknown variant in %s\n", vlist);
                return 2;
            }
            p = e == NULL ? p + len : e + 1;
        }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    strict = getenv("A64PT_STRICT") != NULL && atoi(getenv("A64PT_STRICT")) != 0;
    if (!a64p_init_features()) {
        printf("SKIP: DC ZVA block size is not 64 bytes\n");
        return 0;
    }
    uint64_t dczid;
    __asm__ volatile("mrs %0, dczid_el0" : "=r"(dczid));
    dczva_bytes = 4ULL << (dczid & 15);
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    dline_bytes = 4ULL << ((ctr >> 16) & 15);
    iline_bytes = 4ULL << (ctr & 15);
    a64p_progress_init("a64_prop_trace");
    static a64p_worker_t w;
    a64p_worker_init(&w);
    a64p_worker_bind(&w);
    a64p_setup_maps();
    a64p_install_handlers(&w, 0);

    /* The block sets the selected variants need. */
    blockset_t sets[BS_N];
    memset(sets, 0, sizeof(sets));
    int need[BS_N] = { 0 };
    for (int vi = 0; vi < NTVARIANTS; vi++) {
        if (vlist == NULL || list_has(vlist, tvariants[vi].name))
            need[tvariants[vi].blockset] = 1;
    }
    uint64_t host_ret = 0;
    int fails = 0;
    a64p_counts_t c;
    memset(&c, 0, sizeof(c));
    for (int bs = 0; bs < BS_N; bs++) {
        if (!need[bs])
            continue;
        /* Distinct seeds per set. */
        if (!make_blockset(&sets[bs], bs, seed + (uint64_t)bs * 1000000, n, &w,
                           &host_ret))
            return 1;
        c.generated += sets[bs].c.generated;
        c.accepted += sets[bs].c.accepted;
        c.inconclusive += sets[bs].c.inconclusive;
        fails += a64p_floor("trace", "accepted blocks", sets[bs].c.accepted, (n + 1) / 2);
        if (bs == BS_FAULTS && n >= 16)
            fails += a64p_floor("trace", "planned faults", sets[bs].nexp_faults, 1);
    }
    printf("trace: model coverage:");
    for (int k = 0; k < CV_N; k++)
        printf(" %s=%ld", cv_names[k], coverage[k]);
    printf("\n");
    if (n >= 16) {
        /* With this many blocks every model category appears (the seeds are
         * fixed): a missing one means the generator or model changed.
         */
        for (int k = 0; k < CV_N; k++) {
            if (k == CV_IFLUSH || k == CV_DFLUSH || k == CV_LDRAA)
                continue; /* rarer; reported above */
            fails += a64p_floor("trace", cv_names[k], coverage[k], 1);
        }
    }

    int nrun = 0;
    for (int vi = 0; vi < NTVARIANTS; vi++) {
        const tvariant_t *v = &tvariants[vi];
        if (vlist != NULL && !list_has(vlist, v->name))
            continue;
        blockset_t *set = &sets[v->blockset];
        child_args_t a = { v, &w, set->xb, n, runs, host_ret };
        variant_t pv = { v->name, v->dr_ops, 0, 0, 0, 0 };
        int f = a64p_in_child_timeout("trace", &pv, trace_child, &a, 600);
        progress_t *prog = a64p_prog;
        printf(
            "trace variant %-8s: %s: runs %ld, checked %ld, transparency failures %ld; "
            "compared %ld instruction and %ld data records (%ld markers skipped, %ld "
            "exclusive loops in %ld iterations, %ld encoding changes, %ld faults, %ld "
            "asynchronous signals, %ld uncompleted, %ld perturbations rejected, %ld "
            "dead registers in fault frames); whole trace %ld instructions, %ld data\n",
            v->name, f ? "FAIL" : "ok", prog->stat[ST_RUNS], prog->stat[ST_RUNS_CHECKED],
            prog->stat[ST_TRANSPARENCY], prog->stat[ST_INSTRS], prog->stat[ST_REFS],
            prog->stat[ST_MARKERS], prog->stat[ST_LOOPS], prog->stat[ST_LOOP_ITERS],
            prog->stat[ST_ENC_CHANGES], prog->stat[ST_FAULTS], prog->stat[ST_ASYNC],
            prog->stat[ST_UNCOMPLETED], prog->stat[ST_SELFCHECK],
            prog->stat[ST_DEAD_REGS], prog->stat[ST_TRACE_INSTRS],
            prog->stat[ST_TRACE_DATA]);
        printf("trace variant %-8s: known deviations: cbr-target-next %ld, "
               "frame-pstate %ld, drreg-dead-dest %ld, async-loop-drop %ld, "
               "syscall-signal-dup %ld\n",
               v->name, prog->stat[ST_KD_CBR_NEXT], prog->stat[ST_KD_FRAME_PSTATE],
               prog->stat[ST_KD_DEAD_DEST], prog->stat[ST_KD_ASYNC_DROP],
               prog->stat[ST_KD_SYSCALL_DUP]);
        c.suppressed += prog->stat[ST_KD_CBR_NEXT] + prog->stat[ST_KD_FRAME_PSTATE] +
            prog->stat[ST_KD_DEAD_DEST] + prog->stat[ST_KD_ASYNC_DROP] +
            prog->stat[ST_KD_SYSCALL_DUP];
        c.executed += prog->stat[ST_RUNS];
        c.checked += prog->stat[ST_RUNS_CHECKED];
        fails += f;
        if (f == 0) {
            fails += a64p_floor("trace", v->name, prog->stat[ST_RUNS_CHECKED],
                                set->c.accepted * runs - prog->stat[ST_KD_DEAD_DEST]);
            if (prog->stat[ST_KD_DEAD_DEST] == 0) {
                /* Dropped iterations (async-loop-drop) are not in the trace. */
                fails += a64p_floor("trace", "instruction records",
                                    prog->stat[ST_INSTRS] + prog->stat[ST_DROP_SKIPPED],
                                    set->nexp_instrs * runs);
                fails += a64p_floor("trace", "faults", prog->stat[ST_FAULTS],
                                    set->nexp_faults * runs);
            } else {
                fails += a64p_floor("trace", "instruction records", prog->stat[ST_INSTRS],
                                    set->nexp_instrs * runs / 2);
                fails += a64p_floor("trace", "faults", prog->stat[ST_FAULTS],
                                    set->nexp_faults * runs / 2);
            }
            if (set->c.accepted >= 2)
                fails += a64p_floor("trace", "encoding changes",
                                    prog->stat[ST_ENC_CHANGES], 1);
            if (v->async_us > 0 && n >= 16) {
                /* An absolute quota of deliveries inside runs: none would make
                 * the variant vacuous.
                 */
                fails += a64p_floor("trace", "asynchronous signals in runs",
                                    prog->stat[ST_ASYNC], 20);
            }
        }
        nrun++;
    }
    fails += a64p_floor("trace", "variants run", nrun, 1);
    fails += harness_bugs;
    a64p_counts_print(stdout, "trace", &c);
    printf("trace: %s\n", fails == 0 ? "all properties hold" : "FAILURES");
    return fails == 0 ? 0 : 1;
}

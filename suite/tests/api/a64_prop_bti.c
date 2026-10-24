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

/* Property test of BTI-guarded pages (PROT_BTI) and PSTATE.BTYPE, natively and
 * under static DR (one forked child per option variant).
 *
 * matrix: a fixed matrix of landing pads (none: nop or udf, bti, bti c, bti j,
 *   bti jc, paciasp, pacibsp, brk) x branch forms (BR, BLR, RET, BRAA,
 *   BLRAA, BRAAZ, BLRAAZ with x9/x16/x17/x28, RET x30, RETAA) x guarded or
 *   unguarded source page x guarded or unguarded target page, plus targets on
 *   a read-only page, a PROT_NONE page and an unmapped address, a signal
 *   handler returning with PSTATE.BTYPE set in its frame (sigreturn x BTYPE
 *   1-3) and a signal handler whose entry point is the pad (the kernel enters
 *   handlers with BTYPE=C).  Every case ends in a synchronous signal: the BTI
 *   fault at the target, the target's own fault (udf, brk, a fetch from a
 *   page without execute permission), or the udf after a pad that was
 *   passed.  The handler records signal, si_code, pc and address relative to
 *   the target, PSTATE.BTYPE and the ESR record.  Each case runs 3 times.
 *   Native results must match an architectural model (BTYPE from the branch
 *   form, register and source guard; compatibility of each pad; SCTLR_EL1.BT0
 *   set by Linux, so PACIxSP does not accept BTYPE 3; brk is decided by the
 *   CPU and reported); DR's must match native ones exactly or differ only by
 *   the known deviations below.
 * graph: seeded graphs of nodes on guarded and unguarded pages, each with a
 *   landing pad, a few state updates and an indirect branch (the forms above)
 *   to the next node of a precomputed path whose edges are all compatible;
 *   some graphs end in an incompatible edge (a BTI fault natively).  They run
 *   while a POSIX timer sends SIGALRM every few microseconds.  Every
 *   interrupted context inside a node must have BTYPE 0, except at a node's
 *   first instruction, where it must be the BTYPE of the edge just taken
 *   (nodes are reached only by indirect branches; x21 tells which edge).  The
 *   final state (or the final fault) must equal the uninterrupted native run.
 *
 * PROT_BTI must take effect natively (mprotect succeeds, /proc/self/smaps
 * lists "bt" for the guarded pages, and a BR to a nop on a guarded page
 * faults); otherwise the test prints "SKIP: <reason>" and checks nothing.
 *
 * Known deviations (2026-10-14), counted and listed, never counted as checked;
 * A64_PROP_BTI_STRICT=1 turns them into failures:
 * + bti-not-enforced-{branch,sigreturn,sigentry}: DR executes the application
 *   from its code cache, which is not PROT_BTI, and does not emulate the check,
 *   so an incompatible indirect branch, sigreturn or handler entry into a
 *   guarded page runs the target instead of raising SIGILL.  DR's result must
 *   then equal the native result for the same case on an unguarded page.
 * + frame-btype-{branch,sigreturn,sigentry,noexec}: in a synchronous signal
 *   frame at the target of an indirect branch (or a sigreturn/handler entry)
 *   DR reports BTYPE 0 where the CPU reports the branch's BTYPE.  The frame's
 *   PSTATE comes from the code cache, where the app's branch is an exit to
 *   DR's indirect branch lookup followed by the fragment prefix, so the
 *   hardware BTYPE has been reset by the time the target faults.
 * + forged-fault-no-esr: the SIGSEGV DR raises for a fetch from a page
 *   without execute permission (it builds no code there) has no ESR record;
 *   the kernel's has one (instruction abort).
 * + async-btype: the same as frame-btype for an asynchronous signal whose
 *   context is a node's first instruction.
 * Native results are never masked.  DR does not emulate BTI.  Doing so would
 * take: tracking PROT_BTI per page (mmap/mprotect, and "bt" in smaps at
 * attach); the BTYPE of each indirect branch exit (BR's depends on its
 * register and on whether its own page is guarded); a check at the IBL entry
 * (prefix) of each fragment in a guarded page whose first instruction does
 * not accept every BTYPE (which includes every "bti c" function entry, for
 * BTYPE 3), in dispatch for IBL misses, signal handler entry and sigreturn,
 * and for inlined indirect branches in traces; and forging SIGILL with the
 * BTYPE in the frame.  Reporting BTYPE in synchronous frames would in
 * addition need to know, when translating a fault at a fragment's first
 * instruction, whether that entry came through the IBL, which the code cache
 * does not record (a direct link enters the same code without the prefix).
 *
 * Usage: a64_prop_bti [matrix|graph|all] [-seed S] [-n graphs] [-variants a,b]
 *        [-v]
 */

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include "dr_api.h"

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "a64_prop_support.h"
#pragma GCC diagnostic pop

#ifndef PROT_BTI
#    define PROT_BTI 0x10
#endif
#ifndef HWCAP2_BTI
#    define HWCAP2_BTI (1 << 17)
#endif
#ifndef HWCAP_PACA
#    define HWCAP_PACA (1 << 30)
#endif
#define PSTATE_BTYPE_SHIFT 10
#define PSTATE_BTYPE (3ULL << PSTATE_BTYPE_SHIFT)

static int verbose;
static int strict;
static int have_pac;

/***************************************************************************
 * Encodings.
 */
#define I_NOP 0xd503201fu
#define I_BTI 0xd503241fu
#define I_BTIC 0xd503245fu
#define I_BTIJ 0xd503249fu
#define I_BTIJC 0xd50324dfu
#define I_PACIASP 0xd503233fu
#define I_PACIBSP 0xd503237fu
#define I_UDF(i) ((uint32_t)(i) & 0xffff)
#define I_BRK(i) (0xd4200000u | ((uint32_t)(i) << 5))
#define I_BR(n) (0xd61f0000u | ((uint32_t)(n) << 5))
#define I_BLR(n) (0xd63f0000u | ((uint32_t)(n) << 5))
#define I_RET(n) (0xd65f0000u | ((uint32_t)(n) << 5))
#define I_BRAA(n, m) (0xd71f0800u | ((uint32_t)(n) << 5) | (uint32_t)(m))
#define I_BLRAA(n, m) (0xd73f0800u | ((uint32_t)(n) << 5) | (uint32_t)(m))
#define I_BRAAZ(n) (0xd61f081fu | ((uint32_t)(n) << 5))
#define I_BLRAAZ(n) (0xd63f081fu | ((uint32_t)(n) << 5))
#define I_RETAA 0xd65f0bffu
#define I_PACIA(d, n) (0xdac10000u | ((uint32_t)(n) << 5) | (uint32_t)(d))
#define I_PACIZA(d) (0xdac123e0u | (uint32_t)(d))
#define I_MOV(d, m) (0xaa0003e0u | ((uint32_t)(m) << 16) | (uint32_t)(d))
#define I_ADDI(d, n, imm)                                                     \
    (0x91000000u | (((uint32_t)(imm) & 0xfff) << 10) | ((uint32_t)(n) << 5) | \
     (uint32_t)(d))
/* eor xd, xn, xm, ror #s */
#define I_EOR_ROR(d, n, m, s)                                             \
    (0xcac00000u | ((uint32_t)(m) << 16) | (((uint32_t)(s) & 63) << 10) | \
     ((uint32_t)(n) << 5) | (uint32_t)(d))
/* ldr xt, [xn], #8 */
#define I_LDR_POST8(t, n) (0xf8408400u | ((uint32_t)(n) << 5) | (uint32_t)(t))
/* ldr xt, [xn, #off] / str xt, [xn, #off] (off a multiple of 8) */
#define I_LDR_OFF(t, n, off) \
    (0xf9400000u | (((uint32_t)(off) / 8) << 10) | ((uint32_t)(n) << 5) | (uint32_t)(t))
#define I_STR_OFF(t, n, off) \
    (0xf9000000u | (((uint32_t)(off) / 8) << 10) | ((uint32_t)(n) << 5) | (uint32_t)(t))
/* stp/ldp xt1, xt2, [xn, #off] (signed offset, multiple of 8) */
#define I_STP_OFF(t1, t2, n, off)                                                    \
    (0xa9000000u | ((((uint32_t)(off) / 8) & 0x7f) << 15) | ((uint32_t)(t2) << 10) | \
     ((uint32_t)(n) << 5) | (uint32_t)(t1))
#define I_LDP_OFF(t1, t2, n, off)                                                    \
    (0xa9400000u | ((((uint32_t)(off) / 8) & 0x7f) << 15) | ((uint32_t)(t2) << 10) | \
     ((uint32_t)(n) << 5) | (uint32_t)(t1))
/* stp x29, x30, [sp, #-96]! and ldp x29, x30, [sp], #96 */
#define I_STP_FRAME 0xa9ba7bfdu
#define I_LDP_FRAME 0xa8c67bfdu
#define I_RET_LR 0xd65f03c0u
#define SP 31

/***************************************************************************
 * The architectural model.
 */
enum {
    F_BR,
    F_BLR,
    F_RET,
    F_BRAA,
    F_BLRAA,
    F_BRAAZ,
    F_BLRAAZ,
    F_RETAA,
    F_SIGRET,   /* a handler returns to the target with BTYPE = reg */
    F_SIGENTRY, /* the target is a signal handler */
    NUM_FORMS
};
static const char *const form_name[] = {
    "br", "blr", "ret", "braa", "blraa", "braaz", "blraaz", "retaa", "sigret", "sigentry"
};

enum {
    P_NOP,
    P_UDF,
    P_BTI,
    P_BTIC,
    P_BTIJ,
    P_BTIJC,
    P_PACIASP,
    P_PACIBSP,
    P_BRK,
    NUM_PADS
};
static const char *const pad_name[] = { "nop",    "udf",     "bti",     "bti c", "bti j",
                                        "bti jc", "paciasp", "pacibsp", "brk" };
static const uint32_t pad_word[] = { I_NOP,   I_UDF(0x11), I_BTI,     I_BTIC,     I_BTIJ,
                                     I_BTIJC, I_PACIASP,   I_PACIBSP, I_BRK(0x22) };

static int
form_is_pac(int f)
{
    return f == F_BRAA || f == F_BLRAA || f == F_BRAAZ || f == F_BLRAAZ || f == F_RETAA;
}

/* The BTYPE an indirect branch sets (Arm ARM, BR/BLR/RET pseudocode). */
static int
model_btype(int form, int reg, int src_guarded)
{
    switch (form) {
    case F_RET:
    case F_RETAA: return 0;
    case F_BLR:
    case F_BLRAA:
    case F_BLRAAZ: return 2;
    case F_BR:
    case F_BRAA:
    case F_BRAAZ: return (reg == 16 || reg == 17 || !src_guarded) ? 1 : 3;
    case F_SIGRET: return reg;
    case F_SIGENTRY: return 2; /* the kernel enters handlers with BTYPE=C */
    }
    return -1;
}

/* Whether the instruction at a guarded target accepts BTYPE b; -1 if the
 * model does not decide (brk).
 */
static int
model_compat(int pad, int b)
{
    if (b == 0)
        return 1;
    switch (pad) {
    case P_BTIC: return b != 3;
    case P_BTIJ: return b != 2;
    case P_BTIJC: return 1;
    /* Linux sets SCTLR_EL1.BT0, so PACIxSP is an implicit BTI c only. */
    case P_PACIASP:
    case P_PACIBSP: return b != 3;
    case P_BRK: return -1;
    default: return 0;
    }
}

/***************************************************************************
 * Pages.
 */
enum { PG_SG, PG_SU, PG_TG, PG_TU, PG_TN, PG_TP, PG_GG, PG_GU, NUM_PAGES };
/* Target kinds. */
enum { TG_UNGUARDED, TG_GUARDED, TG_NOEXEC, TG_NOACCESS, TG_UNMAPPED, NUM_TG };
static const char *const tg_name[] = { "unguarded", "guarded", "noexec", "noaccess",
                                       "unmapped" };
#define REGION_SIZE (256 * 1024)
static uint8_t *region[NUM_PAGES];
static const int region_prot[NUM_PAGES] = {
    PROT_READ | PROT_EXEC | PROT_BTI,
    PROT_READ | PROT_EXEC,
    PROT_READ | PROT_EXEC | PROT_BTI,
    PROT_READ | PROT_EXEC,
    PROT_READ,
    PROT_NONE,
    PROT_READ | PROT_EXEC | PROT_BTI,
    PROT_READ | PROT_EXEC,
};
/* The return stub (in PG_SU) a handler sends a finished matrix case to. */
static uint32_t *ret_stub;
/* The graph's abort stub (in PG_GU). */
static uint32_t *abort_stub;

/* Whether /proc/self/smaps lists flag fl ("bt") in the VmFlags of the mapping
 * containing p: 1 yes, 0 no, -1 not found.
 */
static int
smaps_has_flag(void *p, const char *fl)
{
    FILE *f = fopen("/proc/self/smaps", "r");
    if (f == NULL)
        return -1;
    char line[512];
    int in = 0, res = -1;
    uint64_t a = (uint64_t)(uintptr_t)p;
    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long long lo, hi;
        if (sscanf(line, "%llx-%llx ", &lo, &hi) == 2 && strchr(line, '-') < line + 17) {
            in = a >= lo && a < hi;
            continue;
        }
        if (in && strncmp(line, "VmFlags:", 8) == 0) {
            char want[8];
            snprintf(want, sizeof(want), " %s", fl);
            char *s = strstr(line + 8, want);
            res = s != NULL && (s[strlen(want)] == ' ' || s[strlen(want)] == '\n');
            break;
        }
    }
    fclose(f);
    return res;
}

static void
sync_code(void *p, size_t n)
{
    __builtin___clear_cache((char *)p, (char *)p + n);
}

/***************************************************************************
 * Matrix cases.
 */
typedef struct {
    int signo, code;
    int64_t pcrel, addrrel; /* relative to the case's target */
    int btype;
    int has_esr;
    uint64_t esr;
} out_t;

typedef struct {
    int form, reg, sg, tg; /* tg: 0 unguarded, 1 guarded, 2 non-executable */
    int pad;
    uint32_t *entry, *target, *trigger;
} case_t;

#define MAX_CASES 2048
#define REPS 3
static case_t cases[MAX_CASES];
static int ncases;
static out_t (*res_native)[REPS], (*res_dr)[REPS];

static volatile case_t *g_cur;
static volatile int g_stage, g_done;
static out_t *volatile g_out;
static volatile uint64_t g_unexpected_pc;
static volatile int g_unexpected_sig;

static uint32_t *alloc_ptr[NUM_PAGES];
static int alloc_count[NUM_PAGES];

/* Allocates slots of the given size in a scattered order, so that sequential
 * cases do not get sequential addresses (which makes DR's indirect branch
 * tables report long collision clusters in debug builds).
 */
static uint32_t *
alloc_scattered(int pg, int words)
{
    uint32_t nslots = REGION_SIZE / (words * 4);
    uint32_t k = (uint32_t)alloc_count[pg]++;
    if (k >= nslots) {
        fprintf(stderr, "ERROR: region %d is full\n", pg);
        exit(2);
    }
    /* 7919 is prime and does not divide nslots. */
    return (uint32_t *)region[pg] + (size_t)((k * 7919u + 1) % nslots) * words;
}

static uint32_t *
alloc_slot(int pg, int words)
{
    uint32_t *p = alloc_ptr[pg];
    if ((uint8_t *)(p + words) > region[pg] + REGION_SIZE) {
        fprintf(stderr, "ERROR: region %d is full\n", pg);
        exit(2);
    }
    alloc_ptr[pg] = p + words;
    return p;
}

static void
emit_case_target(case_t *c)
{
    if (c->tg == TG_NOEXEC || c->tg == TG_NOACCESS) {
        /* Never executed: a fault on fetch. */
        c->target = alloc_scattered(c->tg == TG_NOEXEC ? PG_TN : PG_TP, 4);
        return;
    }
    if (c->tg == TG_UNMAPPED) {
        /* Below mmap_min_addr. */
        static int nunmapped;
        c->target = (uint32_t *)(uintptr_t)(0x100 + 16 * nunmapped++);
        return;
    }
    uint32_t *t = alloc_scattered(c->tg == TG_GUARDED ? PG_TG : PG_TU, 4);
    t[0] = pad_word[c->pad];
    t[1] = I_UDF(0x33); /* "reached" */
    t[2] = I_UDF(0x34);
    t[3] = I_UDF(0x35);
    c->target = t;
}

/* Entry stubs are called as entry(target, modifier). */
static void
emit_case_entry(case_t *c)
{
    uint32_t *e = alloc_scattered(c->sg ? PG_SG : PG_SU, 12);
    int i = 0, r = c->reg;
    e[i++] = I_BTIC;
    e[i++] = I_STP_FRAME;
    e[i++] = I_STR_OFF(28, SP, 16);
    if (c->form == F_SIGRET) {
        c->trigger = &e[i];
        e[i++] = I_UDF(0x44);
    } else {
        int t = c->form == F_RETAA ? 30 : r;
        e[i++] = I_MOV(t, 0);
        switch (c->form) {
        case F_BRAA:
        case F_BLRAA: e[i++] = I_PACIA(t, 1); break;
        case F_BRAAZ:
        case F_BLRAAZ: e[i++] = I_PACIZA(t); break;
        case F_RETAA: e[i++] = I_PACIA(30, SP); break;
        default: break;
        }
        switch (c->form) {
        case F_BR: e[i++] = I_BR(r); break;
        case F_BLR: e[i++] = I_BLR(r); break;
        case F_RET: e[i++] = I_RET(r); break;
        case F_BRAA: e[i++] = I_BRAA(r, 1); break;
        case F_BLRAA: e[i++] = I_BLRAA(r, 1); break;
        case F_BRAAZ: e[i++] = I_BRAAZ(r); break;
        case F_BLRAAZ: e[i++] = I_BLRAAZ(r); break;
        case F_RETAA: e[i++] = I_RETAA; break;
        }
    }
    e[i++] = I_UDF(0x55); /* fell through */
    while (i < 12)
        e[i++] = I_UDF(0x56);
    c->entry = e;
}

static void
add_case(int form, int reg, int sg, int tg, int pad)
{
    if (ncases >= MAX_CASES) {
        fprintf(stderr, "ERROR: too many cases\n");
        exit(2);
    }
    case_t *c = &cases[ncases++];
    memset(c, 0, sizeof(*c));
    c->form = form;
    c->reg = reg;
    c->sg = sg;
    c->tg = tg;
    c->pad = pad;
    emit_case_target(c);
    if (form != F_SIGENTRY)
        emit_case_entry(c);
}

static void
build_matrix(void)
{
    static const int regs[] = { 9, 16, 17, 28 };
    for (int f = F_BR; f <= F_RETAA; f++) {
        if (form_is_pac(f) && !have_pac)
            continue;
        int nr = f == F_RETAA ? 1 : (f == F_RET ? 5 : 4);
        for (int ri = 0; ri < nr; ri++) {
            int reg = f == F_RETAA ? 30 : (ri < 4 ? regs[ri] : 30);
            for (int sg = 0; sg < 2; sg++) {
                for (int tg = 0; tg < 2; tg++) {
                    for (int p = 0; p < NUM_PADS; p++)
                        add_case(f, reg, sg, tg, p);
                }
                for (int tg = TG_NOEXEC; tg < NUM_TG; tg++)
                    add_case(f, reg, sg, tg, P_NOP);
            }
        }
    }
    for (int b = 1; b <= 3; b++) {
        for (int tg = 0; tg < 2; tg++) {
            for (int p = 0; p < NUM_PADS; p++)
                add_case(F_SIGRET, b, 0, tg, p);
        }
    }
    for (int tg = 0; tg < 2; tg++) {
        for (int p = 0; p < NUM_PADS; p++)
            add_case(F_SIGENTRY, 0, 0, tg, p);
    }
}

static void
case_str(char *buf, size_t n, const case_t *c)
{
    snprintf(buf, n, "%s %s%d src=%s tgt=%s pad=%s", form_name[c->form],
             c->form == F_SIGRET ? "btype=" : "x", c->reg,
             c->form >= F_SIGRET ? "-" : (c->sg ? "guarded" : "unguarded"),
             tg_name[c->tg], c->tg >= TG_NOEXEC ? "-" : pad_name[c->pad]);
}

static void
out_str(char *buf, size_t n, const out_t *o)
{
    if (o->signo == 0) {
        snprintf(buf, n, "no signal");
        return;
    }
    snprintf(buf, n, "sig %d code %d pc T%+lld addr T%+lld btype %d esr %s0x%llx",
             o->signo, o->code, (long long)o->pcrel, (long long)o->addrrel, o->btype,
             o->has_esr ? "" : "(none) ", (unsigned long long)o->esr);
}

static int
out_eq(const out_t *a, const out_t *b)
{
    return a->signo == b->signo && a->code == b->code && a->pcrel == b->pcrel &&
        a->addrrel == b->addrrel && a->btype == b->btype && a->has_esr == b->has_esr &&
        a->esr == b->esr;
}

static uint64_t
xpaci(uint64_t v)
{
    register uint64_t x0 __asm__("x0") = v;
    __asm__ volatile(".inst 0xdac143e0" : "+r"(x0)); /* xpaci x0 */
    return x0;
}

static void
matrix_handler(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    volatile case_t *c = g_cur;
    uint64_t pc = uc->uc_mcontext.pc;
    if (c == NULL || g_done) {
        g_unexpected_sig = sig;
        g_unexpected_pc = pc;
        _exit(4);
    }
    if (c->form == F_SIGRET && g_stage == 0 && pc == (uint64_t)(uintptr_t)c->trigger) {
        g_stage = 1;
        uc->uc_mcontext.pc = (uint64_t)(uintptr_t)c->target;
        uc->uc_mcontext.pstate = (uc->uc_mcontext.pstate & ~PSTATE_BTYPE) |
            ((uint64_t)c->reg << PSTATE_BTYPE_SHIFT);
        return;
    }
    out_t *o = g_out;
    uint64_t t = (uint64_t)(uintptr_t)c->target;
    o->signo = sig;
    o->code = si->si_code;
    o->pcrel = (int64_t)(pc - t);
    o->addrrel = (int64_t)((uint64_t)(uintptr_t)si->si_addr - t);
    o->btype = (int)((uc->uc_mcontext.pstate & PSTATE_BTYPE) >> PSTATE_BTYPE_SHIFT);
    struct a64p_esr_rec *e = (struct a64p_esr_rec *)a64p_find_rec(uc, ESR_MAGIC_);
    o->has_esr = e != NULL;
    o->esr = e != NULL ? e->esr : 0;
    g_done = 1;
    uc->uc_mcontext.pstate &= ~PSTATE_BTYPE;
    if (c->form == F_SIGENTRY) {
        /* Back to the kernel's (or DR's) restorer: x30 as the kernel set it,
         * signed if the pad was paciasp/pacibsp.
         */
        uc->uc_mcontext.pc = xpaci(uc->uc_mcontext.regs[30]);
    } else
        uc->uc_mcontext.pc = (uint64_t)(uintptr_t)ret_stub;
}

static void
install_matrix_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = matrix_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
}

static void
run_case(case_t *c, out_t *o)
{
    memset(o, 0, sizeof(*o));
    g_out = o;
    g_stage = 0;
    g_done = 0;
    __atomic_store_n(&g_cur, c, __ATOMIC_SEQ_CST);
    if (c->form == F_SIGENTRY) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = (void (*)(int, siginfo_t *, void *))(void *)c->target;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR2, &sa, NULL);
        syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR2);
        signal(SIGUSR2, SIG_DFL);
    } else {
        ((void (*)(uint64_t, uint64_t))(void *)c->entry)((uint64_t)(uintptr_t)c->target,
                                                         0x1234567890abcdefULL);
    }
    __atomic_store_n(&g_cur, NULL, __ATOMIC_SEQ_CST);
}

static void
run_matrix(out_t (*res)[REPS])
{
    install_matrix_handlers();
    for (int r = 0; r < REPS; r++) {
        for (int i = 0; i < ncases; i++)
            run_case(&cases[i], &res[i][r]);
    }
}

/* The model's outcome for case c (signal, pc and BTYPE only); returns 0 if
 * the model does not decide (*alt then holds a second permitted outcome).
 */
static void
model_case(const case_t *c, out_t *m, out_t *alt, int *nalt)
{
    int b = model_btype(c->form, c->reg, c->sg);
    memset(m, 0, sizeof(*m));
    *nalt = 0;
    if (c->tg >= TG_NOEXEC) {
        m->signo = SIGSEGV;
        m->btype = b;
        return;
    }
    int compat = c->tg == TG_GUARDED ? model_compat(c->pad, b) : 1;
    /* The target's own behaviour. */
    out_t run;
    memset(&run, 0, sizeof(run));
    if (c->pad == P_UDF || c->pad == P_BRK) {
        run.signo = c->pad == P_UDF ? SIGILL : SIGTRAP;
        run.btype = b;
    } else {
        run.signo = SIGILL;
        run.pcrel = 4;
    }
    out_t bti;
    memset(&bti, 0, sizeof(bti));
    bti.signo = SIGILL;
    bti.btype = b;
    if (compat == 1)
        *m = run;
    else if (compat == 0)
        *m = bti;
    else {
        *m = run;
        *alt = bti;
        *nalt = 1;
    }
}

static int
model_match(const out_t *m, const out_t *o)
{
    return m->signo == o->signo && m->pcrel == o->pcrel && m->btype == o->btype;
}

/***************************************************************************
 * Known deviations.
 */
enum {
    KD_BTI_BRANCH,
    KD_BTI_SIGRET,
    KD_BTI_SIGENTRY,
    KD_FRAME_BRANCH,
    KD_FRAME_SIGRET,
    KD_FRAME_SIGENTRY,
    KD_FRAME_NOEXEC,
    KD_FORGED_ESR,
    KD_ASYNC,
    NUM_KD
};
static const char *const kd_name[] = {
    "bti-not-enforced-branch", "bti-not-enforced-sigreturn", "bti-not-enforced-sigentry",
    "frame-btype-branch",      "frame-btype-sigreturn",      "frame-btype-sigentry",
    "frame-btype-noexec",      "forged-fault-no-esr",        "async-btype",
};

/* Counters a child reports through the progress page. */
enum {
    ST_CASES,    /* matrix case runs compared */
    ST_EXACT,    /* ...equal to native */
    ST_MODEL,    /* native runs checked against the model */
    ST_BRKBTI,   /* native brk on a guarded page with BTYPE != 0: BTI fault */
    ST_BRKRUN,   /* ...: brk ran */
    ST_GRAPHS,   /* graphs compared */
    ST_GFAULT,   /* ...ending in a BTI fault natively */
    ST_ASYNC_N,  /* native in-graph contexts checked */
    ST_ASYNC_NT, /* ...of which at a node's first instruction */
    ST_ASYNC_D,  /* DR in-graph contexts checked */
    ST_ASYNC_DT, /* ...of which at a node's first instruction */
    ST_NCASES,   /* matrix cases built */
    ST_GSUPP,    /* graphs whose DR run was a known deviation (no signal runs) */
    ST_KD0,
    ST_NUM = ST_KD0 + NUM_KD
};
_Static_assert(ST_NUM <= A64P_NSTAT, "progress_t.stat is too small");

static void
stat_add(int i, long v)
{
    a64p_prog->stat[i] += v;
}

static int
check_matrix(const char *vname)
{
    int fails = 0;
    char cs[160], ns[160], ds[160];
    for (int i = 0; i < ncases; i++) {
        case_t *c = &cases[i];
        /* Native against the model, and native repetitions against each
         * other.
         */
        out_t m, alt;
        int nalt;
        model_case(c, &m, &alt, &nalt);
        for (int r = 0; r < REPS; r++) {
            out_t *n = &res_native[i][r];
            int ok = model_match(&m, n) || (nalt && model_match(&alt, n));
            if (ok && nalt && r == 0) {
                if (model_match(&alt, n))
                    stat_add(ST_BRKBTI, 1);
                else
                    stat_add(ST_BRKRUN, 1);
            }
            if (!ok || !out_eq(n, &res_native[i][0])) {
                case_str(cs, sizeof(cs), c);
                out_str(ns, sizeof(ns), n);
                out_str(ds, sizeof(ds), &m);
                fprintf(stderr,
                        "FAIL [%s] native case %d (%s) rep %d: %s; the model expects "
                        "%s\n",
                        vname, i, cs, r, ns, ds);
                fails++;
            }
            stat_add(ST_MODEL, 1);
        }
        /* DR against native. */
        for (int r = 0; r < REPS; r++) {
            out_t *n = &res_native[i][r], *d = &res_dr[i][r];
            stat_add(ST_CASES, 1);
            if (out_eq(n, d)) {
                stat_add(ST_EXACT, 1);
                continue;
            }
            /* Apply the known deviations to the native result, one at a time,
             * and accept DR's result if it then matches.
             */
            int kds[3], nk = 0;
            out_t nn = *n;
            if (!strict) {
                /* bti-not-enforced: DR behaves as on an unguarded page. */
                int b = model_btype(c->form, c->reg, c->sg);
                if (c->tg == TG_GUARDED && b != 0 && n->signo == SIGILL &&
                    n->pcrel == 0 && n->btype == b) {
                    for (int j = 0; j < ncases; j++) {
                        case_t *t = &cases[j];
                        if (t->form == c->form && t->reg == c->reg && t->sg == c->sg &&
                            t->tg == TG_UNGUARDED && t->pad == c->pad) {
                            if (!out_eq(&res_native[j][r], n)) {
                                nn = res_native[j][r];
                                kds[nk++] = c->form == F_SIGRET
                                    ? KD_BTI_SIGRET
                                    : (c->form == F_SIGENTRY ? KD_BTI_SIGENTRY
                                                             : KD_BTI_BRANCH);
                            }
                            break;
                        }
                    }
                }
                if (nn.btype != 0 && d->btype == 0) {
                    nn.btype = 0;
                    kds[nk++] = c->tg >= TG_NOEXEC
                        ? KD_FRAME_NOEXEC
                        : (c->form == F_SIGRET
                               ? KD_FRAME_SIGRET
                               : (c->form == F_SIGENTRY ? KD_FRAME_SIGENTRY
                                                        : KD_FRAME_BRANCH));
                }
                if (c->tg >= TG_NOEXEC && nn.has_esr && !d->has_esr) {
                    nn.has_esr = 0;
                    nn.esr = 0;
                    kds[nk++] = KD_FORGED_ESR;
                }
            }
            if (nk > 0 && out_eq(&nn, d)) {
                for (int k = 0; k < nk; k++) {
                    stat_add(ST_KD0 + kds[k], 1);
                    if (verbose) {
                        case_str(cs, sizeof(cs), c);
                        out_str(ns, sizeof(ns), n);
                        out_str(ds, sizeof(ds), d);
                        fprintf(stderr, "  [%s] %s: %s: native %s, DR %s\n", vname,
                                kd_name[kds[k]], cs, ns, ds);
                    }
                }
                continue;
            }
            case_str(cs, sizeof(cs), c);
            out_str(ns, sizeof(ns), n);
            out_str(ds, sizeof(ds), d);
            fprintf(stderr, "FAIL [%s] case %d (%s) rep %d:\n  native %s\n  DR     %s\n",
                    vname, i, cs, r, ns, ds);
            fails++;
        }
    }
    return fails;
}

/***************************************************************************
 * Graphs.
 */
#define MAX_NODES 40
#define NODE_WORDS 16
#define PATH_LEN 4000
#define GRAPH_RUNS 400
#define MAX_ALOG 65536

typedef struct {
    int form, reg, guarded, pad, exit;
    uint32_t *code;
    int btype; /* of its outgoing edge */
} node_t;

typedef struct {
    /* Read by the entry stub. */
    uint64_t x19, x20, path, mod;
    /* Written by the exit node. */
    uint64_t o19, o20, o23, pad_;
} gio_t;

typedef struct {
    int nnodes, plen, fault_node; /* -1: no final violation */
    node_t node[MAX_NODES];
    uint64_t *path;
    int *path_node;
    uint32_t *entry;
    uint64_t seed;
} graph_t;

typedef struct {
    uint64_t pc, x21;
    int btype;
} arec2_t;

typedef struct {
    gio_t io;
    int faulted;
    out_t fault;
} gres_t;

static graph_t g_graph;
static arec2_t *alog;
static volatile int alog_n;
static volatile int g_graph_on;
static gres_t *volatile g_gres;

static int
pick_pad(rng_t *r)
{
    /* No udf/brk in graphs. */
    static const int pads[] = { P_NOP,   P_BTI,     P_BTIC,   P_BTIJ,
                                P_BTIJC, P_PACIASP, P_PACIBSP };
    return pads[rn(r, sizeof(pads) / sizeof(pads[0]))];
}

static int
edge_ok(graph_t *g, int from, int to)
{
    node_t *t = &g->node[to];
    int b = from < 0 ? 1 : g->node[from].btype;
    return !t->guarded || model_compat(t->pad, b) == 1;
}

static void
emit_node(graph_t *g, int i, rng_t *r)
{
    node_t *n = &g->node[i];
    uint32_t *e = alloc_slot(n->guarded ? PG_GG : PG_GU, NODE_WORDS);
    int k = 0;
    n->code = e;
    e[k++] = pad_word[n->pad];
    if (n->exit) {
        e[k++] = I_STP_OFF(19, 20, 24, offsetof(gio_t, o19));
        e[k++] = I_STR_OFF(23, 24, offsetof(gio_t, o23));
        e[k++] = I_LDP_OFF(19, 20, SP, 16);
        e[k++] = I_LDP_OFF(21, 22, SP, 32);
        e[k++] = I_LDP_OFF(23, 24, SP, 48);
        e[k++] = I_LDR_OFF(28, SP, 64);
        e[k++] = I_LDP_FRAME;
        e[k++] = I_RET_LR;
    } else {
        int t = n->form == F_RETAA ? 30 : n->reg;
        e[k++] = I_ADDI(19, 19, rn(r, 4096));
        e[k++] = I_EOR_ROR(20, 20, 19, 1 + rn(r, 63));
        e[k++] = I_ADDI(23, 23, 1);
        e[k++] = I_LDR_POST8(t, 21);
        switch (n->form) {
        case F_BRAA:
        case F_BLRAA: e[k++] = I_PACIA(t, 22); break;
        case F_BRAAZ:
        case F_BLRAAZ: e[k++] = I_PACIZA(t); break;
        case F_RETAA: e[k++] = I_PACIA(30, SP); break;
        default: break;
        }
        switch (n->form) {
        case F_BR: e[k++] = I_BR(t); break;
        case F_BLR: e[k++] = I_BLR(t); break;
        case F_RET: e[k++] = I_RET(t); break;
        case F_BRAA: e[k++] = I_BRAA(t, 22); break;
        case F_BLRAA: e[k++] = I_BLRAA(t, 22); break;
        case F_BRAAZ: e[k++] = I_BRAAZ(t); break;
        case F_BLRAAZ: e[k++] = I_BLRAAZ(t); break;
        case F_RETAA: e[k++] = I_RETAA; break;
        }
    }
    while (k < NODE_WORDS)
        e[k++] = I_UDF(0x66);
}

/* Generates a graph whose path is all compatible edges, except, if
 * want_fault, the last.  Returns 0 on failure (retry with another seed).
 */
static int
gen_graph(graph_t *g, uint64_t seed, int want_fault)
{
    rng_t r = { seed };
    static const int regs[] = { 9, 16, 17, 28 };
    memset(g->node, 0, sizeof(g->node));
    g->seed = seed;
    g->nnodes = 12 + rn(&r, MAX_NODES - 12);
    for (int i = 0; i < g->nnodes; i++) {
        node_t *n = &g->node[i];
        do
            n->form = rn(&r, F_RETAA + 1);
        while (form_is_pac(n->form) && !have_pac);
        n->reg = n->form == F_RETAA ? 30 : regs[rn(&r, 4)];
        n->guarded = rp(&r, 70);
        n->pad = pick_pad(&r);
        n->btype = model_btype(n->form, n->reg, n->guarded);
    }
    /* Node 0 is the exit. */
    g->node[0].exit = 1;
    g->node[0].pad = P_BTIJC;
    g->fault_node = -1;
    int cur = -1, len = 0;
    while (len < PATH_LEN - 1) {
        int cand[MAX_NODES], nc = 0;
        for (int j = 1; j < g->nnodes; j++) {
            if (edge_ok(g, cur, j))
                cand[nc++] = j;
        }
        if (nc == 0)
            return 0;
        cur = cand[rn(&r, nc)];
        g->path_node[len++] = cur;
    }
    if (want_fault) {
        int cand[MAX_NODES], nc = 0;
        for (int j = 1; j < g->nnodes; j++) {
            if (!edge_ok(g, cur, j))
                cand[nc++] = j;
        }
        if (nc == 0)
            return 0;
        g->fault_node = cand[rn(&r, nc)];
        g->path_node[len++] = g->fault_node;
    } else {
        if (!edge_ok(g, cur, 0))
            return 0;
        g->path_node[len++] = 0;
    }
    g->plen = len;
    return 1;
}

static void
emit_graph(graph_t *g)
{
    rng_t r = { g->seed ^ 0x5eed };
    alloc_ptr[PG_GG] = (uint32_t *)region[PG_GG];
    alloc_ptr[PG_GU] = (uint32_t *)region[PG_GU] + 64;
    mprotect(region[PG_GG], REGION_SIZE, PROT_READ | PROT_WRITE);
    mprotect(region[PG_GU], REGION_SIZE, PROT_READ | PROT_WRITE);
    for (int i = 0; i < g->nnodes; i++)
        emit_node(g, i, &r);
    uint32_t *e = alloc_slot(PG_GU, 16);
    int k = 0;
    e[k++] = I_BTIC;
    e[k++] = I_STP_FRAME;
    e[k++] = I_STP_OFF(19, 20, SP, 16);
    e[k++] = I_STP_OFF(21, 22, SP, 32);
    e[k++] = I_STP_OFF(23, 24, SP, 48);
    e[k++] = I_STR_OFF(28, SP, 64);
    e[k++] = I_MOV(24, 0);
    e[k++] = I_LDP_OFF(19, 20, 24, offsetof(gio_t, x19));
    e[k++] = I_LDP_OFF(21, 22, 24, offsetof(gio_t, path));
    e[k++] = I_MOV(23, 31); /* mov x23, xzr */
    e[k++] = I_LDR_POST8(16, 21);
    e[k++] = I_BR(16); /* from an unguarded page: BTYPE 1 */
    while (k < 16)
        e[k++] = I_UDF(0x77);
    g->entry = e;
    for (int i = 0; i < g->plen; i++)
        g->path[i] = (uint64_t)(uintptr_t)g->node[g->path_node[i]].code;
    sync_code(region[PG_GG], REGION_SIZE);
    sync_code(region[PG_GU], REGION_SIZE);
    mprotect(region[PG_GG], REGION_SIZE, region_prot[PG_GG]);
    mprotect(region[PG_GU], REGION_SIZE, region_prot[PG_GU]);
}

static void
graph_sync_handler(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    gres_t *gr = g_gres;
    if (gr == NULL || gr->faulted)
        _exit(5);
    graph_t *g = &g_graph;
    uint64_t t =
        g->fault_node >= 0 ? (uint64_t)(uintptr_t)g->node[g->fault_node].code : 0;
    out_t *o = &gr->fault;
    uint64_t pc = uc->uc_mcontext.pc;
    o->signo = sig;
    o->code = si->si_code;
    o->pcrel = (int64_t)(pc - t);
    o->addrrel = (int64_t)((uint64_t)(uintptr_t)si->si_addr - t);
    o->btype = (int)((uc->uc_mcontext.pstate & PSTATE_BTYPE) >> PSTATE_BTYPE_SHIFT);
    struct a64p_esr_rec *e = (struct a64p_esr_rec *)a64p_find_rec(uc, ESR_MAGIC_);
    o->has_esr = e != NULL;
    o->esr = e != NULL ? e->esr : 0;
    gr->faulted = 1;
    gr->io.o19 = uc->uc_mcontext.regs[19];
    gr->io.o20 = uc->uc_mcontext.regs[20];
    gr->io.o23 = uc->uc_mcontext.regs[23];
    uc->uc_mcontext.pstate &= ~PSTATE_BTYPE;
    uc->uc_mcontext.pc = (uint64_t)(uintptr_t)abort_stub;
}

static void
graph_async_handler(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    if (!g_graph_on)
        return;
    int i = alog_n;
    if (i >= MAX_ALOG)
        return;
    alog[i].pc = uc->uc_mcontext.pc;
    alog[i].x21 = uc->uc_mcontext.regs[21];
    alog[i].btype = (int)((uc->uc_mcontext.pstate & PSTATE_BTYPE) >> PSTATE_BTYPE_SHIFT);
    alog_n = i + 1;
}

static void
install_graph_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = graph_sync_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sa.sa_sigaction = graph_async_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGALRM, &sa, NULL);
}

static void
run_graph_once(graph_t *g, gres_t *gr)
{
    memset(gr, 0, sizeof(*gr));
    gr->io.x19 = 0x0123456789abcdefULL ^ g->seed;
    gr->io.x20 = 0xfedcba9876543210ULL;
    gr->io.path = (uint64_t)(uintptr_t)g->path;
    gr->io.mod = 0x1122334455667788ULL;
    g_gres = gr;
    ((void (*)(gio_t *))(void *)g->entry)(&gr->io);
    g_gres = NULL;
}

/* Runs g GRAPH_RUNS times with SIGALRM every period_ns; returns 1 if every
 * run's result equals ref (or, for the first run when ref is NULL, the first
 * run's).
 */
static int
run_graph_signals(graph_t *g, gres_t *ref, long period_ns, const char *who,
                  const char *vname)
{
    timer_t tm;
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = SIGALRM;
    sev._sigev_un._tid = (pid_t)syscall(SYS_gettid);
    if (timer_create(CLOCK_MONOTONIC, &sev, &tm) != 0) {
        fprintf(stderr, "ERROR: timer_create: %s\n", strerror(errno));
        return 0;
    }
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = period_ns;
    its.it_interval.tv_nsec = period_ns;
    alog_n = 0;
    g_graph_on = 1;
    timer_settime(tm, 0, &its, NULL);
    int ok = 1;
    for (int i = 0; i < GRAPH_RUNS; i++) {
        gres_t gr;
        run_graph_once(g, &gr);
        if (gr.faulted != ref->faulted || gr.io.o19 != ref->io.o19 ||
            gr.io.o20 != ref->io.o20 || gr.io.o23 != ref->io.o23 ||
            (gr.faulted && !out_eq(&gr.fault, &ref->fault))) {
            char a[160], b[160];
            out_str(a, sizeof(a), &ref->fault);
            out_str(b, sizeof(b), &gr.fault);
            fprintf(stderr,
                    "FAIL [%s] graph seed %llu: %s run %d with signals differs from "
                    "the uninterrupted native run:\n  native x19 %llx x20 %llx x23 "
                    "%llu %s\n  %-6s x19 %llx x20 %llx x23 %llu %s\n",
                    vname, (unsigned long long)g->seed, who, i,
                    (unsigned long long)ref->io.o19, (unsigned long long)ref->io.o20,
                    (unsigned long long)ref->io.o23, ref->faulted ? a : "", who,
                    (unsigned long long)gr.io.o19, (unsigned long long)gr.io.o20,
                    (unsigned long long)gr.io.o23, gr.faulted ? b : "");
            ok = 0;
            break;
        }
    }
    g_graph_on = 0;
    memset(&its, 0, sizeof(its));
    timer_settime(tm, 0, &its, NULL);
    timer_delete(tm);
    return ok;
}

/* Checks the asynchronous contexts logged for g; is_dr selects the
 * deviation allowance.
 */
static int
check_async(graph_t *g, int is_dr, const char *vname)
{
    int fails = 0;
    uint64_t pbase = (uint64_t)(uintptr_t)g->path;
    for (int i = 0; i < alog_n; i++) {
        arec2_t *a = &alog[i];
        int node = -1;
        for (int j = 0; j < g->nnodes; j++) {
            uint64_t c = (uint64_t)(uintptr_t)g->node[j].code;
            if (a->pc >= c && a->pc < c + NODE_WORDS * 4) {
                node = j;
                break;
            }
        }
        if (node < 0)
            continue;
        int first = a->pc == (uint64_t)(uintptr_t)g->node[node].code;
        int want = 0;
        if (first) {
            /* x21 points past the path entry of this node. */
            int64_t k = (int64_t)(a->x21 - pbase) / 8 - 1;
            if (k < 0 || k >= g->plen || g->path_node[k] != node) {
                fprintf(stderr,
                        "FAIL [%s] graph seed %llu: %s context at node %d's entry has "
                        "x21 0x%llx, not just past a path entry for it\n",
                        vname, (unsigned long long)g->seed, is_dr ? "DR" : "native", node,
                        (unsigned long long)a->x21);
                fails++;
                continue;
            }
            want = k == 0 ? 1 : g->node[g->path_node[k - 1]].btype;
        }
        stat_add(is_dr ? ST_ASYNC_D : ST_ASYNC_N, 1);
        if (first)
            stat_add(is_dr ? ST_ASYNC_DT : ST_ASYNC_NT, 1);
        if (a->btype == want)
            continue;
        if (is_dr && !strict && first && a->btype == 0) {
            stat_add(ST_KD0 + KD_ASYNC, 1);
            continue;
        }
        fprintf(stderr,
                "FAIL [%s] graph seed %llu: %s context at node %d +%lld has BTYPE %d, "
                "expected %d\n",
                vname, (unsigned long long)g->seed, is_dr ? "DR" : "native", node,
                (long long)(a->pc - (uint64_t)(uintptr_t)g->node[node].code), a->btype,
                want);
        fails++;
    }
    return fails;
}

/***************************************************************************
 * Driver.
 */
static const variant_t bti_variants[] = {
    { "default", "", 0, 0, 0, 0 },
    { "notraces", "-disable_traces", 0, 0, 0, 0 },
    { "steal27", "-steal_reg 27", 0, 0, 1, 0 },
};
#define NUM_BTI_VARIANTS (int)(sizeof(bti_variants) / sizeof(bti_variants[0]))

static int is_debug_build;
static uint64_t opt_seed = 1;
static int opt_graphs = 24;
static int do_matrix = 1, do_graph = 1;
static const variant_t *cur_variant;

static void
map_regions(void)
{
    for (int i = 0; i < NUM_PAGES; i++) {
        region[i] = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (region[i] == MAP_FAILED) {
            perror("mmap");
            exit(2);
        }
        memset(region[i], 0, REGION_SIZE);
        alloc_ptr[i] = (uint32_t *)region[i];
    }
    /* The return stub: restore what the entry stubs saved and return. */
    ret_stub = alloc_slot(PG_SU, 4);
    ret_stub[0] = I_LDR_OFF(28, SP, 16);
    ret_stub[1] = I_LDP_FRAME;
    ret_stub[2] = I_RET_LR;
    ret_stub[3] = I_UDF(0x99);
    /* The graph abort stub, at the start of PG_GU (nodes start after it). */
    abort_stub = (uint32_t *)region[PG_GU];
    abort_stub[0] = I_LDP_OFF(19, 20, SP, 16);
    abort_stub[1] = I_LDP_OFF(21, 22, SP, 32);
    abort_stub[2] = I_LDP_OFF(23, 24, SP, 48);
    abort_stub[3] = I_LDR_OFF(28, SP, 64);
    abort_stub[4] = I_LDP_FRAME;
    abort_stub[5] = I_RET_LR;
}

static void
protect_regions(void)
{
    for (int i = 0; i < NUM_PAGES; i++) {
        sync_code(region[i], REGION_SIZE);
        if (mprotect(region[i], REGION_SIZE, region_prot[i]) != 0) {
            fprintf(stderr, "ERROR: mprotect region %d: %s\n", i, strerror(errno));
            exit(2);
        }
    }
}

/* Returns NULL if PROT_BTI takes effect natively, else why not. */
static const char *
bti_unavailable(void)
{
    static char why[128];
    uint32_t *p =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return "mmap failed";
    p[0] = I_BTIC;
    p[1] = I_BR(9);
    p[2] = I_NOP; /* the target: not a landing pad */
    p[3] = I_RET_LR;
    sync_code(p, 16);
    if (mprotect(p, 4096, PROT_READ | PROT_EXEC | PROT_BTI) != 0) {
        snprintf(why, sizeof(why), "mprotect(PROT_BTI) failed: %s (HWCAP2_BTI %s)",
                 strerror(errno), (getauxval(AT_HWCAP2) & HWCAP2_BTI) ? "set" : "clear");
        return why;
    }
    int fl = smaps_has_flag(p, "bt");
    if (fl != 1) {
        snprintf(why, sizeof(why), "/proc/self/smaps %s",
                 fl < 0 ? "has no VmFlags for the page"
                        : "does not list bt for the page");
        return why;
    }
    /* A BR x9 from a guarded page to a nop must fault. */
    case_t c;
    memset(&c, 0, sizeof(c));
    c.form = F_BR;
    c.target = p + 2;
    out_t o;
    memset(&o, 0, sizeof(o));
    install_matrix_handlers();
    g_out = &o;
    g_done = 0;
    g_stage = 0;
    /* The probe returns through ret_stub-less code: the handler sends it to
     * the "ret" after the nop, so give it a target-relative layout.
     */
    ret_stub = p + 3;
    g_cur = &c;
    __asm__ volatile("mov x9, %0\n\t"
                     "blr %1\n\t"
                     :
                     : "r"(p + 2), "r"(p)
                     : "x9", "x30", "memory");
    g_cur = NULL;
    if (o.signo != SIGILL || o.pcrel != 0 || o.btype != 3) {
        snprintf(why, sizeof(why),
                 "a BR to a nop on a guarded page did not fault (signal %d pc T%+lld "
                 "btype %d)",
                 o.signo, (long long)o.pcrel, o.btype);
        return why;
    }
    munmap(p, 4096);
    return NULL;
}

static int
child_main(void *arg)
{
    const variant_t *v = cur_variant;
    int fails = 0;
    (void)arg;
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "setup");
    res_native = calloc(MAX_CASES, sizeof(*res_native));
    res_dr = calloc(MAX_CASES, sizeof(*res_dr));
    alog = calloc(MAX_ALOG, sizeof(*alog));
    map_regions();
    if (do_matrix)
        build_matrix();
    stat_add(ST_NCASES, ncases);
    protect_regions();
    for (int i = 0; i < NUM_PAGES; i++) {
        if ((region_prot[i] & PROT_BTI) && smaps_has_flag(region[i], "bt") != 1) {
            fprintf(stderr, "FAIL [%s]: region %d is not guarded\n", v->name, i);
            return 1;
        }
    }
    /* Graphs: generate them all first, then run natively. */
    graph_t *graphs = NULL;
    gres_t *gref = NULL;
    int ngraphs = 0;
    if (do_graph) {
        graphs = calloc(opt_graphs, sizeof(*graphs));
        gref = calloc(opt_graphs, sizeof(*gref));
        for (int i = 0; i < opt_graphs; i++) {
            graph_t *g = &graphs[i];
            g->path = calloc(PATH_LEN + 1, sizeof(uint64_t));
            g->path_node = calloc(PATH_LEN + 1, sizeof(int));
            uint64_t s = opt_seed * 1000003ULL + (uint64_t)i * 7919ULL;
            int tries = 0;
            while (!gen_graph(g, s, i % 3 == 2)) {
                s = s * 6364136223846793005ULL + 1442695040888963407ULL;
                if (++tries > 100) {
                    fprintf(stderr, "ERROR: cannot generate graph %d\n", i);
                    return 1;
                }
            }
            ngraphs++;
        }
    }

    /* Native. */
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "native matrix");
    if (do_matrix)
        run_matrix(res_native);
    install_graph_handlers();
    long period = 10000;
    for (int i = 0; i < ngraphs; i++) {
        graph_t *g = &graphs[i];
        a64p_prog->block = i;
        a64p_prog->seed = g->seed;
        snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "native graph");
        g_graph = *g;
        emit_graph(&g_graph);
        run_graph_once(&g_graph, &gref[i]);
        if ((g->fault_node >= 0) != gref[i].faulted) {
            fprintf(stderr, "FAIL [%s] graph seed %llu: native %s\n", v->name,
                    (unsigned long long)g->seed,
                    gref[i].faulted ? "faulted unexpectedly" : "did not fault");
            fails++;
            continue;
        }
        if (gref[i].faulted) {
            out_t *o = &gref[i].fault;
            int b = g->node[g->path_node[g->plen - 2]].btype;
            if (o->signo != SIGILL || o->pcrel != 0 || o->btype != b) {
                char s[160];
                out_str(s, sizeof(s), o);
                fprintf(stderr,
                        "FAIL [%s] graph seed %llu: native final fault %s, the model "
                        "expects a BTI fault at the last node with btype %d\n",
                        v->name, (unsigned long long)g->seed, s, b);
                fails++;
            }
            stat_add(ST_GFAULT, 1);
        }
        if (!run_graph_signals(&g_graph, &gref[i], period, "native", v->name))
            fails++;
        fails += check_async(&g_graph, 0, v->name);
    }

    /* Under DR. */
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "start DR");
    a64p_start_dr(v->dr_ops);
    period = 50000;
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "DR matrix");
    if (do_matrix)
        run_matrix(res_dr);
    install_graph_handlers();
    for (int i = 0; i < ngraphs; i++) {
        graph_t *g = &graphs[i];
        a64p_prog->block = i;
        a64p_prog->seed = g->seed;
        snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "DR graph");
        g_graph = *g;
        emit_graph(&g_graph);
        gres_t gr;
        run_graph_once(&g_graph, &gr);
        int dev = 0;
        if (gr.faulted != gref[i].faulted || gr.io.o19 != gref[i].io.o19 ||
            gr.io.o20 != gref[i].io.o20 || gr.io.o23 != gref[i].io.o23 ||
            (gr.faulted && !out_eq(&gr.fault, &gref[i].fault))) {
            dev = 1;
        }
        if (dev && !strict && gref[i].faulted && gr.faulted &&
            gr.fault.signo == SIGSEGV &&
            gr.fault.pcrel == -(int64_t)(uintptr_t)g_graph.node[g->fault_node].code &&
            gr.fault.btype == 0 && gr.io.o23 == gref[i].io.o23 + 1) {
            /* bti-not-enforced: DR ran the incompatible edge's target, which
             * went on to the path's terminating 0 and faulted there.
             */
            stat_add(ST_KD0 + KD_BTI_BRANCH, 1);
            stat_add(ST_GSUPP, 1);
            continue;
        }
        if (dev) {
            char a[160], b[160];
            out_str(a, sizeof(a), &gref[i].fault);
            out_str(b, sizeof(b), &gr.fault);
            fprintf(stderr,
                    "FAIL [%s] graph seed %llu: DR differs from native:\n  native "
                    "x19 %llx x20 %llx x23 %llu %s\n  DR     x19 %llx x20 %llx x23 "
                    "%llu %s\n",
                    v->name, (unsigned long long)g->seed,
                    (unsigned long long)gref[i].io.o19,
                    (unsigned long long)gref[i].io.o20,
                    (unsigned long long)gref[i].io.o23, gref[i].faulted ? a : "",
                    (unsigned long long)gr.io.o19, (unsigned long long)gr.io.o20,
                    (unsigned long long)gr.io.o23, gr.faulted ? b : "");
            fails++;
            continue;
        }
        stat_add(ST_GRAPHS, 1);
        if (!run_graph_signals(&g_graph, &gref[i], period, "DR", v->name))
            fails++;
        fails += check_async(&g_graph, 1, v->name);
    }
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "stop DR");
    a64p_stop_dr();
    if (do_matrix)
        fails += check_matrix(v->name);
    return fails;
}

int
main(int argc, char **argv)
{
    const char *vlist = NULL;
    const char *mode = "all";
    int i = 1;
    if (argc > 1 && argv[1][0] != '-') {
        mode = argv[1];
        i = 2;
    }
    for (; i < argc; i++) {
        if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc)
            opt_seed = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            opt_graphs = atoi(argv[++i]);
        else if (strcmp(argv[i], "-variants") == 0 && i + 1 < argc)
            vlist = argv[++i];
        else if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if (strcmp(mode, "matrix") == 0)
        do_graph = 0;
    else if (strcmp(mode, "graph") == 0)
        do_matrix = 0;
    else if (strcmp(mode, "all") != 0) {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    if (vlist != NULL) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s", vlist);
        for (char *t = strtok(buf, ","); t != NULL; t = strtok(NULL, ",")) {
            int found = 0;
            for (int v = 0; v < NUM_BTI_VARIANTS; v++)
                found |= strcmp(t, bti_variants[v].name) == 0;
            if (!found) {
                fprintf(stderr, "unknown variant '%s'\n", t);
                return 2;
            }
        }
    }
    strict = getenv("A64_PROP_BTI_STRICT") != NULL;
    have_pac = (getauxval(AT_HWCAP) & HWCAP_PACA) != 0;
#ifdef A64_DR_PROP_DEBUG_DR
    is_debug_build = 1;
#endif
    if (getenv("A64_DR_PROP_DEBUG_DR") != NULL)
        is_debug_build = atoi(getenv("A64_DR_PROP_DEBUG_DR"));
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *why = bti_unavailable();
    if (why != NULL) {
        printf("SKIP: PROT_BTI does not take effect: %s\n", why);
        return 0;
    }
    if (!have_pac)
        printf("note: no PAuth, the PAC branch forms are not tested\n");

    a64p_progress_init("a64_prop_bti");
    long tot[ST_NUM];
    memset(tot, 0, sizeof(tot));
    int fails = 0, nvar = 0;
    for (int v = 0; v < NUM_BTI_VARIANTS; v++) {
        const variant_t *var = &bti_variants[v];
        if (vlist != NULL && !a64p_variant_selected(vlist, var))
            continue;
        if (var->debug_only && !is_debug_build)
            continue;
        cur_variant = var;
        int f = a64p_in_child("bti", var, child_main, NULL);
        for (int s = 0; s < ST_NUM; s++)
            tot[s] += a64p_prog->stat[s];
        if (f != 0)
            fprintf(stderr, "variant %s: %d failures\n", var->name, f);
        fails += f;
        nvar++;
    }
    if (nvar == 0) {
        fprintf(stderr, "no variant selected\n");
        return 2;
    }
    /* Counts and floors. */
    long kd_total = 0;
    for (int k = 0; k < NUM_KD; k++)
        kd_total += tot[ST_KD0 + k];
    if (do_matrix) {
        a64p_counts_t c;
        memset(&c, 0, sizeof(c));
        c.generated = tot[ST_NCASES] * REPS;
        c.accepted = tot[ST_MODEL];
        c.executed = tot[ST_CASES];
        c.checked = tot[ST_EXACT];
        c.suppressed = tot[ST_CASES] - tot[ST_EXACT];
        a64p_counts_print(stdout, "bti matrix", &c);
        printf("bti matrix: brk on a guarded page with BTYPE != 0: %s\n",
               tot[ST_BRKBTI] > 0 && tot[ST_BRKRUN] == 0
                   ? "BTI fault"
                   : (tot[ST_BRKRUN] > 0 && tot[ST_BRKBTI] == 0 ? "runs" : "mixed"));
        fails += a64p_floor("bti matrix", "native runs checked against the model",
                            tot[ST_MODEL], c.generated);
        fails += a64p_floor("bti matrix", "DR runs compared", tot[ST_CASES], c.generated);
    }
    if (do_graph) {
        a64p_counts_t c;
        memset(&c, 0, sizeof(c));
        c.generated = (long)opt_graphs * nvar;
        c.accepted = c.generated;
        c.executed = tot[ST_GRAPHS] + tot[ST_GSUPP];
        c.checked = tot[ST_GRAPHS];
        c.suppressed = tot[ST_GSUPP];
        a64p_counts_print(stdout, "bti graph", &c);
        printf("bti graph: interrupted contexts checked: native %ld (%ld at a node "
               "entry), DR %ld (%ld at a node entry)\n",
               tot[ST_ASYNC_N], tot[ST_ASYNC_NT], tot[ST_ASYNC_D], tot[ST_ASYNC_DT]);
        fails += a64p_floor("bti graph", "graphs run", c.executed, c.generated);
        fails += a64p_floor("bti graph", "graphs ending in a BTI fault natively",
                            tot[ST_GFAULT], c.generated / 4);
        fails += a64p_floor("bti graph", "native interrupted contexts", tot[ST_ASYNC_N],
                            20L * c.generated);
        fails += a64p_floor("bti graph", "native contexts at a node entry",
                            tot[ST_ASYNC_NT], 2L * c.generated);
        fails += a64p_floor("bti graph", "DR interrupted contexts", tot[ST_ASYNC_D],
                            5L * c.generated);
    }
    printf("bti known deviations:");
    for (int k = 0; k < NUM_KD; k++)
        printf("%s%s %ld", k == 0 ? " " : ", ", kd_name[k], tot[ST_KD0 + k]);
    printf("\n");
    if (strict && kd_total > 0)
        fails++;
    if (fails == 0)
        printf("bti: all properties hold\n");
    else
        printf("bti: %d failures\n", fails);
    return fails == 0 ? 0 : 1;
}

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

/* AArch64 out-of-line clean calls (DR_CLEANCALL_ALWAYS_OUT_OF_LINE): the call
 * site's few instructions and the clean_call_{save,restore} routines that do the
 * whole context switch, interrupted at every instruction.
 *
 * A static-DR executable with its client in the same file.  Each variant has its
 * own copy of an assembly function (ool_target_<v>) that sets every GPR (x28,
 * DR's stolen register, and x30 included), SP (into a stack of the test's own),
 * NZCV and V0-V31 to values that change with every run, then reaches a NOP
 * (ool_site_<v>) before which the client inserts the clean call, then a CBNZ XZR
 * that ends the block, and at ool_after_<v> stores the whole state for the test
 * to compare with what the variant should leave.  Variants:
 *   plain    a callee with no arguments;
 *   args     ten arguments, x30 among the register ones and among the two that
 *            go on the stack, which the callee records;
 *   write    a READS|WRITES_APP_CONTEXT callee that checks dr_get_mcontext()
 *            against the state set and changes x30, SP, the stolen register
 *            (x28), x5, NZCV and V3 with dr_set_mcontext();
 *   redirect the same changes, then dr_redirect_execution() to ool_after;
 *   skip     a meta CBZ on the app's x9 skips the (MULTIPATH) call when it is 0;
 *   fault    the write callee's changes, but ool_site's instruction is a load
 *            from x30, which holds an unmapped address before and after the
 *            change: the app's SIGSEGV handler must see the variant's result at
 *            ool_site (translated right after the restore), and resumes at
 *            ool_after.  (A memory argument, which could fault inside the call,
 *            is not implemented on AArch64: i#2210.)
 * Modes (argv[1]):
 *   basic   every variant, many runs, no interruptions.
 *   stress  the same while a POSIX timer sends SIGUSR1 every 50us and a client
 *           thread suspends the app thread (dr_suspend_all_other_threads_ex())
 *           in a loop: every interrupted context delivered to the app, and every
 *           context dr_get_mcontext() gives for a suspended thread, at ool_site
 *           or ool_after must be the state set or the variant's result.  A
 *           second argument, a number of seconds, ends the runs early once they
 *           have taken that long (under a loaded machine or a debug DR the
 *           5000 runs have taken minutes).
 *   sweep   deterministic: a parent process ptraces the app thread.  The client
 *           puts a BRK before and after each clean call; at each run the parent
 *           single-steps k instructions from the first BRK (stepping over the
 *           callee itself) and then, at that instruction, either injects SIGUSR1
 *           or lets a pending suspend signal of the client thread's
 *           dr_suspend_all_other_threads_ex() be delivered there, for every k
 *           up to the second BRK and every variant (so every instruction of the
 *           call site and of both routines).  A SIGUSR1 must reach the app's
 *           handler exactly once, at ool_after, with the variant's result; a
 *           suspension must either retry (an untranslatable point) or give the
 *           state set or the result at ool_site/ool_after; the state must be the
 *           variant's result after every run.
 * A second argument "store" makes the client return DR_EMIT_STORE_TRANSLATIONS,
 * so that DR translates from the translation info it recorded at emit (where the
 * clean call's DR_NOTE_CALL_SEQUENCE_START/END region is a flag on its entries)
 * rather than from a rebuilt instruction list.
 */

#include "dr_api.h"
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ucontext.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <asm/ptrace.h>

/***************************************************************************
 * State and the assembly targets
 */

typedef struct {
    uint64_t x[31]; /* 0: x0-x30 */
    uint64_t sp;    /* 248 */
    uint64_t nzcv;  /* 256 */
    uint64_t pad;
    __uint128_t v[32]; /* 272 */
} ool_state_t;

typedef struct {
    ool_state_t in;    /* 0: what the target sets */
    ool_state_t out;   /* 784: what it finds at ool_after */
    uint64_t entry_sp; /* 1568 */
    uint64_t pad;
    ool_state_t exp; /* what the variant should leave */
} ool_frame_t;

_Static_assert(offsetof(ool_state_t, sp) == 248, "asm offsets");
_Static_assert(offsetof(ool_state_t, nzcv) == 256, "asm offsets");
_Static_assert(offsetof(ool_state_t, v) == 272, "asm offsets");
_Static_assert(offsetof(ool_frame_t, out) == 784, "asm offsets");
_Static_assert(offsetof(ool_frame_t, entry_sp) == 1568, "asm offsets");

/* The frame of the run in progress (read by the targets, the signal handlers, the
 * callees and the client thread).
 */
ool_frame_t *volatile ool_cur;

/* clang-format off */
#define LDQ(n, m, off) "ldp q" #n ", q" #m ", [x1, #" #off "]\n"
#define STQ(n, m, off) "stp q" #n ", q" #m ", [x0, #" #off "]\n"
__asm__(
    ".macro OOL_TARGET n, fault=0\n"
    ".text\n"
    ".p2align 4\n"
    ".globl ool_target_\\n\n"
    ".type ool_target_\\n, %function\n"
    "ool_target_\\n:\n"
    "stp x29, x30, [sp, #-160]!\n"
    "mov x29, sp\n"
    "stp x19, x20, [sp, #16]\n"
    "stp x21, x22, [sp, #32]\n"
    "stp x23, x24, [sp, #48]\n"
    "stp x25, x26, [sp, #64]\n"
    "stp x27, x28, [sp, #80]\n"
    "stp d8, d9, [sp, #96]\n"
    "stp d10, d11, [sp, #112]\n"
    "stp d12, d13, [sp, #128]\n"
    "stp d14, d15, [sp, #144]\n"
    "mov x1, sp\n"
    "str x1, [x0, #1568]\n"
    "add x1, x0, #272\n"
    LDQ(0, 1, 0) LDQ(2, 3, 32) LDQ(4, 5, 64) LDQ(6, 7, 96)
    LDQ(8, 9, 128) LDQ(10, 11, 160) LDQ(12, 13, 192) LDQ(14, 15, 224)
    LDQ(16, 17, 256) LDQ(18, 19, 288) LDQ(20, 21, 320) LDQ(22, 23, 352)
    LDQ(24, 25, 384) LDQ(26, 27, 416) LDQ(28, 29, 448) LDQ(30, 31, 480)
    "ldr x1, [x0, #256]\n"
    "msr nzcv, x1\n"
    "ldr x1, [x0, #248]\n"
    "mov sp, x1\n"
    "ldp x2, x3, [x0, #16]\n"
    "ldp x4, x5, [x0, #32]\n"
    "ldp x6, x7, [x0, #48]\n"
    "ldp x8, x9, [x0, #64]\n"
    "ldp x10, x11, [x0, #80]\n"
    "ldp x12, x13, [x0, #96]\n"
    "ldp x14, x15, [x0, #112]\n"
    "ldp x16, x17, [x0, #128]\n"
    "ldp x18, x19, [x0, #144]\n"
    "ldp x20, x21, [x0, #160]\n"
    "ldp x22, x23, [x0, #176]\n"
    "ldp x24, x25, [x0, #192]\n"
    "ldp x26, x27, [x0, #208]\n"
    "ldp x28, x29, [x0, #224]\n"
    "ldr x30, [x0, #240]\n"
    "ldr x1, [x0, #8]\n"
    "ldr x0, [x0, #0]\n"
    ".globl ool_site_\\n\n"
    "ool_site_\\n:\n"
    ".if \\fault\n"
    "ldr xzr, [x30]\n"
    ".else\n"
    "nop\n"
    ".endif\n"
    "cbnz xzr, ool_after_\\n\n"
    ".globl ool_after_\\n\n"
    "ool_after_\\n:\n"
    "stp x0, x1, [sp, #-16]!\n"
    "adrp x1, ool_cur\n"
    "ldr x1, [x1, #:lo12:ool_cur]\n"
    "add x1, x1, #784\n"
    "ldr x0, [sp]\n"
    "str x0, [x1, #0]\n"
    "ldr x0, [sp, #8]\n"
    "str x0, [x1, #8]\n"
    "stp x2, x3, [x1, #16]\n"
    "stp x4, x5, [x1, #32]\n"
    "stp x6, x7, [x1, #48]\n"
    "stp x8, x9, [x1, #64]\n"
    "stp x10, x11, [x1, #80]\n"
    "stp x12, x13, [x1, #96]\n"
    "stp x14, x15, [x1, #112]\n"
    "stp x16, x17, [x1, #128]\n"
    "stp x18, x19, [x1, #144]\n"
    "stp x20, x21, [x1, #160]\n"
    "stp x22, x23, [x1, #176]\n"
    "stp x24, x25, [x1, #192]\n"
    "stp x26, x27, [x1, #208]\n"
    "stp x28, x29, [x1, #224]\n"
    "str x30, [x1, #240]\n"
    "mrs x0, nzcv\n"
    "str x0, [x1, #256]\n"
    "add x0, sp, #16\n"
    "str x0, [x1, #248]\n"
    "add x0, x1, #272\n"
    STQ(0, 1, 0) STQ(2, 3, 32) STQ(4, 5, 64) STQ(6, 7, 96)
    STQ(8, 9, 128) STQ(10, 11, 160) STQ(12, 13, 192) STQ(14, 15, 224)
    STQ(16, 17, 256) STQ(18, 19, 288) STQ(20, 21, 320) STQ(22, 23, 352)
    STQ(24, 25, 384) STQ(26, 27, 416) STQ(28, 29, 448) STQ(30, 31, 480)
    "ldr x0, [x1, #784]\n"
    "mov sp, x0\n"
    "ldp x19, x20, [sp, #16]\n"
    "ldp x21, x22, [sp, #32]\n"
    "ldp x23, x24, [sp, #48]\n"
    "ldp x25, x26, [sp, #64]\n"
    "ldp x27, x28, [sp, #80]\n"
    "ldp d8, d9, [sp, #96]\n"
    "ldp d10, d11, [sp, #112]\n"
    "ldp d12, d13, [sp, #128]\n"
    "ldp d14, d15, [sp, #144]\n"
    "ldp x29, x30, [sp], #160\n"
    "ret\n"
    ".size ool_target_\\n, .-ool_target_\\n\n"
    ".endm\n"
    "OOL_TARGET 0\n"
    "OOL_TARGET 1\n"
    "OOL_TARGET 2\n"
    "OOL_TARGET 3\n"
    "OOL_TARGET 4\n"
    "OOL_TARGET 5, 1\n");
/* clang-format on */

enum { V_PLAIN, V_ARGS, V_WRITE, V_REDIRECT, V_SKIP, V_FAULT, NUM_VARIANTS };
static const char *const variant_names[NUM_VARIANTS] = { "plain",    "args", "write",
                                                         "redirect", "skip", "fault" };

#define DECLARE_TARGET(n)                      \
    extern void ool_target_##n(ool_frame_t *); \
    extern char ool_site_##n[], ool_after_##n[];
DECLARE_TARGET(0)
DECLARE_TARGET(1)
DECLARE_TARGET(2)
DECLARE_TARGET(3)
DECLARE_TARGET(4)
DECLARE_TARGET(5)
static void (*const targets[NUM_VARIANTS])(ool_frame_t *) = {
    ool_target_0, ool_target_1, ool_target_2, ool_target_3, ool_target_4, ool_target_5
};
static char *const sites[NUM_VARIANTS] = { ool_site_0, ool_site_1, ool_site_2,
                                           ool_site_3, ool_site_4, ool_site_5 };
static char *const afters[NUM_VARIANTS] = { ool_after_0, ool_after_1, ool_after_2,
                                            ool_after_3, ool_after_4, ool_after_5 };

/* The changes the write and redirect callees make. */
#define EDIT_X30 0x0f0f000000000030ULL
#define EDIT_X28 0x0f0f000000000028ULL
#define EDIT_X5 0x0f0f000000000005ULL
#define EDIT_SP 64
#define EDIT_NZCV (1ULL << 29)
#define EDIT_V3 0x33ULL

/* An address no run can load from (the fault variant's x30), before and after
 * EDIT_X30.
 */
#define BAD_ADDR 0x18ULL

#define TEST_STACK_SIZE (256 * 1024)
static char test_stack[TEST_STACK_SIZE] __attribute__((aligned(16)));

/***************************************************************************
 * Shared state and checks
 */

typedef struct {
    /* Parent (sweep) to child. */
    volatile int sweep_variant; /* -1: stop */
    volatile int s_go;          /* the client thread should suspend once */
    volatile int s_exit;
    volatile int s_exited;
    /* Child to parent. */
    volatile long sig_delivered, sig_at_after, sig_at_site, sig_elsewhere[NUM_VARIANTS];
    volatile long susp_done, susp_at_site, susp_at_after, susp_elsewhere;
    volatile long mismatches, runs, faults, callee_checked;
    char msg[2048];
} shared_t;

static shared_t *shared;
static int mode_sweep, mode_stress, mode_store;
static volatile int cur_variant = -1;
static volatile int dr_ready; /* the client thread may suspend */
static uint64_t args_seen[10];
static volatile long callee_calls;

static void
fail(const char *fmt, ...)
{
    __atomic_fetch_add(&shared->mismatches, 1, __ATOMIC_SEQ_CST);
    if (shared->msg[0] != '\0')
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(shared->msg, sizeof(shared->msg), fmt, ap);
    va_end(ap);
}

/* Returns the first difference between two states, or NULL. */
static const char *
state_diff(const ool_state_t *a, const ool_state_t *b, char *buf, size_t len)
{
    for (int i = 0; i < 31; i++) {
        if (a->x[i] != b->x[i]) {
            snprintf(buf, len, "x%d %#llx vs %#llx", i, (unsigned long long)a->x[i],
                     (unsigned long long)b->x[i]);
            return buf;
        }
    }
    if (a->sp != b->sp) {
        snprintf(buf, len, "sp %#llx vs %#llx", (unsigned long long)a->sp,
                 (unsigned long long)b->sp);
        return buf;
    }
    if (a->nzcv != b->nzcv) {
        snprintf(buf, len, "nzcv %#llx vs %#llx", (unsigned long long)a->nzcv,
                 (unsigned long long)b->nzcv);
        return buf;
    }
    for (int i = 0; i < 32; i++) {
        if (a->v[i] != b->v[i]) {
            snprintf(buf, len, "v%d %#llx:%#llx vs %#llx:%#llx", i,
                     (unsigned long long)(a->v[i] >> 64), (unsigned long long)a->v[i],
                     (unsigned long long)(b->v[i] >> 64), (unsigned long long)b->v[i]);
            return buf;
        }
    }
    return NULL;
}

/* Checks an interrupted state seen at app pc: at ool_site it must be the state
 * set or the variant's result (the context saved for the call, before or after
 * the callee changed it), and at ool_after the result.  Returns -1 for another pc
 * (not checked), 0 at ool_site, 1 at ool_after.
 */
static int
check_interrupted(const char *who, uint64_t pc, const ool_state_t *s)
{
    ool_frame_t *f = ool_cur;
    int v = cur_variant;
    char buf[160];
    if (f == NULL || v < 0)
        return -1;
    if (pc == (uint64_t)afters[v]) {
        const char *d = state_diff(s, &f->exp, buf, sizeof(buf));
        if (d != NULL)
            fail("%s: %s at ool_after: %s (got vs expected)\n", who, variant_names[v], d);
        return 1;
    }
    if (pc == (uint64_t)sites[v]) {
        const char *d = state_diff(s, &f->in, buf, sizeof(buf));
        if (d != NULL && state_diff(s, &f->exp, buf, sizeof(buf)) != NULL)
            fail("%s: %s at ool_site: %s (got vs result)\n", who, variant_names[v], d);
        return 0;
    }
    return -1;
}

/***************************************************************************
 * The app's signal handlers
 */

#define FPSIMD_MAGIC_ 0x46508001

static void
state_from_ucontext(ucontext_t *uc, ool_state_t *s)
{
    memset(s, 0, sizeof(*s));
    for (int i = 0; i < 31; i++)
        s->x[i] = uc->uc_mcontext.regs[i];
    s->sp = uc->uc_mcontext.sp;
    s->nzcv = uc->uc_mcontext.pstate & 0xf0000000ULL;
    byte *p = (byte *)uc->uc_mcontext.__reserved;
    while (p + 8 <=
           (byte *)uc->uc_mcontext.__reserved + sizeof(uc->uc_mcontext.__reserved)) {
        uint32_t magic = *(uint32_t *)p, size = *(uint32_t *)(p + 4);
        if (magic == 0 || size == 0)
            break;
        if (magic == FPSIMD_MAGIC_) {
            /* head (8), fpsr (4), fpcr (4), vregs[32]. */
            memcpy(s->v, p + 16, sizeof(s->v));
            break;
        }
        p += size;
    }
}

static void
handle_usr1(int sig, siginfo_t *info, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    ool_state_t s;
    int v = cur_variant;
    __atomic_fetch_add(&shared->sig_delivered, 1, __ATOMIC_SEQ_CST);
    state_from_ucontext(uc, &s);
    int where = check_interrupted("SIGUSR1", uc->uc_mcontext.pc, &s);
    if (v == V_FAULT && where != 1) {
        /* The fault may come first, and the signal be delivered in its handler. */
        __atomic_fetch_add(&shared->sig_elsewhere[v], 1, __ATOMIC_SEQ_CST);
    } else if (where == 1)
        __atomic_fetch_add(&shared->sig_at_after, 1, __ATOMIC_SEQ_CST);
    else if (where == 0)
        __atomic_fetch_add(&shared->sig_at_site, 1, __ATOMIC_SEQ_CST);
    else if (v >= 0)
        __atomic_fetch_add(&shared->sig_elsewhere[v], 1, __ATOMIC_SEQ_CST);
}

static void
handle_segv(int sig, siginfo_t *info, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    ool_state_t s;
    char buf[160];
    if (cur_variant != V_FAULT || uc->uc_mcontext.pc != (uint64_t)sites[V_FAULT] ||
        /* The kernel clears the address's top byte (TBI). */
        (uint64_t)info->si_addr != (ool_cur->exp.x[30] & ((1ULL << 56) - 1))) {
        fprintf(stderr, "unexpected SIGSEGV: pc %#llx addr %p variant %d\n",
                (unsigned long long)uc->uc_mcontext.pc, info->si_addr, cur_variant);
        _exit(1);
    }
    state_from_ucontext(uc, &s);
    const char *d = state_diff(&s, &ool_cur->exp, buf, sizeof(buf));
    if (d != NULL)
        fail("SIGSEGV: fault after the call: %s (got vs expected)\n", d);
    shared->faults++;
    uc->uc_mcontext.pc = (uint64_t)afters[V_FAULT];
}

/***************************************************************************
 * The client
 */

static void
callee_plain(void)
{
    callee_calls++;
}

static void
callee_args(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5,
            uint64_t a6, uint64_t a7, uint64_t a8, uint64_t a9)
{
    uint64_t a[10] = { a0, a1, a2, a3, a4, a5, a6, a7, a8, a9 };
    memcpy(args_seen, a, sizeof(a));
    callee_calls++;
}

static void
state_from_mcontext(dr_mcontext_t *mc, ool_state_t *s)
{
    memset(s, 0, sizeof(*s));
    for (int i = 0; i < 31; i++)
        s->x[i] = reg_get_value(DR_REG_X0 + i, mc);
    s->sp = mc->sp;
    s->nzcv = mc->nzcv & 0xf0000000U;
    for (int i = 0; i < 32; i++)
        s->v[i] = ((__uint128_t)mc->simd[i].u64[1] << 64) | mc->simd[i].u64[0];
}

static void
edit_mcontext(dr_mcontext_t *mc)
{
    reg_set_value(DR_REG_X30, mc, reg_get_value(DR_REG_X30, mc) ^ EDIT_X30);
    reg_set_value(DR_REG_X28, mc, reg_get_value(DR_REG_X28, mc) ^ EDIT_X28);
    reg_set_value(DR_REG_X5, mc, reg_get_value(DR_REG_X5, mc) ^ EDIT_X5);
    mc->sp -= EDIT_SP;
    mc->nzcv ^= EDIT_NZCV;
    mc->simd[3].u64[0] ^= EDIT_V3;
}

static void
callee_check_and_edit(dr_mcontext_t *mc)
{
    void *dc = dr_get_current_drcontext();
    ool_state_t s;
    char buf[160];
    if (!dr_get_mcontext(dc, mc))
        fail("dr_get_mcontext failed\n");
    state_from_mcontext(mc, &s);
    const char *d = state_diff(&s, &ool_cur->in, buf, sizeof(buf));
    if (d != NULL)
        fail("%s callee: dr_get_mcontext(): %s (got vs set)\n",
             variant_names[cur_variant], d);
    shared->callee_checked++;
    edit_mcontext(mc);
    callee_calls++;
}

static void
callee_write(void)
{
    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    callee_check_and_edit(&mc);
    if (!dr_set_mcontext(dr_get_current_drcontext(), &mc))
        fail("dr_set_mcontext failed\n");
}

static void
callee_redirect(void)
{
    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    callee_check_and_edit(&mc);
    mc.pc = (app_pc)afters[V_REDIRECT];
    dr_redirect_execution(&mc);
    fail("dr_redirect_execution returned\n");
}

#define BRK(imm) INSTR_CREATE_brk(dc, OPND_CREATE_INT16(imm))
#define MARK_START(v) (0x100 + (v))
#define MARK_END(v) (0x200 + (v))
#define MARK_STEP 0x3cc
#define BRK_WORD(imm) (0xd4200000U | ((uint32_t)(imm) << 5))

static dr_emit_flags_t
event_bb(void *dc, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    for (instr_t *inst = instrlist_first_app(bb); inst != NULL;
         inst = instr_get_next_app(inst)) {
        app_pc pc = instr_get_app_pc(inst);
        int v;
        for (v = 0; v < NUM_VARIANTS; v++) {
            if (pc == (app_pc)sites[v])
                break;
        }
        if (v == NUM_VARIANTS)
            continue;
        if (mode_sweep)
            instrlist_meta_preinsert(bb, inst, BRK(MARK_START(v)));
        opnd_t x30 = opnd_create_reg(DR_REG_X30);
        switch (v) {
        case V_PLAIN:
            dr_insert_clean_call_ex(dc, bb, inst, (void *)callee_plain,
                                    DR_CLEANCALL_ALWAYS_OUT_OF_LINE, 0);
            break;
        case V_ARGS:
            dr_insert_clean_call_ex(
                dc, bb, inst, (void *)callee_args, DR_CLEANCALL_ALWAYS_OUT_OF_LINE, 10,
                x30, opnd_create_reg(DR_REG_X1), opnd_create_reg(DR_REG_X2),
                opnd_create_reg(DR_REG_X3), opnd_create_reg(DR_REG_X4),
                opnd_create_reg(DR_REG_X5), opnd_create_reg(DR_REG_X6),
                opnd_create_reg(DR_REG_X7), opnd_create_reg(DR_REG_X29), x30);
            break;
        case V_WRITE:
        case V_FAULT:
        case V_REDIRECT:
            dr_insert_clean_call_ex(
                dc, bb, inst,
                v == V_REDIRECT ? (void *)callee_redirect : (void *)callee_write,
                DR_CLEANCALL_ALWAYS_OUT_OF_LINE | DR_CLEANCALL_READS_APP_CONTEXT |
                    DR_CLEANCALL_WRITES_APP_CONTEXT,
                0);
            break;
        case V_SKIP: {
            instr_t *skip = INSTR_CREATE_label(dc);
            instrlist_meta_preinsert(bb, inst,
                                     INSTR_CREATE_cbz(dc, opnd_create_instr(skip),
                                                      opnd_create_reg(DR_REG_X9)));
            dr_insert_clean_call_ex(
                dc, bb, inst, (void *)callee_plain,
                DR_CLEANCALL_ALWAYS_OUT_OF_LINE | DR_CLEANCALL_MULTIPATH, 0);
            instrlist_meta_preinsert(bb, inst, skip);
            break;
        }
        }
        if (mode_sweep)
            instrlist_meta_preinsert(bb, inst, BRK(MARK_END(v)));
    }
    return mode_store ? DR_EMIT_STORE_TRANSLATIONS : DR_EMIT_DEFAULT;
}

/* Suspends the app thread and checks the context DR translated for it. */
static void
suspend_and_check(void)
{
    void **drcs;
    uint num, unsuspended;
    if (!dr_suspend_all_other_threads_ex(&drcs, &num, &unsuspended, 0)) {
        fail("dr_suspend_all_other_threads_ex failed\n");
        return;
    }
    for (uint i = 0; i < num; i++) {
        dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
        ool_state_t s;
        if (!dr_get_mcontext(drcs[i], &mc)) {
            fail("dr_get_mcontext of a suspended thread failed\n");
            continue;
        }
        state_from_mcontext(&mc, &s);
        int where = check_interrupted("suspend", (uint64_t)mc.pc, &s);
        if (where == 1)
            shared->susp_at_after++;
        else if (where == 0)
            shared->susp_at_site++;
        else
            shared->susp_elsewhere++;
    }
    if (!dr_resume_all_other_threads(drcs, num))
        fail("dr_resume_all_other_threads failed\n");
    shared->susp_done++;
}

static void
suspender(void *arg)
{
    while (!shared->s_exit) {
        if (dr_ready && (mode_stress || shared->s_go)) {
            suspend_and_check();
            shared->s_go = 0;
            if (mode_stress)
                dr_thread_yield();
        } else
            dr_sleep(1);
    }
    shared->s_exited = 1;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_register_bb_event(event_bb);
    if (mode_sweep || mode_stress)
        dr_create_client_thread(suspender, NULL);
}

/***************************************************************************
 * The app
 */

static void
make_state(ool_frame_t *f, int v, uint64_t run)
{
    uint64_t seed = (run + 1) * 0x9e3779b97f4a7c15ULL ^ ((uint64_t)v << 56);
    ool_state_t *s = &f->in;
    memset(s, 0, sizeof(*s));
    for (int i = 0; i < 31; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        s->x[i] = seed ^ ((uint64_t)i << 48);
    }
    if (v == V_SKIP)
        s->x[9] = (mode_sweep || (run & 1) != 0) ? s->x[9] | 1 : 0;
    if (v == V_FAULT)
        s->x[30] = BAD_ADDR;
    /* Below the top, by a varying amount, with room for the redirect's move. */
    s->sp = ((uint64_t)(test_stack + TEST_STACK_SIZE) - 1024 - (run % 8) * 16) & ~15ULL;
    s->nzcv = (run % 16) << 28;
    for (int i = 0; i < 32; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        s->v[i] = ((__uint128_t)seed << 64) | (seed ^ (uint64_t)i);
    }
    f->exp = f->in;
    if (v == V_WRITE || v == V_REDIRECT || v == V_FAULT) {
        f->exp.x[30] ^= EDIT_X30;
        f->exp.x[28] ^= EDIT_X28;
        f->exp.x[5] ^= EDIT_X5;
        f->exp.sp -= EDIT_SP;
        f->exp.nzcv ^= EDIT_NZCV;
        f->exp.v[3] ^= EDIT_V3;
    }
}

static ool_frame_t frame;

static void
run_one(int v, uint64_t run)
{
    char buf[160];
    long calls = callee_calls, faults = shared->faults;
    make_state(&frame, v, run);
    memset(&frame.out, 0, sizeof(frame.out));
    memset(args_seen, 0, sizeof(args_seen));
    ool_cur = &frame;
    cur_variant = v;
    targets[v](&frame);
    cur_variant = -1;
    const char *d = state_diff(&frame.out, &frame.exp, buf, sizeof(buf));
    if (d != NULL)
        fail("%s run %llu: state after the call: %s (got vs expected)\n",
             variant_names[v], (unsigned long long)run, d);
    bool called = !(v == V_SKIP && frame.in.x[9] == 0);
    if (called != (callee_calls != calls))
        fail("%s run %llu: callee %s\n", variant_names[v], (unsigned long long)run,
             called ? "not called" : "called");
    if (v == V_FAULT && shared->faults != faults + 1)
        fail("fault run %llu: no fault\n", (unsigned long long)run);
    if (v == V_ARGS) {
        const uint64_t *x = frame.in.x;
        uint64_t want[10] = { x[30], x[1], x[2], x[3],  x[4],
                              x[5],  x[6], x[7], x[29], x[30] };
        for (int i = 0; i < 10; i++) {
            if (args_seen[i] != want[i]) {
                fail("args run %llu: argument %d is %#llx, not %#llx\n",
                     (unsigned long long)run, i, (unsigned long long)args_seen[i],
                     (unsigned long long)want[i]);
            }
        }
        shared->callee_checked++;
    }
    shared->runs++;
}

static void
install_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handle_usr1;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_sigaction = handle_segv;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
}

static void
start_dr(void)
{
    if (dr_app_setup_and_start() != 0 || !dr_app_running_under_dynamorio()) {
        fprintf(stderr, "ERROR: could not start DR\n");
        exit(1);
    }
    dr_ready = 1;
}

static void
stop_dr(void)
{
    shared->s_exit = 1;
    if (mode_sweep || mode_stress) {
        while (!shared->s_exited)
            usleep(1000);
    }
    dr_app_stop_and_cleanup();
}

static double
monotonic_secs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Runs every variant runs times, or until max_secs seconds have passed if that
 * is sooner (0: no limit).
 */
static int
run_basic_or_stress(const char *mode, int runs, double max_secs)
{
    timer_t timer;
    install_handlers();
    start_dr();
    if (mode_stress) {
        struct sigevent sev;
        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_THREAD_ID;
        sev.sigev_signo = SIGUSR1;
        sev._sigev_un._tid = syscall(SYS_gettid);
        if (timer_create(CLOCK_MONOTONIC, &sev, &timer) != 0) {
            perror("timer_create");
            return 1;
        }
        struct itimerspec its = { { 0, 50000 }, { 0, 50000 } };
        timer_settime(timer, 0, &its, NULL);
    }
    double start = monotonic_secs();
    for (int r = 0; r < runs; r++) {
        for (int v = 0; v < NUM_VARIANTS; v++)
            run_one(v, (uint64_t)r);
        if (max_secs > 0 && monotonic_secs() - start > max_secs)
            break;
    }
    if (mode_stress) {
        struct itimerspec its = { { 0, 0 }, { 0, 0 } };
        timer_settime(timer, 0, &its, NULL);
        timer_delete(timer);
    }
    stop_dr();
    long elsewhere = 0;
    for (int v = 0; v < NUM_VARIANTS; v++)
        elsewhere += shared->sig_elsewhere[v];
    printf("%s: runs %ld, callee contexts and arguments checked %ld, faults %ld\n", mode,
           shared->runs, shared->callee_checked, shared->faults);
    if (mode_stress) {
        printf("%s: signals %ld (at ool_after %ld, at ool_site %ld, elsewhere %ld), "
               "suspensions %ld (at ool_after %ld, at ool_site %ld, elsewhere %ld)\n",
               mode, shared->sig_delivered, shared->sig_at_after, shared->sig_at_site,
               elsewhere, shared->susp_done, shared->susp_at_after, shared->susp_at_site,
               shared->susp_elsewhere);
    }
    if (shared->mismatches != 0) {
        printf("%s: FAILED: %ld mismatches; first: %s", mode, shared->mismatches,
               shared->msg);
        return 1;
    }
    printf("%s: all properties hold\n", mode);
    return 0;
}

/* The child of the sweep: runs the variant the parent asks for until told to stop. */
static int
sweep_child(void)
{
    install_handlers();
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
        perror("PTRACE_TRACEME");
        return 1;
    }
    raise(SIGSTOP);
    start_dr();
    for (uint64_t r = 0;; r++) {
        int v = shared->sweep_variant;
        if (v < 0)
            break;
        run_one(v, r);
    }
    stop_dr();
    return shared->mismatches != 0 ? 1 : 0;
}

/***************************************************************************
 * The sweep's tracer
 */

static pid_t child;
static long steps_total, injections[2], seq_len[NUM_VARIANTS];
/* Where the first mismatch came from. */
static char first_bad[256];

static void
tracer_fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("sweep: FAILED: ");
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
    kill(child, SIGKILL);
    exit(1);
}

static struct user_pt_regs
get_regs(void)
{
    struct user_pt_regs r;
    struct iovec iov = { &r, sizeof(r) };
    if (ptrace(PTRACE_GETREGSET, child, (void *)NT_PRSTATUS, &iov) != 0)
        tracer_fail("GETREGSET: %s\n", strerror(errno));
    return r;
}

static void
set_pc(uint64_t pc)
{
    struct user_pt_regs r = get_regs();
    struct iovec iov = { &r, sizeof(r) };
    r.pc = pc;
    if (ptrace(PTRACE_SETREGSET, child, (void *)NT_PRSTATUS, &iov) != 0)
        tracer_fail("SETREGSET: %s\n", strerror(errno));
}

static uint32_t
read_word(uint64_t pc)
{
    errno = 0;
    long w = ptrace(PTRACE_PEEKTEXT, child, (void *)(pc & ~7ULL), 0);
    if (errno != 0)
        tracer_fail("PEEKTEXT %#llx: %s\n", (unsigned long long)pc, strerror(errno));
    return (pc & 4) != 0 ? (uint32_t)((uint64_t)w >> 32) : (uint32_t)w;
}

static void
write_word(uint64_t pc, uint32_t word)
{
    errno = 0;
    uint64_t w = (uint64_t)ptrace(PTRACE_PEEKTEXT, child, (void *)(pc & ~7ULL), 0);
    if (errno != 0)
        tracer_fail("PEEKTEXT %#llx: %s\n", (unsigned long long)pc, strerror(errno));
    if ((pc & 4) != 0)
        w = (w & 0xffffffffULL) | ((uint64_t)word << 32);
    else
        w = (w & ~0xffffffffULL) | word;
    if (ptrace(PTRACE_POKETEXT, child, (void *)(pc & ~7ULL), (void *)w) != 0)
        tracer_fail("POKETEXT %#llx: %s\n", (unsigned long long)pc, strerror(errno));
}

/* Resumes the child (singlestep or not, with sig) and waits for its next stop.
 * Returns the stop signal.
 */
static int
resume(int req, int sig)
{
    int status;
    if (ptrace(req, child, 0, (void *)(long)sig) != 0)
        tracer_fail("ptrace resume: %s\n", strerror(errno));
    if (waitpid(child, &status, __WALL) != child)
        tracer_fail("waitpid: %s\n", strerror(errno));
    if (!WIFSTOPPED(status)) {
        tracer_fail("the child %s %d\n", WIFEXITED(status) ? "exited with" : "died of",
                    WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
    }
    return WSTOPSIG(status);
}

/* Returns the BRK immediate at pc, or -1. */
static int
brk_at(uint64_t pc)
{
    uint32_t w = read_word(pc);
    if ((w & 0xffe0001fU) != 0xd4200000U)
        return -1;
    return (w >> 5) & 0xffff;
}

/* Runs the child until it stops at a marker BRK for which accept() is true,
 * passing other markers and passing on its signals.  Leaves it at the BRK.
 */
static int at_marker = -1; /* the marker the child is stopped at, if any */

static int
run_to_marker(int want_start, int want_end, int v, int sig)
{
    for (;;) {
        if (at_marker >= 0) {
            set_pc(get_regs().pc + 4);
            at_marker = -1;
        }
        int stop = resume(PTRACE_CONT, sig);
        sig = 0;
        if (stop == SIGTRAP) {
            int m = brk_at(get_regs().pc);
            if (m < 0)
                tracer_fail("SIGTRAP not at a marker, pc %#llx\n",
                            (unsigned long long)get_regs().pc);
            at_marker = m;
            if ((want_start && m == MARK_START(v)) || (want_end && m == MARK_END(v)))
                return m;
            if (m >= MARK_START(0) && m < MARK_START(NUM_VARIANTS) && want_end)
                return m; /* the call did not reach its end (redirect, fault) */
            continue;
        }
        sig = stop; /* pass it on */
    }
}

enum { INJECT_SIGNAL, INJECT_SUSPEND };

static int
suspend_pending(void)
{
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/status", child, child);
    FILE *f = fopen(path, "r");
    int res = 0;
    if (f == NULL)
        tracer_fail("open %s\n", path);
    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long long mask;
        if (sscanf(line, "SigPnd: %llx", &mask) == 1 ||
            sscanf(line, "ShdPnd: %llx", &mask) == 1) {
            /* DR's suspend signal is a realtime one (or SIGSTKFLT under QEMU):
             * the app has nothing else pending in a sweep.
             */
            if (mask != 0)
                res = 1;
        }
    }
    fclose(f);
    return res;
}

/* One run of variant v: steps k instructions into the call, then injects there.
 * Returns false if the call ended before k steps (no injection).
 */
static bool
sweep_run(int v, int k, int kind)
{
    /* For a suspension, the client thread must be done with the previous one. */
    for (;;) {
        run_to_marker(1, 0, v, 0);
        if (kind == INJECT_SIGNAL || !shared->s_go)
            break;
    }
    set_pc(get_regs().pc + 4);
    at_marker = -1;
    uint64_t start_pc = get_regs().pc;
    int steps = 0;
    while (steps < k) {
        int stop = resume(PTRACE_SINGLESTEP, 0);
        uint64_t pc = get_regs().pc;
        if (stop != SIGTRAP)
            tracer_fail("%s: signal %d while stepping at %#llx\n", variant_names[v], stop,
                        (unsigned long long)pc);
        steps_total++;
        int m = brk_at(pc);
        if (m == MARK_END(v)) {
            at_marker = m;
            seq_len[v] = steps + 1;
            return false;
        }
        if (m >= 0)
            tracer_fail("%s: marker %#x while stepping\n", variant_names[v], m);
        if (pc == (uint64_t)callee_plain || pc == (uint64_t)callee_args ||
            pc == (uint64_t)callee_write || pc == (uint64_t)callee_redirect) {
            /* Step over the callee: break at its return address. */
            uint64_t ret = get_regs().regs[30];
            uint32_t orig = read_word(ret);
            write_word(ret, BRK_WORD(MARK_STEP));
            int sig = 0;
            for (;;) {
                stop = resume(PTRACE_CONT, sig);
                sig = 0;
                if (stop != SIGTRAP) {
                    sig = stop;
                    continue;
                }
                uint64_t at = get_regs().pc;
                if (at == ret)
                    break;
                int mm = brk_at(at);
                if (mm >= MARK_START(0) && mm < MARK_START(NUM_VARIANTS)) {
                    /* The callee redirected: the call ends here. */
                    write_word(ret, orig);
                    at_marker = mm;
                    seq_len[v] = steps + 1;
                    return false;
                }
                tracer_fail("%s: SIGTRAP at %#llx in the callee\n", variant_names[v],
                            (unsigned long long)at);
            }
            write_word(ret, orig);
        }
        steps++;
    }
    injections[kind]++;
    long done = shared->susp_done, bad = shared->mismatches;
    uint64_t inject_pc = get_regs().pc;
    uint32_t inject_word = read_word(inject_pc);
    int sig;
    if (kind == INJECT_SIGNAL)
        sig = SIGUSR1;
    else {
        shared->s_go = 1;
        int tries = 0;
        while (!suspend_pending()) {
            if (++tries > 20000)
                tracer_fail("%s: no suspend signal\n", variant_names[v]);
            usleep(100);
        }
        /* With a signal pending, the kernel stops for its delivery before
         * executing anything.  Delivering it from that stop keeps its siginfo,
         * by which DR knows it for its own.
         */
        sig = resume(PTRACE_SINGLESTEP, 0);
        if (sig == SIGTRAP)
            tracer_fail("%s: the suspend signal was not delivered\n", variant_names[v]);
    }
    /* Deliver the signal here, then run to the end of the call (or, if the call
     * does not get there, the next one's start), and for a suspension on until
     * the client thread is done with it.
     */
    char delivered[160] = "";
    for (;;) {
        int stop = resume(PTRACE_CONT, sig);
        sig = 0;
        if (stop != SIGTRAP) {
            /* Pass it on.  Where each signal arrives, relative to the call's start,
             * is for the report of a mismatch.
             */
            sig = stop;
            size_t len = strlen(delivered);
            snprintf(delivered + len, sizeof(delivered) - len, " %+lld",
                     (long long)(get_regs().pc - start_pc));
            continue;
        }
        at_marker = brk_at(get_regs().pc);
        if (at_marker < 0)
            tracer_fail("%s: SIGTRAP not at a marker\n", variant_names[v]);
        if (kind == INJECT_SIGNAL || shared->susp_done != done)
            break;
        set_pc(get_regs().pc + 4);
        at_marker = -1;
    }
    if (shared->mismatches != bad && first_bad[0] == '\0') {
        snprintf(first_bad, sizeof(first_bad),
                 "%s at instruction %d of the call (pc %#llx, %08x); later "
                 "signals at offsets from the call's start:%s",
                 kind == INJECT_SIGNAL ? "a signal" : "a suspension", k,
                 (unsigned long long)inject_pc, inject_word, delivered);
    }
    return true;
}

static int
sweep_parent(void)
{
    int status;
    if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status))
        tracer_fail("the child did not stop\n");
    ptrace(PTRACE_SETOPTIONS, child, 0, (void *)PTRACE_O_EXITKILL);
    for (int v = 0; v < NUM_VARIANTS; v++) {
        shared->sweep_variant = v;
        for (int k = 0;; k++) {
            if (k > 4000)
                tracer_fail("%s: the call never ends\n", variant_names[v]);
            if (!sweep_run(v, k, INJECT_SIGNAL))
                break;
            if (!sweep_run(v, k, INJECT_SUSPEND))
                break;
        }
    }
    shared->sweep_variant = -1;
    /* Let the child finish. */
    int sig = 0;
    for (;;) {
        if (at_marker >= 0) {
            set_pc(get_regs().pc + 4);
            at_marker = -1;
        }
        if (ptrace(PTRACE_CONT, child, 0, (void *)(long)sig) != 0)
            tracer_fail("PTRACE_CONT: %s\n", strerror(errno));
        if (waitpid(child, &status, __WALL) != child)
            tracer_fail("waitpid\n");
        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;
        sig = WSTOPSIG(status);
        if (sig == SIGTRAP) {
            at_marker = brk_at(get_regs().pc);
            sig = 0;
        }
    }
    long elsewhere = 0;
    for (int v = 0; v < NUM_VARIANTS; v++) {
        if (v != V_FAULT)
            elsewhere += shared->sig_elsewhere[v];
    }
    printf("sweep: call lengths in instructions:");
    for (int v = 0; v < NUM_VARIANTS; v++)
        printf(" %s %ld", variant_names[v], seq_len[v]);
    printf("\n");
    printf("sweep: steps %ld, runs %ld, signals injected %ld delivered %ld (at ool_after "
           "%ld, at ool_site %ld, elsewhere %ld + %ld in fault), suspensions injected "
           "%ld done %ld (translated at ool_after %ld, at ool_site %ld, elsewhere %ld)\n",
           steps_total, shared->runs, injections[INJECT_SIGNAL], shared->sig_delivered,
           shared->sig_at_after, shared->sig_at_site, elsewhere,
           shared->sig_elsewhere[V_FAULT], injections[INJECT_SUSPEND], shared->susp_done,
           shared->susp_at_after, shared->susp_at_site, shared->susp_elsewhere);
    if (WIFSIGNALED(status) || WEXITSTATUS(status) != 0) {
        printf("sweep: FAILED: the child %s %d; first mismatch: %s",
               WIFSIGNALED(status) ? "died of" : "exited with",
               WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status), shared->msg);
        if (first_bad[0] != '\0')
            printf("sweep: first mismatch after %s\n", first_bad);
        return 1;
    }
    if (shared->mismatches != 0) {
        printf("sweep: FAILED: %ld mismatches; first: %s", shared->mismatches,
               shared->msg);
        printf("sweep: first mismatch after %s\n", first_bad);
        return 1;
    }
    /* Every injected SIGUSR1 reaches the handler exactly once, and (but in the
     * fault variant, whose fault comes first) at ool_after.
     */
    if (shared->sig_delivered != injections[INJECT_SIGNAL] || elsewhere != 0 ||
        shared->sig_at_site != 0) {
        printf("sweep: FAILED: %ld signals injected, %ld delivered, %ld not at "
               "ool_after\n",
               injections[INJECT_SIGNAL], shared->sig_delivered,
               elsewhere + shared->sig_at_site);
        return 1;
    }
    if (shared->susp_done != injections[INJECT_SUSPEND]) {
        printf("sweep: FAILED: %ld suspensions injected, %ld done\n",
               injections[INJECT_SUSPEND], shared->susp_done);
        return 1;
    }
    printf("sweep: all properties hold\n");
    return 0;
}

int
main(int argc, const char *argv[])
{
    const char *mode = argc > 1 ? argv[1] : "basic";
    mode_store = argc > 2 && strcmp(argv[2], "store") == 0;
    shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED)
        return 1;
    memset(shared, 0, sizeof(*shared));
    if (strcmp(mode, "basic") == 0)
        return run_basic_or_stress(mode, 2000, 0);
    if (strcmp(mode, "stress") == 0) {
        mode_stress = 1;
        return run_basic_or_stress(mode, 5000, argc > 2 ? atof(argv[2]) : 0);
    }
    if (strcmp(mode, "sweep") == 0) {
        mode_sweep = 1;
        fflush(stdout);
        child = fork();
        if (child < 0)
            return 1;
        if (child == 0)
            _exit(sweep_child());
        return sweep_parent();
    }
    fprintf(stderr, "unknown mode %s\n", mode);
    return 1;
}

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

/* Properties of AArch64 clean calls and drreg, with the native CPU as the
 * oracle: random blocks from the a64_dr_prop generator (api/a64_dr_prop_gen.h)
 * run natively (single-stepped by ptrace for a per-instruction trace) and then
 * under static DR with an in-process client, in forked children per variant.
 * The application's final state, memory and every fault frame must equal the
 * native ones, and every value the instrumentation observes must equal the
 * one computed from the native trace.
 *
 * cleancall: before random instructions the client inserts clean calls to
 *   - an assembly callee that conforms to AAPCS64 but clobbers every
 *     caller-saved GPR (x0-x18), all of V0-V7 and V16-V31, the upper 64 bits
 *     of V8-V15 (it saves and restores d8-d15 and x19-x24, which it uses),
 *     NZCV and FPSR (division by zero, invalid), and changes FPCR only
 *     temporarily; it logs its 8 register and 4 stack arguments;
 *   - an assembly callee that touches only GPRs, inserted with
 *     DR_CLEANCALL_NOSAVE_FLAGS and NOSAVE_XMM(_NONPARAM/_NONRET);
 *   - leaf callees DR may analyze or inline (counter, sum of an argument, a
 *     flag-setting compare, an FPSR write, an exact FP add on V0-V2);
 *   - a non-leaf C callee (libc formatting, memcpy, a division by zero);
 *   - a DR_CLEANCALL_READS_APP_CONTEXT callee that logs dr_get_mcontext();
 *   - a pair of READS|WRITES callees: the first changes one GPR (any, the
 *     stolen register included), V register, NZCV or FPSR with
 *     dr_set_mcontext(), the second checks that the context is exactly the
 *     first one's plus that delta and restores it;
 *   with 0-12 arguments (stack-passed beyond 8) from immediates, SP and
 *   application GPRs (aliasing the parameter registers, x29, x30; not the
 *   stolen register, which in inserted code means DR's TLS base: see
 *   api/docs/bt.dox sec_reg_stolen), with or without
 *   DR_CLEANCALL_ALWAYS_OUT_OF_LINE and DR_CLEANCALL_INDIRECT.  Argument logs,
 *   leaf counters and contexts are compared with the native trace.  Variants:
 *   default, -disable_traces, and against a debug DR -opt_cleancall 0/2/3 and
 *   -steal_reg 27; "store" variants return DR_EMIT_STORE_TRANSLATIONS, so that
 *   DR translates from the info it stored rather than a rebuilt list.  A fixed
 *   window that writes TPIDR_EL0 (and restores it
 *   before returning to C) is instrumented with the callees that use neither
 *   the DR API nor libc TLS, plus one that checks whether the hardware
 *   TPIDR_EL0 it runs with is the thread pointer libc uses.
 * drreg: before random instructions the client opens long-lived drreg
 *   reservations (1-3 GPRs, optionally the arithmetic flags) that span up to
 *   6 application instructions (which may read and write those registers and
 *   the flags) and hold fixed tool values, and at random instructions reads
 *   up to 4 application registers with drreg_get_app_value() into another
 *   reserved register and logs them with the window registers' tool values
 *   (clobbering the flags in between while they are reserved); it also
 *   inserts the READS|WRITES clean-call pair and the clobbering callee (with
 *   DR_CLEANCALL_READS_APP_CONTEXT) inside windows.  Variants use different
 *   allocation strategies (drreg's choice, registers the instruction uses,
 *   random subsets, callee-saved registers, and -steal_reg 27): every one must
 *   give the native final state, memory and fault frames, and the trace's
 *   register values, and the tool values must survive every app instr and
 *   clean call in their window.  A fault frame may differ from native in a register or
 *   NZCV only if that value is dead there (drreg's documented i#3801
 *   limitation); the oracle for "dead" is independent of drreg and DR's IR:
 *   the parent reruns the block natively, overwriting that register (twice,
 *   with different values) in that fault's frame before it returns, and
 *   requires the final state, memory and later fault frames to be unchanged.
 *   Observations of a register that differed in a frame are not compared for
 *   the rest of that run (the app resumed with that value), and are counted.
 *   Each traced block also runs 30 more times while asynchronous signals
 *   arrive (an itimer, a POSIX timer or another thread's tgkill, by block), so
 *   that DR translates interrupted contexts inside instrumented fragments:
 *   every run must still give the native result, and every interrupted
 *   context in the block must be a state of the native trace at that pc (same
 *   GPRs, SP, NZCV; conservative variants).
 *   The progress variants insert only the pattern of an instruction-counting
 *   tool (Seedbox's progress client): a reserved register loads a budget from
 *   raw TLS, decrements and stores it, a TBZ skips a READS_APP_CONTEXT |
 *   MULTIPATH clean call (which calls dr_get_mcontext() and refills the
 *   budget), and drreg_get_app_value(reg, reg) precedes the unreserve.
 *   In the progress-redirect variants the callee, like Seedbox's, then sets
 *   the mcontext's pc to the charged instruction and calls
 *   dr_redirect_execution() instead of returning.
 *   The progress-writer variants insert the pattern only before an
 *   instruction DR replaces with meta instructions that write its destination
 *   (ADR, ADRP, a literal load), reserving that destination, as drreg picks LR
 *   before an elided BL in Go code: state restoration must see that the
 *   mangling wrote the app value after the tool's raw-TLS store of the
 *   register (-noreload: without drreg_get_app_value(); -nocall: without the
 *   clean call either).
 *   Mixing that pattern with the long-lived reservations above
 *   (A64CC_PROGRESS_MIXED=1) currently fails: drreg's stateless restores
 *   before a MULTIPATH call may be skipped by the tool's branch, which its
 *   state restoration cannot model (and on AArch64 the stateless flags
 *   restore even reserves, and may spill, a scratch register there).
 *   Non-conservative mode (drreg.h: the app is assumed not to rely on a dead
 *   register's value at a fault, while our handler resumes after the faulting
 *   instruction) runs on fault-free blocks and checks resumed behaviour
 *   (final state and memory) and the tool values: it does not compare app
 *   observations, which may legitimately see tool values in dead registers
 *   (or get DRREG_ERROR_NO_APP_VALUE, counted).
 *   The "nohwcc" variants (both modes) run under -no_hw_cache_consistency with
 *   the code installed in a writable page (RWX, then IC IVAU): DR replaces
 *   each IC IVAU and DSB with an exit to its dispatcher, and keeps a copy of
 *   the code of blocks from writable pages to translate from (-xl8_code_copy).
 *   The "sandbox" variants do the same under -sandbox_writable (cleancall's
 *   and drreg's sandbox-choice are known to fail, see below).
 *   The drreg "store" variants, which return DR_EMIT_STORE_TRANSLATIONS (or use
 *   -store_translations), are known to fail and run only when listed in
 *   -variants: without a list of the fragment's instrs, drreg's state
 *   restoration guesses from the cache code (i#4937), e.g. takes an app's
 *   or a clean call's MRS of NZCV for its own flags spill, or a tool value's
 *   spill for the app value's (see ext/drreg/drreg.dox sec_drreg_xl8).
 *
 * Known deviations, counted; A64_PROP_CLEANCALL_STRICT=1 makes them failures:
 * + static-tpidr (2026-10-14): under static DR there is no private loader, so
 *   DR does not mangle application writes to TPIDR_EL0 (mangle.c applies
 *   mangle_writes_thread_register() only with -private_loader): a clean-call
 *   callee in a window where the app changed TPIDR_EL0 runs with the app's
 *   thread pointer, and DR itself, which finds its TLS through it, crashes on
 *   any DR API call there (dr_get_current_drcontext()).
 * + fault-frame SSBS (kernel nondeterminism) and BTYPE (DR reports 0 at an
 *   indirect branch target), as in api.a64_dr_prop and api.a64_prop_bti.
 * Known failures, not run by default:
 * + cleancall "sandbox" and drreg "sandbox-choice" (-sandbox_writable,
 *   2026-10-14): a fault in a sandboxed block that writes the stolen register
 *   (e.g., LDAR into x28) can be translated to the next instruction, fault
 *   frames and app values differ, and DR crashes on some blocks.
 *
 * Counts of generated/accepted/executed/checked/suppressed/inconclusive
 * blocks are printed with floors; "all properties hold" is printed only if
 * every check and floor passed.  A64CC_DUMP=1 prints each instrumented block
 * after drreg (debugging).
 *
 * Usage: a64_prop_cleancall cleancall|drreg [-seed S] [-n N] [-variants a,b]
 *        [-v]
 */

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "../api/a64_prop_support.h"
#pragma GCC diagnostic pop

/***************************************************************************
 * Callees.  The log is a sequence of records, each starting with a marker
 * word that identifies its kind (and so its length).
 */
#define MK_CLOBBER 0xc1
#define MK_PRESERVE 0xc2
#define MK_NONLEAF 0xc3
#define MK_CTXR 0xc4
#define MK_CTXW 0xc5
#define MK_TP 0xc6
#define MK_HASH 0xd0 /* drreg values: marker in the top byte, pc index below */
#define HASH_WORDS 8
/* The tool value the client keeps in window register k. */
#define WINDOW_VAL(k) (0x7001ULL + (k) * 0x1111ULL)
#define CTX_WORDS 36 /* x0-x30, sp, nzcv, fpsr, fpcr, vhash */

uint64_t *a64cc_log_pos;
uint64_t a64cc_leaf_cnt, a64cc_leaf_sum, a64cc_leaf_flagcnt, a64cc_leaf_fpsrcnt,
    a64cc_leaf_fpx;

/* clang-format off */
__asm__(
    ".text\n"
    ".p2align 4\n"
    /* AAPCS64-conforming, clobbers all caller-saved state.  Frame: x29/x30,
     * x19-x24 and d8-d15 (128 bytes); stack arguments at x29 + 128.
     */
    ".global a64cc_clobber\n"
    ".type a64cc_clobber, %function\n"
    "a64cc_clobber:\n"
    "  stp x29, x30, [sp, #-128]!\n"
    "  mov x29, sp\n"
    "  stp x19, x20, [sp, #16]\n"
    "  stp x21, x22, [sp, #32]\n"
    "  stp x23, x24, [sp, #48]\n"
    "  stp d8, d9, [sp, #64]\n"
    "  stp d10, d11, [sp, #80]\n"
    "  stp d12, d13, [sp, #96]\n"
    "  stp d14, d15, [sp, #112]\n"
    "  adrp x9, a64cc_log_pos\n"
    "  add x9, x9, :lo12:a64cc_log_pos\n"
    "  ldr x10, [x9]\n"
    "  mov x11, #0xc1\n"
    "  str x11, [x10], #8\n"
    "  stp x0, x1, [x10], #16\n"
    "  stp x2, x3, [x10], #16\n"
    "  stp x4, x5, [x10], #16\n"
    "  stp x6, x7, [x10], #16\n"
    "  ldp x11, x12, [x29, #128]\n"
    "  stp x11, x12, [x10], #16\n"
    "  ldp x11, x12, [x29, #144]\n"
    "  stp x11, x12, [x10], #16\n"
    "  str x10, [x9]\n"
    /* Use the callee-saved registers. */
    "  mov x19, #0x1919\n"
    "  mov x20, #0x2020\n"
    "  mov x21, #0x2121\n"
    "  mov x22, #0x2222\n"
    "  mov x23, #0x2323\n"
    "  mov x24, #0x2424\n"
    "  fmov d8, x19\n"
    "  fmov d9, x20\n"
    "  fmov d10, x21\n"
    "  fmov d11, x22\n"
    "  fmov d12, x23\n"
    "  fmov d13, x24\n"
    "  fmov d14, x19\n"
    "  fmov d15, x20\n"
    /* FPSR: division by zero and an invalid operation, with FPCR changed
     * (round toward zero) only for the duration.
     */
    "  mrs x13, fpcr\n"
    "  orr x14, x13, #0xc00000\n"
    "  msr fpcr, x14\n"
    "  fmov d0, #1.0\n"
    "  movi d1, #0\n"
    "  fdiv d2, d0, d1\n"
    "  fneg d3, d0\n"
    "  fsqrt d4, d3\n"
    "  fadd d5, d0, d0\n"
    "  msr fpcr, x13\n"
    /* NZCV. */
    "  movz x15, #0x6000, lsl #16\n"
    "  msr nzcv, x15\n"
    /* Restore the callee-saved registers: ldp of D registers zeroes the
     * upper halves of V8-V15, which the caller does not own.
     */
    "  ldp x19, x20, [sp, #16]\n"
    "  ldp x21, x22, [sp, #32]\n"
    "  ldp x23, x24, [sp, #48]\n"
    "  ldp d8, d9, [sp, #64]\n"
    "  ldp d10, d11, [sp, #80]\n"
    "  ldp d12, d13, [sp, #96]\n"
    "  ldp d14, d15, [sp, #112]\n"
    /* The upper halves of V8-V15 explicitly too. */
    "  mov x0, #0x5a5a\n"
    "  mov v8.d[1], x0\n"
    "  mov v9.d[1], x0\n"
    "  mov v10.d[1], x0\n"
    "  mov v11.d[1], x0\n"
    "  mov v12.d[1], x0\n"
    "  mov v13.d[1], x0\n"
    "  mov v14.d[1], x0\n"
    "  mov v15.d[1], x0\n"
    /* Every caller-saved vector register. */
    "  movi v0.16b, #0xa0\n"
    "  movi v1.16b, #0xa1\n"
    "  movi v2.16b, #0xa2\n"
    "  movi v3.16b, #0xa3\n"
    "  movi v4.16b, #0xa4\n"
    "  movi v5.16b, #0xa5\n"
    "  movi v6.16b, #0xa6\n"
    "  movi v7.16b, #0xa7\n"
    "  movi v16.16b, #0xb0\n"
    "  movi v17.16b, #0xb1\n"
    "  movi v18.16b, #0xb2\n"
    "  movi v19.16b, #0xb3\n"
    "  movi v20.16b, #0xb4\n"
    "  movi v21.16b, #0xb5\n"
    "  movi v22.16b, #0xb6\n"
    "  movi v23.16b, #0xb7\n"
    "  movi v24.16b, #0xb8\n"
    "  movi v25.16b, #0xb9\n"
    "  movi v26.16b, #0xba\n"
    "  movi v27.16b, #0xbb\n"
    "  movi v28.16b, #0xbc\n"
    "  movi v29.16b, #0xbd\n"
    "  movi v30.16b, #0xbe\n"
    "  movi v31.16b, #0xbf\n"
    /* Every caller-saved GPR. */
    "  mov x0, #0x1000\n"
    "  mov x1, #0x1001\n"
    "  mov x2, #0x1002\n"
    "  mov x3, #0x1003\n"
    "  mov x4, #0x1004\n"
    "  mov x5, #0x1005\n"
    "  mov x6, #0x1006\n"
    "  mov x7, #0x1007\n"
    "  mov x8, #0x1008\n"
    "  mov x9, #0x1009\n"
    "  mov x10, #0x100a\n"
    "  mov x11, #0x100b\n"
    "  mov x12, #0x100c\n"
    "  mov x13, #0x100d\n"
    "  mov x14, #0x100e\n"
    "  mov x15, #0x100f\n"
    "  mov x16, #0x1010\n"
    "  mov x17, #0x1011\n"
    "  mov x18, #0x1012\n"
    "  ldp x29, x30, [sp], #128\n"
    "  ret\n"
    ".size a64cc_clobber, .-a64cc_clobber\n"

    /* Touches only caller-saved GPRs: no NZCV, FPSR or vector state. */
    ".p2align 4\n"
    ".global a64cc_preserve\n"
    ".type a64cc_preserve, %function\n"
    "a64cc_preserve:\n"
    "  adrp x9, a64cc_log_pos\n"
    "  add x9, x9, :lo12:a64cc_log_pos\n"
    "  ldr x10, [x9]\n"
    "  mov x11, #0xc2\n"
    "  str x11, [x10], #8\n"
    "  stp x0, x1, [x10], #16\n"
    "  stp x2, x3, [x10], #16\n"
    "  stp x4, x5, [x10], #16\n"
    "  stp x6, x7, [x10], #16\n"
    "  str x10, [x9]\n"
    "  mov x0, #0x2000\n"
    "  mov x1, #0x2001\n"
    "  mov x2, #0x2002\n"
    "  mov x3, #0x2003\n"
    "  mov x4, #0x2004\n"
    "  mov x5, #0x2005\n"
    "  mov x6, #0x2006\n"
    "  mov x7, #0x2007\n"
    "  mov x8, #0x2008\n"
    "  mov x12, #0x200c\n"
    "  mov x13, #0x200d\n"
    "  mov x14, #0x200e\n"
    "  mov x15, #0x200f\n"
    "  mov x16, #0x2010\n"
    "  mov x17, #0x2011\n"
    "  ret\n"
    ".size a64cc_preserve, .-a64cc_preserve\n"

    /* Leaf callees DR may analyze and inline. */
    ".p2align 4\n"
    ".global a64cc_leaf0\n"
    ".type a64cc_leaf0, %function\n"
    "a64cc_leaf0:\n"
    "  adrp x0, a64cc_leaf_cnt\n"
    "  ldr x1, [x0, :lo12:a64cc_leaf_cnt]\n"
    "  add x1, x1, #1\n"
    "  str x1, [x0, :lo12:a64cc_leaf_cnt]\n"
    "  ret\n"
    ".size a64cc_leaf0, .-a64cc_leaf0\n"
    ".p2align 4\n"
    ".global a64cc_leaf1\n"
    ".type a64cc_leaf1, %function\n"
    "a64cc_leaf1:\n"
    "  adrp x1, a64cc_leaf_sum\n"
    "  ldr x2, [x1, :lo12:a64cc_leaf_sum]\n"
    "  add x2, x2, x0\n"
    "  str x2, [x1, :lo12:a64cc_leaf_sum]\n"
    "  ret\n"
    ".size a64cc_leaf1, .-a64cc_leaf1\n"
    ".p2align 4\n"
    ".global a64cc_leaf_flags\n"
    ".type a64cc_leaf_flags, %function\n"
    "a64cc_leaf_flags:\n"
    "  cmp x0, #100\n"
    "  cset x1, hi\n"
    "  adrp x2, a64cc_leaf_flagcnt\n"
    "  ldr x3, [x2, :lo12:a64cc_leaf_flagcnt]\n"
    "  add x3, x3, x1\n"
    "  str x3, [x2, :lo12:a64cc_leaf_flagcnt]\n"
    "  ret\n"
    ".size a64cc_leaf_flags, .-a64cc_leaf_flags\n"
    ".p2align 4\n"
    ".global a64cc_leaf_fpsr\n"
    ".type a64cc_leaf_fpsr, %function\n"
    "a64cc_leaf_fpsr:\n"
    "  mrs x1, fpsr\n"
    "  orr x1, x1, #0x1f\n"
    "  msr fpsr, x1\n"
    "  adrp x2, a64cc_leaf_fpsrcnt\n"
    "  ldr x3, [x2, :lo12:a64cc_leaf_fpsrcnt]\n"
    "  add x3, x3, #1\n"
    "  str x3, [x2, :lo12:a64cc_leaf_fpsrcnt]\n"
    "  ret\n"
    ".size a64cc_leaf_fpsr, .-a64cc_leaf_fpsr\n"
    ".p2align 4\n"
    ".global a64cc_leaf_fp\n"
    ".type a64cc_leaf_fp, %function\n"
    "a64cc_leaf_fp:\n"
    "  and x0, x0, #0xfffff\n"
    "  and x1, x1, #0xfffff\n"
    "  scvtf d0, x0\n"
    "  scvtf d1, x1\n"
    "  fadd d2, d0, d1\n"
    "  movi d1, #0\n"
    "  fdiv d1, d0, d1\n"
    "  fcvtzs x2, d2\n"
    "  adrp x3, a64cc_leaf_fpx\n"
    "  ldr x4, [x3, :lo12:a64cc_leaf_fpx]\n"
    "  eor x4, x4, x2\n"
    "  str x4, [x3, :lo12:a64cc_leaf_fpx]\n"
    "  ret\n"
    ".size a64cc_leaf_fp, .-a64cc_leaf_fp\n"

    /* The TPIDR_EL0 window: x0 = a new thread pointer, x1 = 5 output words.
     * Restores TPIDR_EL0 before returning.
     */
    ".p2align 4\n"
    ".global a64cc_tpwin\n"
    ".type a64cc_tpwin, %function\n"
    "a64cc_tpwin:\n"
    "  mrs x9, tpidr_el0\n"
    "  msr tpidr_el0, x0\n"
    "  add x2, x0, #1\n"
    "  eor x3, x2, x0\n"
    "  mrs x10, tpidr_el0\n"
    "  add x4, x10, x3\n"
    "  msr tpidr_el0, x9\n"
    "  mrs x11, tpidr_el0\n"
    "  stp x2, x3, [x1]\n"
    "  stp x4, x10, [x1, #16]\n"
    "  str x11, [x1, #32]\n"
    "  ret\n"
    ".global a64cc_tpwin_end\n"
    "a64cc_tpwin_end:\n"
    ".size a64cc_tpwin, .-a64cc_tpwin\n");
/* clang-format on */

void
a64cc_clobber(void);
void
a64cc_preserve(void);
void
a64cc_leaf0(void);
void
a64cc_leaf1(void);
void
a64cc_leaf_flags(void);
void
a64cc_leaf_fpsr(void);
void
a64cc_leaf_fp(void);
void
a64cc_tpwin(uint64_t tp, uint64_t *out);
extern const char a64cc_tpwin_end[];

static char g_scratch[256];
static uint64_t g_nonleaf_cnt;

/* A non-leaf callee: libc, SIMD in memcpy, and an FPSR flag. */
static void
a64cc_nonleaf(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
              uint64_t a5, uint64_t a6, uint64_t a7)
{
    uint64_t *p = a64cc_log_pos;
    p[0] = MK_NONLEAF;
    p[1] = a0;
    p[2] = a1;
    p[3] = a2;
    p[4] = a3;
    p[5] = a4;
    p[6] = a5;
    p[7] = a6;
    p[8] = a7;
    a64cc_log_pos = p + 9;
    char buf[64];
    snprintf(buf, sizeof(buf), "%.3f %llx", (double)(a0 & 0xffff) / 7.0,
             (unsigned long long)a1);
    memcpy(g_scratch, buf, sizeof(buf));
    volatile double z = 0;
    volatile double r = 1.0 / z;
    (void)r;
    errno = 0;
    g_nonleaf_cnt++;
}

static uint64_t g_libc_tp;
static uint64_t g_tp_bad;

static uint64_t
read_tp(void)
{
    uint64_t tp;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
    return tp;
}

/* Checks that the hardware thread pointer is the one libc uses. */
static void
a64cc_tp_check(void)
{
    uint64_t ok = read_tp() == g_libc_tp;
    uint64_t *p = a64cc_log_pos;
    p[0] = MK_TP;
    p[1] = ok;
    a64cc_log_pos = p + 2;
    if (!ok)
        g_tp_bad++;
}

/***************************************************************************
 * Context callees.
 */
typedef struct {
    int dk; /* 0 GPR, 1 vector, 2 NZCV, 3 FPSR */
    int dreg;
    uint64_t dval;
} delta_t;

static dr_mcontext_t g_snap;
static delta_t g_cur_delta;
static long g_ctx_bad;

static uint64_t
mc_vhash(dr_mcontext_t *mc, int vres)
{
    __uint128_t v[32];
    for (int i = 0; i < 32; i++)
        memcpy(&v[i], &mc->simd[i], 16);
    return a64p_vhash(v, vres);
}

static int g_vres = -1;

static void
log_ctx(dr_mcontext_t *mc, int marker, int with_ok, uint64_t ok)
{
    uint64_t *p = a64cc_log_pos;
    *p++ = (uint64_t)marker;
    if (with_ok)
        *p++ = ok;
    for (int i = 0; i < 31; i++)
        *p++ = (&mc->r0)[i]; /* r0-r30 are consecutive */
    *p++ = mc->sp;
    *p++ = mc->nzcv & 0xf0000000ULL;
    *p++ = mc->fpsr;
    *p++ = mc->fpcr;
    *p++ = mc_vhash(mc, g_vres);
    a64cc_log_pos = p;
}

static void
a64cc_ctx_read(void)
{
    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    if (!dr_get_mcontext(dr_get_current_drcontext(), &mc))
        g_ctx_bad++;
    log_ctx(&mc, MK_CTXR, 0, 0);
}

static void
apply_delta(dr_mcontext_t *mc, const delta_t *d, int undo)
{
    switch (d->dk) {
    case 0:
        if (undo)
            (&mc->r0)[d->dreg] -= d->dval;
        else
            (&mc->r0)[d->dreg] += d->dval;
        break;
    case 1: *(uint64_t *)&mc->simd[d->dreg] ^= d->dval; break;
    case 2: mc->nzcv ^= d->dval; break;
    case 3: mc->fpsr ^= d->dval; break;
    }
}

static int
plan_delta(uint64_t code, delta_t *d);

/* The first of the pair: snapshot, change, set. */
static void
a64cc_ctx_write(uint64_t code)
{
    void *dc = dr_get_current_drcontext();
    g_snap.size = sizeof(g_snap);
    g_snap.flags = DR_MC_ALL;
    if (!dr_get_mcontext(dc, &g_snap))
        g_ctx_bad++;
    plan_delta(code, &g_cur_delta);
    dr_mcontext_t mc = g_snap;
    apply_delta(&mc, &g_cur_delta, 0);
    if (!dr_set_mcontext(dc, &mc))
        g_ctx_bad++;
}

static int
mc_equal(dr_mcontext_t *a, dr_mcontext_t *b)
{
    if (memcmp(&a->r0, &b->r0, 31 * sizeof(reg_t)) != 0 || a->sp != b->sp ||
        (a->nzcv & 0xf0000000ULL) != (b->nzcv & 0xf0000000ULL) || a->fpsr != b->fpsr ||
        a->fpcr != b->fpcr)
        return 0;
    for (int i = 0; i < 32; i++) {
        if (memcmp(&a->simd[i], &b->simd[i], 16) != 0)
            return 0;
    }
    return 1;
}

/* The second: the context must be the snapshot plus the delta, exactly. */
static void
a64cc_ctx_check(uint64_t code)
{
    void *dc = dr_get_current_drcontext();
    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    if (!dr_get_mcontext(dc, &mc))
        g_ctx_bad++;
    dr_mcontext_t want = g_snap;
    apply_delta(&want, &g_cur_delta, 0);
    uint64_t ok = mc_equal(&mc, &want);
    apply_delta(&mc, &g_cur_delta, 1);
    log_ctx(&mc, MK_CTXW, 1, ok);
    if (!dr_set_mcontext(dc, &mc))
        g_ctx_bad++;
    (void)code;
}

/***************************************************************************
 * The plan: what the client inserts before the instruction at a pc,
 * deterministic in (seed, pc) so that the checker can recompute it.
 */
enum {
    K_CLOBBER,
    K_PRESERVE,
    K_LEAF0,
    K_LEAF1,
    K_LEAFFLAGS,
    K_LEAFFPSR,
    K_LEAFFP,
    K_NONLEAF,
    K_CTXR,
    K_CTXW,
    K_TP,
    NUM_K
};
static const char *const kind_name[] = { "clobber",   "preserve", "leaf0",  "leaf1",
                                         "leafflags", "leaffpsr", "leaffp", "nonleaf",
                                         "ctxread",   "ctxwrite", "tpcheck" };

#define MAXARGS 12
typedef struct {
    int kind, nargs;
    int src[MAXARGS]; /* -1 immediate, else a GPR number */
    uint64_t imm[MAXARGS];
    uint flags;
    uint64_t code; /* for the context pair: identifies the delta */
} site_t;

static uint64_t g_plan_seed;
static int g_progress_only; /* A64CC_PROGRESS_ONLY: debugging */
static int g_store;         /* return DR_EMIT_STORE_TRANSLATIONS for every block */
static int g_mode; /* 0 cleancall, 1 drreg */
static int g_alloc, g_cons;

static uint64_t
pc_rng_seed(uint64_t pc, uint64_t salt)
{
    return g_plan_seed ^ (pc * 0x9e3779b97f4a7c15ULL) ^ (salt * 0xbf58476d1ce4e5b9ULL);
}

static int
plan_delta(uint64_t code, delta_t *d)
{
    rng_t r = { code };
    d->dk = (int)rn(&r, 4);
    d->dreg = d->dk == 0 ? (int)rn(&r, 31) : (int)rn(&r, 32);
    switch (d->dk) {
    case 0: d->dval = rnext(&r) | 1; break;
    case 1: d->dval = rnext(&r) | 1; break;
    case 2: d->dval = (1ULL + rn(&r, 15)) << 28; break;
    case 3: d->dval = 1ULL << rn(&r, 5); break; /* a cumulative flag */
    }
    return 1;
}

static void
plan_args(rng_t *r, site_t *s, int nargs)
{
    /* Not the stolen register: in inserted code it holds DR's TLS base, and a
     * client must use dr_insert_get_stolen_reg_value() for the app's value
     * (api/docs/bt.dox, sec_reg_stolen).  31 is SP, whose application value
     * DR passes.
     */
    static const int interesting[] = { 0, 1, 2,  3,  4,  5,  6,  7,
                                       8, 9, 16, 17, 18, 29, 30, 31 };
    s->nargs = nargs;
    for (int i = 0; i < nargs; i++) {
        if (rp(r, 30)) {
            s->src[i] = -1;
            s->imm[i] = rval(r);
        } else if (rp(r, 70)) {
            s->src[i] = interesting[rn(r, sizeof(interesting) / sizeof(interesting[0]))];
        } else {
            s->src[i] = (int)rn(r, 32);
            if (s->src[i] == (int)(dr_get_stolen_reg() - DR_REG_X0))
                s->src[i] = 31;
        }
    }
}

/* Inside the TPIDR_EL0 window under static DR only callees that use neither
 * DR's TLS (the DR API) nor libc's (errno) are inserted: see the
 * static-tpidr deviation.
 */
static int
tpwin_kind_ok(int kind)
{
    return kind != K_CTXR && kind != K_CTXW && kind != K_NONLEAF;
}

/* Clean-call sites before the instruction at pc (cleancall mode); returns
 * their number.
 */
static int
plan_sites(uint64_t pc, int in_tpwin, site_t *s)
{
    rng_t r = { pc_rng_seed(pc, 1) };
    int n = in_tpwin ? 1 + (int)rn(&r, 2) : (rp(&r, 55) ? 0 : (rp(&r, 75) ? 1 : 2));
    for (int i = 0; i < n; i++) {
        site_t *t = &s[i];
        memset(t, 0, sizeof(*t));
        t->kind = (int)rn(&r, in_tpwin ? NUM_K : NUM_K - 1);
        if (in_tpwin && !tpwin_kind_ok(t->kind))
            t->kind = K_TP;
        switch (t->kind) {
        case K_CLOBBER: plan_args(&r, t, (int)rn(&r, MAXARGS + 1)); break;
        case K_PRESERVE:
            plan_args(&r, t, (int)rn(&r, 9));
            if (rp(&r, 70)) {
                static const uint nosave[] = {
                    DR_CLEANCALL_NOSAVE_FLAGS,
                    DR_CLEANCALL_NOSAVE_XMM,
                    DR_CLEANCALL_NOSAVE_FLAGS | DR_CLEANCALL_NOSAVE_XMM,
                    DR_CLEANCALL_NOSAVE_XMM_NONPARAM,
                    DR_CLEANCALL_NOSAVE_XMM_NONRET | DR_CLEANCALL_NOSAVE_FLAGS,
                };
                t->flags |= nosave[rn(&r, sizeof(nosave) / sizeof(nosave[0]))];
            }
            break;
        case K_LEAF0: break;
        case K_LEAF1:
        case K_LEAFFLAGS: plan_args(&r, t, 1); break;
        case K_LEAFFPSR: break;
        case K_LEAFFP: plan_args(&r, t, 2); break;
        case K_NONLEAF: plan_args(&r, t, (int)rn(&r, 9)); break;
        case K_CTXR: t->flags |= DR_CLEANCALL_READS_APP_CONTEXT; break;
        case K_CTXW:
            t->flags |= DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT;
            t->code = rnext(&r);
            break;
        case K_TP: break;
        }
        if (t->kind != K_CTXW && t->kind != K_CTXR) {
            if (rp(&r, 25))
                t->flags |= DR_CLEANCALL_ALWAYS_OUT_OF_LINE;
            if (rp(&r, 25))
                t->flags |= DR_CLEANCALL_INDIRECT;
        }
    }
    return n;
}

/* drreg mode plan. */
typedef struct {
    int start, nres, aflags, len;
    int log;
    int nhash;
    int hreg[4], hrot[4];
    uint64_t hconst;
    int ctxw;
    int progress, charge; /* a budget charge with a MULTIPATH clean call */
    uint64_t ctx_code;
    int clobber;
    site_t cl;
} dplan_t;

static void
plan_drreg(uint64_t pc, dplan_t *p)
{
    rng_t r = { pc_rng_seed(pc, 2) };
    memset(p, 0, sizeof(*p));
    p->start = rp(&r, 30);
    p->nres = 1 + (int)rn(&r, 3);
    p->aflags = rp(&r, 50);
    p->len = 1 + (int)rn(&r, 6);
    p->log = rp(&r, 45);
    p->nhash = 1 + (int)rn(&r, 4);
    for (int i = 0; i < p->nhash; i++) {
        p->hreg[i] = (int)rn(&r, 31);
        p->hrot[i] = 1 + (int)rn(&r, 63);
    }
    p->hconst = rnext(&r) & 0xffff;
    p->ctxw = rp(&r, 8);
    p->ctx_code = rnext(&r);
    p->clobber = rp(&r, 8);
    if (p->clobber) {
        memset(&p->cl, 0, sizeof(p->cl));
        p->cl.kind = K_CLOBBER;
        plan_args(&r, &p->cl, (int)rn(&r, MAXARGS + 1));
        p->cl.flags = DR_CLEANCALL_READS_APP_CONTEXT;
    }
    if (g_progress_only) {
        /* Only the budget pattern, as the Seedbox progress client inserts it. */
        p->start = p->log = p->ctxw = p->clobber = 0;
    }
    rng_t r2 = { pc_rng_seed(pc, 9) };
    p->progress = g_progress_only ? 1 : rp(&r2, 35);
    p->charge = 1 + (int)rn(&r2, 3);
}

/***************************************************************************
 * The client.
 */
static a64p_worker_t g_w;
static int g_client_on;
static uint64_t g_tp_lo, g_tp_hi;
static long g_api_fail;
static long g_no_app_value;
static int g_progress_on;

static void
insert_site(void *dc, instrlist_t *bb, instr_t *inst, site_t *s)
{
    opnd_t args[MAXARGS];
    for (int i = 0; i < s->nargs; i++) {
        args[i] = s->src[i] < 0
            ? OPND_CREATE_INT64(s->imm[i])
            : opnd_create_reg(s->src[i] == 31 ? DR_REG_SP : DR_REG_X0 + s->src[i]);
    }
    void *callee = NULL;
    switch (s->kind) {
    case K_CLOBBER: callee = (void *)a64cc_clobber; break;
    case K_PRESERVE: callee = (void *)a64cc_preserve; break;
    case K_LEAF0: callee = (void *)a64cc_leaf0; break;
    case K_LEAF1: callee = (void *)a64cc_leaf1; break;
    case K_LEAFFLAGS: callee = (void *)a64cc_leaf_flags; break;
    case K_LEAFFPSR: callee = (void *)a64cc_leaf_fpsr; break;
    case K_LEAFFP: callee = (void *)a64cc_leaf_fp; break;
    case K_NONLEAF: callee = (void *)a64cc_nonleaf; break;
    case K_CTXR: callee = (void *)a64cc_ctx_read; break;
    case K_TP: callee = (void *)a64cc_tp_check; break;
    case K_CTXW: {
        opnd_t code = OPND_CREATE_INT64(s->code);
        dr_insert_clean_call_ex_varg(dc, bb, inst, (void *)a64cc_ctx_write,
                                     (dr_cleancall_save_t)s->flags, 1, &code);
        dr_insert_clean_call_ex_varg(dc, bb, inst, (void *)a64cc_ctx_check,
                                     (dr_cleancall_save_t)s->flags, 1, &code);
        return;
    }
    }
    dr_insert_clean_call_ex_varg(dc, bb, inst, callee, (dr_cleancall_save_t)s->flags,
                                 s->nargs, args);
}

/* The budget pattern of an instruction-counting tool (e.g. Seedbox's progress
 * client): a reserved register loads a budget from raw TLS, is decremented
 * and stored back, a TBZ skips a READS_APP_CONTEXT | MULTIPATH clean call
 * while the budget is not negative, and the register gets its app value back
 * with drreg_get_app_value(reg, reg) before it is unreserved.
 */
static reg_id_t g_budget_seg;
static uint g_budget_offs;
#define BUDGET_REFILL 7
#define SIG_RUNS 20
static long g_progress_calls, g_progress_bad;
static int g_progress_redirect; /* the callee redirects to the charged instruction */
static int g_progress_noreload; /* no drreg_get_app_value() before the unreserve */
static int g_progress_nocall;   /* no clean call (and no reload) */

static void
set_budget(void *dc, ptr_int_t v)
{
    *(ptr_int_t *)(dr_get_dr_segment_base(g_budget_seg) + g_budget_offs) = v;
}

static void
a64cc_progress(uint64_t pc, uint64_t charge)
{
    void *dc = dr_get_current_drcontext();
    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    if (!dr_get_mcontext(dc, &mc))
        g_progress_bad++;
    g_progress_calls++;
    set_budget(dc, BUDGET_REFILL);
    (void)charge;
    if (g_progress_redirect) {
        /* As Seedbox's checkpoint_and_dispatch() does: the whole app state
         * comes from dr_get_mcontext(), and execution resumes at the charged
         * instruction (which is charged again) instead of returning.
         */
        mc.pc = (app_pc)(uintptr_t)pc;
        dr_redirect_execution(&mc);
        g_progress_bad++; /* not reached */
    }
}

static int
reserve(void *dc, instrlist_t *bb, instr_t *inst, rng_t *r, reg_id_t *out);
static void
unreserve(void *dc, instrlist_t *bb, instr_t *inst, reg_id_t reg);

static void
insert_progress(void *dc, instrlist_t *bb, instr_t *inst, dplan_t *p, rng_t *r)
{
    reg_id_t scratch;
    instr_t *skip = INSTR_CREATE_label(dc);
    if (!reserve(dc, bb, inst, r, &scratch))
        return;
    dr_insert_read_raw_tls(dc, bb, inst, g_budget_seg, g_budget_offs, scratch);
    instrlist_meta_preinsert(bb, inst,
                             INSTR_CREATE_sub(dc, opnd_create_reg(scratch),
                                              opnd_create_reg(scratch),
                                              OPND_CREATE_INT(p->charge)));
    dr_insert_write_raw_tls(dc, bb, inst, g_budget_seg, g_budget_offs, scratch);
    instrlist_meta_preinsert(bb, inst,
                             INSTR_CREATE_tbz(dc, opnd_create_instr(skip),
                                              opnd_create_reg(scratch),
                                              OPND_CREATE_INT(63)));
    if (g_progress_nocall) {
        /* Refill inline instead (the budget only steers the branch). */
        instrlist_insert_mov_immed_ptrsz(dc, BUDGET_REFILL, opnd_create_reg(scratch), bb,
                                         inst, NULL, NULL);
        dr_insert_write_raw_tls(dc, bb, inst, g_budget_seg, g_budget_offs, scratch);
    } else {
        dr_insert_clean_call_ex(dc, bb, inst, (void *)a64cc_progress,
                                DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_MULTIPATH,
                                2, OPND_CREATE_INTPTR((ptr_int_t)instr_get_app_pc(inst)),
                                OPND_CREATE_INTPTR((ptr_int_t)p->charge));
    }
    instrlist_meta_preinsert(bb, inst, skip);
    if (!g_progress_noreload) {
        drreg_status_t res = drreg_get_app_value(dc, bb, inst, scratch, scratch);
        if (res == DRREG_ERROR_NO_APP_VALUE && !g_cons)
            g_no_app_value++; /* a dead register in non-conservative mode */
        else if (res != DRREG_SUCCESS)
            g_api_fail++;
    }
    unreserve(dc, bb, inst, scratch);
}

/* Per-bb drreg window state. */
typedef struct {
    int active, left, nres, aflags;
    reg_id_t res[3];
} window_t;

/* The GPR inst writes if DR replaces it with meta instructions that do. */
static reg_id_t
mangled_dst(instr_t *inst)
{
    int op = instr_get_opcode(inst);
    if (op == OP_bl)
        return DR_REG_X30;
    if (instr_num_dsts(inst) < 1 || !opnd_is_reg(instr_get_dst(inst, 0)))
        return DR_REG_NULL;
    reg_id_t dst = reg_to_pointer_sized(opnd_get_reg(instr_get_dst(inst, 0)));
    if (dst < DR_REG_X0 || dst > DR_REG_X30 || dst == dr_get_stolen_reg())
        return DR_REG_NULL;
    if (op == OP_adr || op == OP_adrp)
        return dst;
    for (int i = 0; i < instr_num_srcs(inst); i++) {
        if (opnd_is_rel_addr(instr_get_src(inst, i)))
            return dst;
    }
    return DR_REG_NULL;
}

static void
fill_allowed(void *dc, drvector_t *allowed, instr_t *inst, rng_t *r)
{
    drreg_init_and_fill_vector(allowed, false);
    switch (g_alloc) {
    case 1:
        /* Registers the instruction uses, plus a few. */
        for (int i = 0; i < 31; i++) {
            if (instr_uses_reg(inst, DR_REG_X0 + i) || i < 3)
                drreg_set_vector_entry(allowed, DR_REG_X0 + i, true);
        }
        break;
    case 2:
        for (int i = 0; i < 31; i++) {
            if (rp(r, 30))
                drreg_set_vector_entry(allowed, DR_REG_X0 + i, true);
        }
        break;
    case 3:
        for (int i = 19; i < 31; i++)
            drreg_set_vector_entry(allowed, DR_REG_X0 + i, true);
        break;
    case 4: {
        /* The register an instruction that DR mangles into meta instructions
         * writes (ADR, ADRP, BL, literal loads), so that the mangling, not an
         * app instruction, writes the app value after the tool's use.
         */
        reg_id_t dst = mangled_dst(inst);
        for (int i = 0; i < 31; i++) {
            if (dst == DR_REG_NULL ? i < 3 : DR_REG_X0 + i == dst)
                drreg_set_vector_entry(allowed, DR_REG_X0 + i, true);
        }
        break;
    }
    }
    drreg_set_vector_entry(allowed, dr_get_stolen_reg(), false);
}

static int
reserve(void *dc, instrlist_t *bb, instr_t *inst, rng_t *r, reg_id_t *out)
{
    drreg_status_t res;
    if (g_alloc == 0)
        res = drreg_reserve_register(dc, bb, inst, NULL, out);
    else {
        drvector_t allowed;
        fill_allowed(dc, &allowed, inst, r);
        res = drreg_reserve_register(dc, bb, inst, &allowed, out);
        drvector_delete(&allowed);
        if (res != DRREG_SUCCESS)
            res = drreg_reserve_register(dc, bb, inst, NULL, out);
    }
    if (res != DRREG_SUCCESS) {
        g_api_fail++;
        return 0;
    }
    return 1;
}

static void
unreserve(void *dc, instrlist_t *bb, instr_t *inst, reg_id_t reg)
{
    if (drreg_unreserve_register(dc, bb, inst, reg) != DRREG_SUCCESS)
        g_api_fail++;
}

static void
close_window(void *dc, instrlist_t *bb, instr_t *inst, window_t *w)
{
    for (int i = 0; i < w->nres; i++)
        unreserve(dc, bb, inst, w->res[i]);
    if (w->aflags && drreg_unreserve_aflags(dc, bb, inst) != DRREG_SUCCESS)
        g_api_fail++;
    memset(w, 0, sizeof(*w));
}

static void
insert_hash(void *dc, instrlist_t *bb, instr_t *inst, dplan_t *p, window_t *w,
            uint64_t pc, rng_t *r)
{
    /* Three temporaries of our own: the window's registers keep their tool
     * values, which the record includes.
     */
    reg_id_t t[3];
    int own[3] = { 0, 0, 0 };
    for (int i = 0; i < 3; i++) {
        if (!reserve(dc, bb, inst, r, &t[i])) {
            for (int j = 0; j < i; j++)
                unreserve(dc, bb, inst, t[j]);
            return;
        }
        own[i] = 1;
    }
    /* Record [marker, app value of each hashed register, tool value of each
     * window register] at *log_pos:
     *   ad = &a64cc_log_pos; pr = *ad;
     *   for each: val = app value (drreg_get_app_value); pr[1 + j] = val;
     *   for each window register: pr[5 + k] = it;
     *   pr[0] = marker (with the window size); *ad = pr + 8 * HASH_WORDS
     */
    reg_id_t val = t[0], pr = t[1], ad = t[2];
    instrlist_insert_mov_immed_ptrsz(dc, (ptr_int_t)&a64cc_log_pos, opnd_create_reg(ad),
                                     bb, inst, NULL, NULL);
    instrlist_meta_preinsert(
        bb, inst, INSTR_CREATE_ldr(dc, opnd_create_reg(pr), OPND_CREATE_MEMPTR(ad, 0)));
    for (int j = 0; j < p->nhash; j++) {
        reg_id_t app = DR_REG_X0 + p->hreg[j];
        drreg_status_t res = drreg_get_app_value(dc, bb, inst, app, val);
        if (res == DRREG_ERROR_NO_APP_VALUE && !g_cons) {
            /* Permitted for a dead register in non-conservative mode. */
            g_no_app_value++;
            continue;
        }
        if (res != DRREG_SUCCESS) {
            g_api_fail++;
            continue;
        }
        instrlist_meta_preinsert(bb, inst,
                                 INSTR_CREATE_str(dc, OPND_CREATE_MEMPTR(pr, 8 * (1 + j)),
                                                  opnd_create_reg(val)));
        if (w->aflags) {
            /* Clobber the flags while they are reserved. */
            instrlist_meta_preinsert(
                bb, inst, INSTR_CREATE_cmp(dc, opnd_create_reg(val), OPND_CREATE_INT(7)));
        }
    }
    for (int k = 0; k < w->nres; k++) {
        instrlist_meta_preinsert(bb, inst,
                                 INSTR_CREATE_str(dc, OPND_CREATE_MEMPTR(pr, 8 * (5 + k)),
                                                  opnd_create_reg(w->res[k])));
    }
    instrlist_insert_mov_immed_ptrsz(dc,
                                     (ptr_int_t)(((uint64_t)MK_HASH << 56) |
                                                 ((uint64_t)w->nres << 48) |
                                                 ((pc - CODE_BASE) / 4)),
                                     opnd_create_reg(val), bb, inst, NULL, NULL);
    instrlist_meta_preinsert(
        bb, inst, INSTR_CREATE_str(dc, OPND_CREATE_MEMPTR(pr, 0), opnd_create_reg(val)));
    instrlist_meta_preinsert(
        bb, inst,
        XINST_CREATE_add(dc, opnd_create_reg(pr), OPND_CREATE_INT16(8 * HASH_WORDS)));
    instrlist_meta_preinsert(
        bb, inst, INSTR_CREATE_str(dc, OPND_CREATE_MEMPTR(ad, 0), opnd_create_reg(pr)));
    for (int i = 0; i < 3; i++) {
        if (own[i])
            unreserve(dc, bb, inst, t[i]);
    }
}

static int
pc_instrumented(uint64_t pc, int *in_tpwin)
{
    *in_tpwin = pc >= g_tp_lo && pc < g_tp_hi;
    return *in_tpwin || (pc >= g_w.blk_lo && pc <= g_w.blk_hi);
}

static dr_emit_flags_t
event_analysis(void *dc, void *tag, instrlist_t *bb, bool for_trace, bool translating,
               void **user_data)
{
    window_t *w = dr_thread_alloc(dc, sizeof(*w));
    memset(w, 0, sizeof(*w));
    *user_data = w;
    return g_store ? DR_EMIT_STORE_TRANSLATIONS : DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_insert(void *dc, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace,
             bool translating, void *user_data)
{
    window_t *w = (window_t *)user_data;
    int last = drmgr_is_last_instr(dc, inst);
    int in_tpwin;
    if (!instr_is_app(inst)) {
        if (last && w->active)
            close_window(dc, bb, inst, w);
        goto done;
    }
    uint64_t pc = (uint64_t)(uintptr_t)instr_get_app_pc(inst);
    if (!pc_instrumented(pc, &in_tpwin)) {
        if (w->active)
            close_window(dc, bb, inst, w);
        goto done;
    }
    if (g_mode == 0) {
        site_t s[2];
        int n = plan_sites(pc, in_tpwin, s);
        for (int i = 0; i < n; i++)
            insert_site(dc, bb, inst, &s[i]);
        goto done;
    }
    /* drreg. */
    dplan_t p;
    plan_drreg(pc, &p);
    rng_t r = { pc_rng_seed(pc, 3 + (uint64_t)g_alloc) };
    if (w->active && w->left <= 0)
        close_window(dc, bb, inst, w);
    /* Only outside windows: a MULTIPATH clean call may clobber tool values. */
    if (!w->active && p.progress && g_progress_on &&
        /* Only before such instructions, so that no later charge reuses the
         * slot (which would end the stale app value's life in the walk).
         */
        (g_alloc != 4 || mangled_dst(inst) != DR_REG_NULL))
        insert_progress(dc, bb, inst, &p, &r);
    if (!w->active && p.start) {
        w->active = 1;
        w->left = p.len;
        for (int i = 0; i < p.nres; i++) {
            if (reserve(dc, bb, inst, &r, &w->res[w->nres]))
                w->nres++;
        }
        if (p.aflags) {
            if (drreg_reserve_aflags(dc, bb, inst) == DRREG_SUCCESS)
                w->aflags = 1;
            else
                g_api_fail++;
        }
        /* Give the reserved registers tool values. */
        for (int i = 0; i < w->nres; i++) {
            instrlist_insert_mov_immed_ptrsz(dc, (ptr_int_t)WINDOW_VAL(i),
                                             opnd_create_reg(w->res[i]), bb, inst, NULL,
                                             NULL);
        }
        if (w->aflags) {
            instrlist_meta_preinsert(
                bb, inst,
                INSTR_CREATE_cmp(dc, opnd_create_reg(DR_REG_X0), OPND_CREATE_INT(1)));
        }
    }
    if (p.log)
        insert_hash(dc, bb, inst, &p, w, pc, &r);
    if (p.clobber)
        insert_site(dc, bb, inst, &p.cl);
    if (p.ctxw) {
        site_t s;
        memset(&s, 0, sizeof(s));
        s.kind = K_CTXW;
        s.code = p.ctx_code;
        s.flags = DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT;
        insert_site(dc, bb, inst, &s);
    }
    if (w->active) {
        w->left--;
        if (last)
            close_window(dc, bb, inst, w);
    }
done:
    if (last)
        dr_thread_free(dc, w, sizeof(*w));
    return DR_EMIT_DEFAULT;
}

static void
event_thread_init(void *dc)
{
    set_budget(dc, BUDGET_REFILL);
}

/* With A64CC_DUMP set, prints each instrumented block after drreg (debugging). */
static dr_emit_flags_t
event_dump(void *dc, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    uint64_t pc = (uint64_t)(uintptr_t)dr_fragment_app_pc(tag);
    int in_tpwin;
    if (!translating && pc_instrumented(pc, &in_tpwin)) {
        dr_fprintf(STDERR, "=== bb 0x%llx%s\n", (unsigned long long)pc,
                   for_trace ? " (trace)" : "");
        instrlist_disassemble(dc, (app_pc)tag, bb, STDERR);
    }
    return DR_EMIT_DEFAULT;
}

static void
client_exit(void)
{
    if (g_mode == 1)
        drreg_exit();
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    if (!g_client_on)
        return;
    /* dr_merge_arith_flags() takes only the flags from the saved value: drreg's
     * state restoration without an ilist can misidentify a slot, and PSTATE bits
     * outside NZCV (e.g., DAIF) made the kernel reject the context we returned to.
     */
    for (int i = 0; i < 64; i++) {
        reg_t cur = 0x60001000ULL, junk = 1ULL << i | 0x31000001c0ULL;
        DR_ASSERT((dr_merge_arith_flags(cur, junk) & ~(reg_t)EFLAGS_ARITH) ==
                  (cur & ~(reg_t)EFLAGS_ARITH));
    }
    if (!drmgr_init())
        DR_ASSERT(false);
    if (g_mode == 1) {
        /* As drreg.h asks: one slot per simultaneously reserved register (3
         * window + 3 temporaries), one for the flags, and one more per value
         * held across app instrs (3 window registers and the flags): DR's own
         * slots, which drreg falls back to, do not survive app instrs.
         */
        drreg_options_t ops = { sizeof(ops), 12, g_cons != 0 };
        if (drreg_init(&ops) != DRREG_SUCCESS)
            DR_ASSERT(false);
        if (!dr_raw_tls_calloc(&g_budget_seg, &g_budget_offs, 1, 0))
            DR_ASSERT(false);
        drmgr_register_thread_init_event(event_thread_init);
    }
    drmgr_register_bb_instrumentation_event(event_analysis, event_insert, NULL);
    if (getenv("A64CC_DUMP") != NULL) {
        drmgr_priority_t pri = { sizeof(pri), "a64cc_dump", NULL, NULL, 10000 };
        drmgr_register_bb_instru2instru_event(event_dump, &pri);
    }
    dr_register_exit_event(client_exit);
}

/***************************************************************************
 * The checker: the expected log and counters from the native trace.
 */
typedef struct {
    uint64_t cnt, sum, flagcnt, fpsrcnt, fpx;
} leafexp_t;

static uint64_t *g_log_base;
#define MAXLOG (4u << 20)
static int g_strict;
/* Registers (x0-x30 in bits 0-30, NZCV in bit 31) whose value in some fault
 * frame of the run differed from native (left to the liveness oracle): once
 * the handler resumes with that frame, the app's own value of that register
 * differs too until the app overwrites it, so observations of it are not
 * compared (and counted).
 */
static uint32_t g_taint;
/* Whether instrumentation observations of app registers are compared: not in
 * drreg's non-conservative mode, where a dead register's app value is not
 * kept (drreg.h) and only resumed behaviour (final state, memory and fault
 * frames, with the liveness oracle) is checked.
 */
static int g_observe = 1;

static uint64_t
arg_value(site_t *s, int i, tstep_t *st)
{
    return s->src[i] < 0 ? s->imm[i] : (s->src[i] == 31 ? st->sp : st->x[s->src[i]]);
}

enum {
    ST_BLOCKS_CHECKED,
    ST_RUNS,
    ST_RECORDS,                   /* log records compared with the trace */
    ST_CTX,                       /* context records */
    ST_LEAF,                      /* leaf calls counted */
    ST_TPWIN,                     /* TPIDR windows compared */
    ST_HASHES,                    /* drreg hashes compared */
    ST_UNTRACED,                  /* blocks checked without a trace */
    ST_KIND0,                     /* per kind: sites executed (NUM_K) */
    ST_DEAD_Q = ST_KIND0 + NUM_K, /* fault-frame differences sent to the oracle */
    ST_KD_TPIDR,       /* callees that ran with the app's TPIDR_EL0 (static-tpidr) */
    ST_TP_OK,          /* ...that ran with libc's */
    ST_KD_SSBS,        /* fault frames differing in SSBS (kernel nondeterminism) */
    ST_KD_BTYPE,       /* ...reporting BTYPE 0 where native has the branch's */
    ST_BAD_PSTATE,     /* masked PSTATE differences that are neither */
    ST_TAINTED,        /* observations skipped: register differed in a fault frame */
    ST_NO_APP_VALUE,   /* non-conservative DRREG_ERROR_NO_APP_VALUE results */
    ST_ASYNC_CHECKED,  /* interrupted contexts checked against the trace */
    ST_PROGRESS_CALLS, /* MULTIPATH budget clean calls taken */
    ST_NUM
};
_Static_assert(ST_NUM <= A64P_NSTAT, "progress_t.stat is too small");

static void
stat_add(int i, long v)
{
    a64p_prog->stat[i] += v;
}

#define PSTATE_SSBS (1ULL << 12)
#define PSTATE_BTYPE (3ULL << 10)

/* The two PSTATE differences a64_dr_prop knows (fault-ssbs, fault-btype):
 * counted, and the BTYPE one only in the direction DR is known to differ.
 */
static void
on_masked_pstate(int i, fault_rec_t *n, fault_rec_t *d)
{
    uint64_t diff = n->pstate ^ d->pstate;
    if (diff & PSTATE_SSBS)
        stat_add(ST_KD_SSBS, 1);
    if (diff & PSTATE_BTYPE) {
        if ((d->pstate & PSTATE_BTYPE) != 0)
            stat_add(ST_BAD_PSTATE, 1);
        else
            stat_add(ST_KD_BTYPE, 1);
    }
}

static int
check_ctx_rec(FILE *o, uint64_t *rec, tstep_t *st, const char *what, uint64_t pc)
{
    int bad = 0;
    if (!g_observe)
        return 0;
    for (int i = 0; i < 31; i++) {
        if ((g_taint & (1u << i)) != 0) {
            stat_add(ST_TAINTED, 1);
            continue;
        }
        if (rec[i] != st->x[i]) {
            fprintf(o, "    %s at 0x%llx: x%d 0x%llx, native 0x%llx\n", what,
                    (unsigned long long)pc, i, (unsigned long long)rec[i],
                    (unsigned long long)st->x[i]);
            bad++;
        }
    }
    if (rec[31] != st->sp) {
        fprintf(o, "    %s at 0x%llx: sp 0x%llx, native 0x%llx\n", what,
                (unsigned long long)pc, (unsigned long long)rec[31],
                (unsigned long long)st->sp);
        bad++;
    }
    if ((g_taint & (1u << 31)) == 0 && rec[32] != (st->pstate & 0xf0000000ULL)) {
        fprintf(o, "    %s at 0x%llx: nzcv 0x%llx, native 0x%llx\n", what,
                (unsigned long long)pc, (unsigned long long)rec[32],
                (unsigned long long)(st->pstate & 0xf0000000ULL));
        bad++;
    }
    if (rec[33] != st->fpsr || rec[34] != st->fpcr) {
        fprintf(o, "    %s at 0x%llx: fpsr/fpcr 0x%llx/0x%llx, native 0x%x/0x%x\n", what,
                (unsigned long long)pc, (unsigned long long)rec[33],
                (unsigned long long)rec[34], st->fpsr, st->fpcr);
        bad++;
    }
    if (rec[35] != st->vhash) {
        fprintf(o, "    %s at 0x%llx: vector registers differ from native\n", what,
                (unsigned long long)pc);
        bad++;
    }
    return bad;
}

/* Walks the log against the trace; returns the number of differences. */
static int
check_log(FILE *o, block_t *b, trace_t *t, int traced)
{
    if (getenv("A64CC_TRACEREG") != NULL && t != NULL) {
        /* Debugging: the native value of one register at every step. */
        int reg = atoi(getenv("A64CC_TRACEREG"));
        for (int st = 0; st < t->n; st++) {
            fprintf(stderr, "  native step %d pc 0x%llx x%d 0x%llx\n", st,
                    (unsigned long long)t->steps[st].pc, reg,
                    (unsigned long long)t->steps[st].x[reg]);
        }
    }
    int bad = 0;
    uint64_t *p = g_log_base, *end = a64cc_log_pos;
    leafexp_t want = { 0 };
    if (end < p || end > g_log_base + MAXLOG) {
        fprintf(o, "    log pointer out of range\n");
        return 1;
    }
    if (!traced) {
        /* Only the records' own checks. */
        while (p < end && bad < 10) {
            uint64_t mk = *p;
            if (mk == MK_CLOBBER)
                p += 13;
            else if (mk == MK_PRESERVE || mk == MK_NONLEAF)
                p += 9;
            else if (mk == MK_CTXR)
                p += 1 + CTX_WORDS;
            else if (mk == MK_CTXW) {
                if (p[1] != 1 && g_observe) {
                    fprintf(o, "    a dr_set_mcontext() delta was not exact\n");
                    bad++;
                }
                p += 2 + CTX_WORDS;
            } else if (mk == MK_TP) {
                if (p[1] != 1) {
                    /* The static-tpidr deviation. */
                    stat_add(ST_KD_TPIDR, 1);
                    if (g_strict) {
                        fprintf(o, "    callee ran with the app's TPIDR_EL0\n");
                        bad++;
                    }
                } else
                    stat_add(ST_TP_OK, 1);
                p += 2;
            } else if ((mk >> 56) == MK_HASH)
                p += HASH_WORDS;
            else {
                fprintf(o, "    corrupt log record 0x%llx\n", (unsigned long long)mk);
                return bad + 1;
            }
        }
        return bad;
    }
    for (int s = 0; s < t->n && bad < 10; s++) {
        tstep_t *st = &t->steps[s];
        uint64_t pc = st->pc;
        if (g_mode == 0) {
            site_t sites[2];
            int n = plan_sites(pc, 0, sites);
            for (int k = 0; k < n; k++) {
                site_t *si = &sites[k];
                stat_add(ST_KIND0 + si->kind, 1);
                int words = 0, mk = 0, nlog = 0;
                switch (si->kind) {
                case K_CLOBBER: mk = MK_CLOBBER, words = 13, nlog = si->nargs; break;
                case K_PRESERVE: mk = MK_PRESERVE, words = 9, nlog = si->nargs; break;
                case K_NONLEAF: mk = MK_NONLEAF, words = 9, nlog = si->nargs; break;
                case K_CTXR: mk = MK_CTXR, words = 1 + CTX_WORDS; break;
                case K_CTXW: mk = MK_CTXW, words = 2 + CTX_WORDS; break;
                case K_LEAF0: want.cnt++; break;
                case K_LEAF1: want.sum += arg_value(si, 0, st); break;
                case K_LEAFFLAGS: want.flagcnt += arg_value(si, 0, st) > 100; break;
                case K_LEAFFPSR: want.fpsrcnt++; break;
                case K_LEAFFP:
                    want.fpx ^= (arg_value(si, 0, st) & 0xfffff) +
                        (arg_value(si, 1, st) & 0xfffff);
                    break;
                }
                if (words == 0) {
                    stat_add(ST_LEAF, 1);
                    continue;
                }
                if (p + words > end || *p != (uint64_t)mk) {
                    fprintf(o,
                            "    step %d pc 0x%llx: expected a %s record, log has %s\n",
                            s, (unsigned long long)pc, kind_name[si->kind],
                            p + words > end ? "ended" : "another record");
                    return bad + 1;
                }
                stat_add(ST_RECORDS, 1);
                if (si->kind == K_CTXR) {
                    bad += check_ctx_rec(o, p + 1, st, "dr_get_mcontext", pc);
                    stat_add(ST_CTX, 1);
                } else if (si->kind == K_CTXW) {
                    if (p[1] != 1) {
                        delta_t d;
                        plan_delta(si->code, &d);
                        fprintf(o,
                                "    step %d pc 0x%llx: after dr_set_mcontext() of a "
                                "delta (kind %d reg %d val 0x%llx) the context was not "
                                "the old one plus the delta\n",
                                s, (unsigned long long)pc, d.dk, d.dreg,
                                (unsigned long long)d.dval);
                        bad++;
                    }
                    bad += check_ctx_rec(o, p + 2, st, "context after the delta", pc);
                    stat_add(ST_CTX, 1);
                } else {
                    for (int a = 0; a < nlog; a++) {
                        uint64_t want_v = arg_value(si, a, st);
                        if (p[1 + a] != want_v) {
                            fprintf(o,
                                    "    step %d pc 0x%llx: %s arg %d (%s%d) is 0x%llx, "
                                    "native 0x%llx\n",
                                    s, (unsigned long long)pc, kind_name[si->kind], a,
                                    si->src[a] < 0 ? "imm" : "x",
                                    si->src[a] < 0 ? 0 : si->src[a],
                                    (unsigned long long)p[1 + a],
                                    (unsigned long long)want_v);
                            bad++;
                        }
                    }
                }
                p += words;
            }
        } else {
            dplan_t dp;
            plan_drreg(pc, &dp);
            if (dp.log) {
                uint64_t mk = ((uint64_t)MK_HASH << 56) | ((pc - CODE_BASE) / 4);
                if (p + HASH_WORDS > end || (p[0] & ~(0xfULL << 48)) != mk) {
                    fprintf(o, "    step %d pc 0x%llx: expected a value record, %s\n", s,
                            (unsigned long long)pc,
                            p + HASH_WORDS > end ? "the log ended" : "log has another");
                    return bad + 1;
                }
                for (int j = 0; j < dp.nhash && g_observe; j++) {
                    if ((g_taint & (1u << dp.hreg[j])) != 0) {
                        stat_add(ST_TAINTED, 1);
                        continue;
                    }
                    if (p[1 + j] != st->x[dp.hreg[j]]) {
                        fprintf(o,
                                "    step %d pc 0x%llx: drreg_get_app_value(x%d) 0x%llx, "
                                "native 0x%llx\n",
                                s, (unsigned long long)pc, dp.hreg[j],
                                (unsigned long long)p[1 + j],
                                (unsigned long long)st->x[dp.hreg[j]]);
                        bad++;
                    }
                }
                int nwin = (int)((p[0] >> 48) & 0xf);
                for (int k = 0; k < nwin && k < 3; k++) {
                    /* Tool values must survive app instrs and clean calls in
                     * between, whatever the app does with those registers.
                     */
                    if (p[5 + k] != WINDOW_VAL(k)) {
                        fprintf(o,
                                "    step %d pc 0x%llx: window register %d holds tool "
                                "value 0x%llx, not 0x%llx\n",
                                s, (unsigned long long)pc, k,
                                (unsigned long long)p[5 + k],
                                (unsigned long long)WINDOW_VAL(k));
                        bad++;
                    }
                }
                stat_add(ST_HASHES, 1);
                p += HASH_WORDS;
            }
            if (dp.clobber) {
                if (p + 13 > end || *p != MK_CLOBBER) {
                    fprintf(o, "    step %d pc 0x%llx: expected a clobber record\n", s,
                            (unsigned long long)pc);
                    return bad + 1;
                }
                for (int a = 0; a < dp.cl.nargs && g_observe; a++) {
                    uint64_t want_v = arg_value(&dp.cl, a, st);
                    if (dp.cl.src[a] >= 0 && dp.cl.src[a] < 31 &&
                        (g_taint & (1u << dp.cl.src[a])) != 0) {
                        stat_add(ST_TAINTED, 1);
                        continue;
                    }
                    if (p[1 + a] != want_v) {
                        fprintf(o,
                                "    step %d pc 0x%llx: clobber arg %d (%s%d) is 0x%llx, "
                                "native 0x%llx\n",
                                s, (unsigned long long)pc, a,
                                dp.cl.src[a] < 0 ? "imm" : "x",
                                dp.cl.src[a] < 0 ? 0 : dp.cl.src[a],
                                (unsigned long long)p[1 + a], (unsigned long long)want_v);
                        bad++;
                    }
                }
                stat_add(ST_RECORDS, 1);
                p += 13;
            }
            if (dp.ctxw) {
                if (p + 2 + CTX_WORDS > end || *p != MK_CTXW) {
                    fprintf(o, "    step %d pc 0x%llx: expected a context record\n", s,
                            (unsigned long long)pc);
                    return bad + 1;
                }
                if (p[1] != 1 && g_observe) {
                    delta_t d;
                    plan_delta(dp.ctx_code, &d);
                    fprintf(o,
                            "    step %d pc 0x%llx: after dr_set_mcontext() of a delta "
                            "(kind %d reg %d val 0x%llx) the context was not the old "
                            "one plus the delta\n",
                            s, (unsigned long long)pc, d.dk, d.dreg,
                            (unsigned long long)d.dval);
                    bad++;
                }
                bad += check_ctx_rec(o, p + 2, st, "context after the delta", pc);
                stat_add(ST_CTX, 1);
                p += 2 + CTX_WORDS;
            }
        }
    }
    if (bad == 0 && p != end) {
        fprintf(o, "    %lld log words beyond the trace's records\n",
                (long long)(end - p));
        bad++;
    }
    if (g_mode == 0) {
        if (a64cc_leaf_cnt != want.cnt || a64cc_leaf_sum != want.sum ||
            a64cc_leaf_flagcnt != want.flagcnt || a64cc_leaf_fpsrcnt != want.fpsrcnt ||
            a64cc_leaf_fpx != want.fpx) {
            fprintf(
                o,
                "    leaf counters: cnt %llu/%llu sum 0x%llx/0x%llx flags %llu/%llu "
                "fpsr %llu/%llu fp 0x%llx/0x%llx (DR/native)\n",
                (unsigned long long)a64cc_leaf_cnt, (unsigned long long)want.cnt,
                (unsigned long long)a64cc_leaf_sum, (unsigned long long)want.sum,
                (unsigned long long)a64cc_leaf_flagcnt, (unsigned long long)want.flagcnt,
                (unsigned long long)a64cc_leaf_fpsrcnt, (unsigned long long)want.fpsrcnt,
                (unsigned long long)a64cc_leaf_fpx, (unsigned long long)want.fpx);
            bad++;
        }
    }
    return bad;
}

static void
reset_logs(void)
{
    a64cc_log_pos = g_log_base;
    a64cc_leaf_cnt = a64cc_leaf_sum = a64cc_leaf_flagcnt = a64cc_leaf_fpsrcnt =
        a64cc_leaf_fpx = 0;
}

/***************************************************************************
 * Fault-frame differences and the liveness oracle.
 */
typedef struct {
    int block, fault, variant;
    uint32_t mask; /* x0-x30 in bits 0-30, NZCV in bit 31 */
} deadq_t;
#define MAXQ 4096
typedef struct {
    volatile int n;
    deadq_t q[MAXQ];
} deadqs_t;
static deadqs_t *g_dq;

/* Whether n and d differ only in fault-frame GPRs/NZCV; fills masks. */
static int
only_frame_diffs(block_t *b, result_t *n, result_t *d, uint32_t *mask)
{
    if (n->nf != d->nf)
        return 0;
    static result_t nn, dd;
    nn = *n;
    dd = *d;
    for (int i = 0; i < n->nf && i < MAXF; i++) {
        mask[i] = 0;
        for (int r = 0; r < 31; r++) {
            if (nn.f[i].x[r] != dd.f[i].x[r])
                mask[i] |= 1u << r;
        }
        if ((nn.f[i].pstate ^ dd.f[i].pstate) & 0xf0000000ULL)
            mask[i] |= 1u << 31;
        memset(nn.f[i].x, 0, sizeof(nn.f[i].x));
        memset(dd.f[i].x, 0, sizeof(dd.f[i].x));
        nn.f[i].pstate &= ~0xf0000000ULL;
        dd.f[i].pstate &= ~0xf0000000ULL;
    }
    FILE *devnull = fopen("/dev/null", "w");
    int bad = a64p_cmp_results(devnull, b, &nn, &dd);
    fclose(devnull);
    return bad == 0;
}

static int g_pert_fault = -1, g_pert_reg;
static uint64_t g_pert_val;

static void
perturb_hook(a64p_worker_t *w, int n, ucontext_t *uc)
{
    if (n != g_pert_fault)
        return;
    if (g_pert_reg == 31)
        uc->uc_mcontext.pstate ^= g_pert_val & 0xf0000000ULL;
    else
        uc->uc_mcontext.regs[g_pert_reg] ^= g_pert_val;
}

/* Whether register reg (31: NZCV) is dead at fault k of b: perturbing it there
 * (twice) changes nothing observable natively.
 */
static int
native_dead(block_t *b, result_t *base, int k, int reg)
{
    static result_t r;
    static const uint64_t vals[2] = { 0x5a5a5a5a5a5a5a5aULL, 0x8000000000000001ULL };
    for (int i = 0; i < 2; i++) {
        g_pert_fault = k;
        g_pert_reg = reg;
        g_pert_val = reg == 31 ? (i == 0 ? 0x50000000ULL : 0xa0000000ULL) : vals[i];
        a64p_fault_hook = perturb_hook;
        a64p_run_block(&g_w, b, &r);
        a64p_fault_hook = NULL;
        g_pert_fault = -1;
        FILE *devnull = fopen("/dev/null", "w");
        int bad = a64p_cmp_results(devnull, b, base, &r);
        fclose(devnull);
        if (bad != 0)
            return 0;
    }
    return 1;
}

/***************************************************************************
 * Variants and the driver.
 */
typedef struct {
    variant_t v;
    int alloc, cons;
    int progress_only; /* only the budget pattern (Seedbox's progress client); 2:
                        * the callee redirects (dr_redirect_execution); 3: no
                        * drreg_get_app_value() before the unreserve; 4: no
                        * clean call either
                        */
    int store;         /* DR_EMIT_STORE_TRANSLATIONS: translate from stored info */
    int known;         /* a known failure (see the header): run only if listed */
} cvar_t;

static const cvar_t cc_variants[] = {
    { { "default", "", 0, 0, 0, 0 }, 0, 1 },
    { { "notraces", "-disable_traces", 0, 0, 0, 0 }, 0, 1 },
    { { "opt0", "-opt_cleancall 0", 0, 0, 1, 0 }, 0, 1 },
    { { "opt2", "-opt_cleancall 2", 0, 0, 1, 0 }, 0, 1 },
    { { "opt3", "-opt_cleancall 3", 0, 0, 1, 0 }, 0, 1 },
    { { "steal27", "-steal_reg 27", 0, 0, 1, 0 }, 0, 1 },
    { { "store", "", 0, 0, 0, 0 }, 0, 1, 0, 1 },
    { { "store-notraces", "-disable_traces", 0, 0, 0, 0 }, 0, 1, 0, 1 },
    { { "store-steal27", "-steal_reg 27", 0, 0, 1, 0 }, 0, 1, 0, 1 },
    { { "sandbox", "-sandbox_writable", 0, 1, 0, 0 }, 0, 1, 0, 0, 1 },
    { { "nohwcc", "-no_hw_cache_consistency", 0, 1, 0, 0 }, 0, 1 },
    { { "nohwcc-steal27", "-no_hw_cache_consistency -steal_reg 27", 0, 1, 1, 0 }, 0, 1 },
};
static const cvar_t dr_variants[] = {
    { { "drreg-choice", "", 0, 0, 0, 0 }, 0, 1 },
    { { "app-regs", "", 0, 0, 0, 0 }, 1, 1 },
    { { "random", "", 0, 0, 0, 0 }, 2, 1 },
    { { "callee-saved", "", 0, 0, 0, 0 }, 3, 1 },
    { { "noncons-choice", "", 0, 0, 0, 0 }, 0, 0 },
    { { "noncons-app-regs", "", 0, 0, 0, 0 }, 1, 0 },
    { { "noncons-random", "-disable_traces", 0, 0, 0, 0 }, 2, 0 },
    { { "steal27-random", "-steal_reg 27", 0, 0, 1, 0 }, 2, 1 },
    { { "progress", "", 0, 0, 0, 0 }, 0, 1, 1 },
    { { "progress-random", "", 0, 0, 0, 0 }, 2, 1, 1 },
    { { "progress-noncons", "", 0, 0, 0, 0 }, 0, 0, 1 },
    { { "progress-notraces", "-disable_traces", 0, 0, 0, 0 }, 1, 1, 1 },
    { { "progress-redirect", "", 0, 0, 0, 0 }, 0, 1, 2 },
    { { "progress-redirect-random", "-disable_traces", 0, 0, 0, 0 }, 2, 1, 2 },
    { { "progress-redirect-noncons", "", 0, 0, 0, 0 }, 1, 0, 2 },
    { { "progress-writer", "", 0, 0, 0, 0 }, 4, 1, 2 },
    { { "progress-writer-noreload", "", 0, 0, 0, 0 }, 4, 1, 3 },
    { { "progress-writer-nocall", "", 0, 0, 0, 0 }, 4, 1, 4 },
    { { "store-choice", "", 0, 0, 0, 0 }, 0, 1, 0, 1, 1 },
    { { "store-random", "-disable_traces", 0, 0, 0, 0 }, 2, 1, 0, 1, 1 },
    { { "store-callee-saved", "", 0, 0, 0, 0 }, 3, 1, 0, 1, 1 },
    { { "store-steal27", "-steal_reg 27", 0, 0, 1, 0 }, 2, 1, 0, 1, 1 },
    { { "store-progress", "", 0, 0, 0, 0 }, 0, 1, 1, 1, 1 },
    { { "store-progress-random", "", 0, 0, 0, 0 }, 2, 1, 1, 1, 1 },
    { { "store-progress-redirect", "", 0, 0, 0, 0 }, 0, 1, 2, 1, 1 },
    { { "store-progress-writer", "", 0, 0, 0, 0 }, 4, 1, 2, 1, 1 },
    { { "store-progress-writer-noreload", "", 0, 0, 0, 0 }, 4, 1, 3, 1, 1 },
    { { "storexl8-progress", "-store_translations", 0, 0, 1, 0 }, 0, 1, 1, 0, 1 },
    { { "sandbox-choice", "-sandbox_writable", 0, 1, 0, 0 }, 0, 1, 0, 0, 1 },
    { { "sandbox-progress", "-sandbox_writable", 0, 1, 0, 0 }, 0, 1, 1 },
    { { "sandbox-progress-redirect", "-sandbox_writable", 0, 1, 0, 0 }, 2, 1, 2 },
    { { "nohwcc-choice", "-no_hw_cache_consistency", 0, 1, 0, 0 }, 0, 1 },
    { { "nohwcc-random", "-no_hw_cache_consistency", 0, 1, 0, 0 }, 2, 1 },
    { { "nohwcc-noncons", "-no_hw_cache_consistency", 0, 1, 0, 0 }, 1, 0 },
    { { "nohwcc-progress", "-no_hw_cache_consistency", 0, 1, 0, 0 }, 0, 1, 1 },
    { { "nohwcc-progress-redirect", "-no_hw_cache_consistency", 0, 1, 0, 0 }, 2, 1, 2 },
    { { "nohwcc-progress-writer", "-no_hw_cache_consistency", 0, 1, 0, 0 }, 4, 1, 2 },
};

static int verbose;
static int is_debug_build;

/* A set of blocks with their native results and traces. */
typedef struct {
    int faults; /* generated with planned faults */
    result_t *native;
    uint8_t *valid, *traced;
    trace_t *traces;
    int gen_fail, gen_bugs, trace_fail, nvalid, ntraced;
} bset_t;

typedef struct {
    int n;
    uint64_t seed0;
    const cvar_t *cv;
    int vidx;
    int faults;
    result_t *native;
    uint8_t *valid, *traced;
    trace_t *traces;
    uint64_t tp_native[5];
} cargs_t;

static bset_t g_bsets[2];

static void
print_block_txt(FILE *o, block_t *b)
{
    for (int i = 0; i < b->a.n; i++)
        fprintf(o, "      %llx: %s\n", (unsigned long long)pc_of(i), b->a.txt[i]);
}

static int
gen(block_t *b, uint64_t seed, int traced, int faults)
{
    gen_opts_t o;
    memset(&o, 0, sizeof(o));
    o.allow_svc = 1;
    o.allow_fpcr = 1;
    o.allow_faults = faults;
    o.allow_excl = !traced;
    o.traced = traced;
    o.len = 40;
    o.dyn_max = 2000;
    return a64p_make_block(b, &o, seed);
}

static int
run_tpwin(uint64_t *out)
{
    /* Large enough that libc's TLS offsets stay inside it should the
     * hardware thread pointer ever be the app's value.
     */
    static uint64_t fake_tls[16384];
    memset(out, 0, 5 * sizeof(uint64_t));
    a64cc_tpwin((uint64_t)(uintptr_t)&fake_tls[8192], out);
    return 0;
}

/* drreg mode: runs b repeatedly while asynchronous signals arrive (an
 * itimer, a POSIX timer or another thread's tgkill), so that DR translates
 * interrupted contexts inside instrumented fragments (and drreg restores its
 * spilled app values there).  Every run must still give the native result
 * (fault frames may differ only where the plain run's did: taint), and every
 * interrupted context inside the block must be a native state: some step of
 * the native trace at that pc with the same GPRs, SP and NZCV.
 */
static a64p_sigsrc_t g_src;

static int
signal_runs(block_t *b, result_t *native, trace_t *t, uint32_t taint, int idx,
            const cvar_t *cv)
{
    int bad = 0;
    int src = idx % 3;
    rng_t r = { b->seed * 0x9e3779b97f4a7c15ULL + 17 };
    result_t *res = malloc(sizeof(*res));
    if (!a64p_sigsrc_arm(&g_src, src, &r)) {
        free(res);
        return 1;
    }
    g_w.na = 0;
    g_w.async_on = 1;
    for (int run = 0; run < SIG_RUNS && bad == 0; run++) {
        reset_logs();
        a64p_run_block(&g_w, b, res);
        stat_add(ST_RUNS, 1);
        uint32_t mask[MAXF];
        FILE *devnull = fopen("/dev/null", "w");
        int differs = a64p_cmp_results(devnull, b, native, res) != 0;
        fclose(devnull);
        if (differs) {
            int frames_only = only_frame_diffs(b, native, res, mask);
            for (int k = 0; frames_only && k < res->nf && k < MAXF; k++) {
                if ((mask[k] & ~taint) != 0)
                    frames_only = 0;
            }
            if (!frames_only) {
                fprintf(stderr,
                        "FAIL [drreg] variant=%s seed=%llu: run %d with %s signals "
                        "differs from native:\n",
                        cv->v.name, (unsigned long long)b->seed, run,
                        a64p_sigsrc_name(src));
                a64p_cmp_results(stderr, b, native, res);
                bad++;
            }
        }
    }
    g_w.async_on = 0;
    a64p_sigsrc_disarm(&g_src, src);
    /* The interrupted contexts (not in non-conservative mode, where dead
     * registers may hold tool values: only the resumed results count there).
     */
    int n = !g_cons ? 0 : g_w.na < MAXA ? g_w.na : MAXA;
    for (int k = 0; k < n && bad < 5; k++) {
        arec_t *a = &g_w.alog[k];
        if (a->run < 0 || a->pc < g_w.blk_lo || a->pc >= g_w.exit_pc)
            continue;
        int found = 0, pc_seen = 0;
        for (int st = 0; st < t->n && !found; st++) {
            tstep_t *s2 = &t->steps[st];
            if (s2->pc != a->pc)
                continue;
            pc_seen = 1;
            int eq = s2->sp == a->sp &&
                ((taint & (1u << 31)) != 0 ||
                 (s2->pstate & 0xf0000000ULL) == (a->pstate & 0xf0000000ULL));
            for (int reg = 0; reg < 31 && eq; reg++) {
                if ((taint & (1u << reg)) == 0 && s2->x[reg] != a->x[reg])
                    eq = 0;
            }
            found = eq;
        }
        if (!pc_seen)
            continue; /* not a step the native trace records (e.g. the exit) */
        stat_add(ST_ASYNC_CHECKED, 1);
        if (found)
            continue;
        fprintf(stderr,
                "FAIL [drreg] variant=%s seed=%llu: %s interrupted context at pc 0x%llx "
                "matches no native state there:\n",
                cv->v.name, (unsigned long long)b->seed, a64p_sigsrc_name(src),
                (unsigned long long)a->pc);
        /* Show the closest native step. */
        int best = -1, bestd = 99;
        for (int st = 0; st < t->n; st++) {
            if (t->steps[st].pc != a->pc)
                continue;
            int d = 0;
            for (int reg = 0; reg < 31; reg++)
                d += t->steps[st].x[reg] != a->x[reg];
            if (d < bestd) {
                bestd = d;
                best = st;
            }
        }
        if (best >= 0) {
            tstep_t *s2 = &t->steps[best];
            for (int reg = 0; reg < 31; reg++) {
                if (s2->x[reg] != a->x[reg]) {
                    fprintf(stderr, "    x%d 0x%llx, native 0x%llx (step %d)\n", reg,
                            (unsigned long long)a->x[reg], (unsigned long long)s2->x[reg],
                            best);
                }
            }
            if (s2->sp != a->sp)
                fprintf(stderr, "    sp differs\n");
            if ((s2->pstate ^ a->pstate) & 0xf0000000ULL)
                fprintf(stderr, "    nzcv 0x%llx, native 0x%llx\n",
                        (unsigned long long)(a->pstate & 0xf0000000ULL),
                        (unsigned long long)(s2->pstate & 0xf0000000ULL));
        }
        bad++;
    }
    free(res);
    return bad;
}

static int
child(void *argp)
{
    cargs_t *a = (cargs_t *)argp;
    const cvar_t *cv = a->cv;
    block_t *b = malloc(sizeof(*b));
    result_t *r = malloc(sizeof(*r));
    int fails = 0;
    a64p_install_handlers(&g_w, 0);
    g_alloc = cv->alloc;
    g_progress_only = cv->progress_only || getenv("A64CC_PROGRESS_ONLY") != NULL;
    g_progress_redirect =
        cv->progress_only == 2 || getenv("A64CC_PROGRESS_REDIRECT") != NULL;
    g_progress_noreload = cv->progress_only >= 3;
    g_progress_nocall = cv->progress_only == 4;
    g_store = cv->store;
    /* The budget pattern mixed with the other reservations: off by default,
     * see the header (drreg's state restoration cannot model it).
     */
    g_progress_on = g_progress_only || getenv("A64CC_PROGRESS_MIXED") != NULL;
    g_cons = cv->cons;
    g_observe = g_mode == 0 || g_cons;
    g_client_on = 1;
    g_tp_lo = (uint64_t)(uintptr_t)a64cc_tpwin;
    g_tp_hi = (uint64_t)(uintptr_t)a64cc_tpwin_end;
    g_w.blk_lo = CODE_BASE;
    g_w.blk_hi = CODE_BASE;
    g_libc_tp = read_tp();
    a64p_sigsrc_init(&g_src, &g_w);
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "dr start");
    a64p_start_dr(cv->v.dr_ops);
    /* The TPIDR_EL0 window. */
    if (g_mode == 0) {
        g_plan_seed = a->seed0 * 77 + 1;
        reset_logs();
        uint64_t out[5];
        for (int rep = 0; rep < 3; rep++) {
            reset_logs();
            run_tpwin(out);
            char *txt = NULL;
            size_t len = 0;
            FILE *o = open_memstream(&txt, &len);
            int bad = 0;
            for (int i = 0; i < 5; i++) {
                if (out[i] != a->tp_native[i]) {
                    fprintf(o, "    tpwin out[%d] 0x%llx, native 0x%llx\n", i,
                            (unsigned long long)out[i],
                            (unsigned long long)a->tp_native[i]);
                    bad++;
                }
            }
            bad += check_log(o, b, NULL, 0);
            if (read_tp() != g_libc_tp) {
                fprintf(o, "    TPIDR_EL0 not restored after the window\n");
                bad++;
            }
            fclose(o);
            stat_add(ST_TPWIN, 1);
            if (bad) {
                fprintf(stderr, "FAIL [cleancall] variant=%s TPIDR_EL0 window:\n%s",
                        cv->v.name, txt);
                fails++;
            }
            free(txt);
        }
    }
    for (int i = 0; i < a->n; i++) {
        if (!a->valid[i])
            continue;
        uint64_t seed = a->seed0 + i;
        a64p_prog->block = i;
        a64p_prog->seed = seed;
        g_plan_seed = seed * 31 + 7;
        if (!gen(b, seed, a->traced[i], a->faults)) {
            fprintf(stderr, "FAIL: seed %llu no longer generates\n",
                    (unsigned long long)seed);
            fails++;
            continue;
        }
        g_vres = b->vres;
        a64p_install_code(&g_w, b, cv->v.install);
        int ok = 1;
        for (int rep = 0; rep < 2 && ok; rep++) {
            a64p_prog->run = rep;
            reset_logs();
            g_api_fail = 0;
            g_no_app_value = 0;
            g_ctx_bad = 0;
            snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "run");
            a64p_run_block(&g_w, b, r);
            stat_add(ST_RUNS, 1);
            char *txt = NULL;
            size_t len = 0;
            FILE *o = open_memstream(&txt, &len);
            int bad = 0;
            uint32_t mask[MAXF];
            g_taint = 0;
            FILE *devnull = fopen("/dev/null", "w");
            int differs = a64p_cmp_results(devnull, b, &a->native[i], r) != 0;
            fclose(devnull);
            if (differs) {
                if (g_mode == 1 && only_frame_diffs(b, &a->native[i], r, mask)) {
                    if (verbose) {
                        fprintf(stderr,
                                "  [%s] seed %llu run %d: fault-frame "
                                "differences for the liveness oracle:\n",
                                cv->v.name, (unsigned long long)seed, rep);
                        a64p_cmp_results(stderr, b, &a->native[i], r);
                    }
                    /* For the liveness oracle in the parent. */
                    for (int k = 0; k < r->nf && k < MAXF; k++) {
                        if (mask[k] == 0)
                            continue;
                        g_taint |= mask[k];
                        int qi = __atomic_fetch_add(&g_dq->n, 1, __ATOMIC_SEQ_CST);
                        if (qi < MAXQ) {
                            g_dq->q[qi].block = i;
                            g_dq->q[qi].fault = k;
                            g_dq->q[qi].variant = a->vidx;
                            g_dq->q[qi].mask = mask[k];
                        }
                        stat_add(ST_DEAD_Q, 1);
                    }
                } else
                    bad += a64p_cmp_results(o, b, &a->native[i], r);
            }
            bad += check_log(o, b, &a->traces[i], a->traced[i]);
            if (g_api_fail > 0) {
                fprintf(o, "    %ld drreg/DR API failures\n", g_api_fail);
                bad++;
            }
            stat_add(ST_NO_APP_VALUE, g_no_app_value);
            if (g_ctx_bad > 0) {
                fprintf(o, "    %ld dr_get/set_mcontext failures\n", g_ctx_bad);
                bad++;
            }
            fclose(o);
            if (bad > 0) {
                ok = 0;
                fails++;
                fprintf(stderr, "FAIL [%s] variant=%s seed=%llu run=%d:\n%s",
                        g_mode ? "drreg" : "cleancall", cv->v.name,
                        (unsigned long long)seed, rep, txt);
                if (verbose) {
                    a64p_print_faults(stderr, "native", &a->native[i]);
                    a64p_print_faults(stderr, "dr", r);
                    print_block_txt(stderr, b);
                }
                fprintf(stderr,
                        "  repro: a64_prop_cleancall %s -seed %llu -n 1 "
                        "-variants %s -v\n",
                        g_mode ? "drreg" : "cleancall", (unsigned long long)seed,
                        cv->v.name);
            }
            free(txt);
        }
        if (ok && g_mode == 1 && a->traced[i]) {
            uint32_t taint = g_taint;
            int bad = signal_runs(b, &a->native[i], &a->traces[i], taint, i, cv);
            if (bad) {
                ok = 0;
                fails++;
                fprintf(stderr,
                        "  repro: a64_prop_cleancall drreg -seed %llu -n 1 -variants %s "
                        "-v\n",
                        (unsigned long long)seed, cv->v.name);
            }
        }
        if (ok) {
            stat_add(ST_BLOCKS_CHECKED, 1);
            if (!a->traced[i])
                stat_add(ST_UNTRACED, 1);
        }
        if (fails > 5)
            break;
    }
    stat_add(ST_PROGRESS_CALLS, g_progress_calls);
    if (g_progress_bad > 0) {
        fprintf(stderr, "FAIL: %ld dr_get_mcontext failures in MULTIPATH calls\n",
                g_progress_bad);
        fails++;
    }
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "dr stop");
    a64p_stop_dr();
    return fails;
}

int
main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "cleancall";
    uint64_t seed0 = 1;
    int n = 40;
    const char *vlist = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc)
            seed0 = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            n = atoi(argv[++i]);
        else if (strcmp(argv[i], "-variants") == 0 && i + 1 < argc)
            vlist = argv[++i];
        else if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if (strcmp(mode, "cleancall") == 0)
        g_mode = 0;
    else if (strcmp(mode, "drreg") == 0)
        g_mode = 1;
    else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    const cvar_t *vars = g_mode == 0 ? cc_variants : dr_variants;
    int nvars = g_mode == 0 ? (int)(sizeof(cc_variants) / sizeof(cc_variants[0]))
                            : (int)(sizeof(dr_variants) / sizeof(dr_variants[0]));
    if (vlist != NULL) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s", vlist);
        for (char *t = strtok(buf, ","); t != NULL; t = strtok(NULL, ",")) {
            int found = 0;
            for (int v = 0; v < nvars; v++)
                found |= strcmp(t, vars[v].v.name) == 0;
            if (!found) {
                fprintf(stderr, "unknown variant '%s'\n", t);
                return 2;
            }
        }
    }
#ifdef A64_DR_PROP_DEBUG_DR
    is_debug_build = 1;
#endif
    if (getenv("A64_DR_PROP_DEBUG_DR") != NULL)
        is_debug_build = atoi(getenv("A64_DR_PROP_DEBUG_DR"));
    g_strict = getenv("A64_PROP_CLEANCALL_STRICT") != NULL;
    if (!g_strict) {
        a64p_fault_pstate_ignore = PSTATE_SSBS | PSTATE_BTYPE;
        a64p_on_masked_pstate = on_masked_pstate;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    a64p_init_features();
    a64p_progress_init("a64_prop_cleancall");
    a64p_worker_init(&g_w);
    a64p_setup_maps();
    a64p_install_handlers(&g_w, 0);
    g_log_base = mmap(NULL, MAXLOG * sizeof(uint64_t), PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_dq = mmap(NULL, sizeof(*g_dq), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                -1, 0);
    g_libc_tp = read_tp();

    /* Native runs and traces: blocks with planned faults for clean calls and
     * conservative drreg, and fault-free blocks for non-conservative drreg
     * (whose documented assumption is that the app does not rely on a dead
     * register's value when a fault happens, while our handler resumes after
     * the faulting instruction, which can leave a register live that drreg
     * took as dead because that instruction writes it).
     */
    block_t *b = malloc(sizeof(*b));
    int fails = 0;
    for (int set = 0; set < 2; set++) {
        bset_t *bs = &g_bsets[set];
        bs->faults = set == 0;
        bs->native = calloc(n, sizeof(result_t));
        bs->valid = calloc(n, 1);
        bs->traced = calloc(n, 1);
        bs->traces = calloc(n, sizeof(trace_t));
        if (set == 1 && g_mode == 0)
            break;
        for (int i = 0; i < n; i++) {
            uint64_t seed = seed0 + i;
            int want_trace = (seed % 4) != 3;
            if (!gen(b, seed, want_trace, bs->faults)) {
                bs->gen_fail++;
                continue;
            }
            a64p_install_code(&g_w, b, 0);
            a64p_run_block(&g_w, b, &bs->native[i]);
            if (!a64p_check_planned(b, &bs->native[i])) {
                fprintf(stderr, "GENERATOR BUG: unplanned native fault, seed %llu\n",
                        (unsigned long long)seed);
                bs->gen_bugs++;
                continue;
            }
            result_t again;
            a64p_run_block(&g_w, b, &again);
            FILE *devnull = fopen("/dev/null", "w");
            int nondet = a64p_cmp_results(devnull, b, &bs->native[i], &again);
            fclose(devnull);
            if (nondet) {
                bs->gen_fail++;
                continue;
            }
            bs->valid[i] = 1;
            bs->nvalid++;
            if (want_trace) {
                bs->traces[i].cap = 20000;
                bs->traces[i].steps = malloc(sizeof(tstep_t) * bs->traces[i].cap);
                if (a64p_trace_block(&g_w, b, &bs->traces[i]) < 0) {
                    bs->trace_fail++;
                    free(bs->traces[i].steps);
                    bs->traces[i].steps = NULL;
                    continue;
                }
                bs->traced[i] = 1;
                bs->ntraced++;
            }
        }
    }
    cargs_t a;
    memset(&a, 0, sizeof(a));
    a.n = n;
    a.seed0 = seed0;
    if (g_mode == 0)
        run_tpwin(a.tp_native);
    long tot[ST_NUM];
    memset(tot, 0, sizeof(tot));
    int nvar = 0;
    g_dq->n = 0;
    for (int v = 0; v < nvars; v++) {
        if (vlist != NULL && !a64p_variant_selected(vlist, &vars[v].v))
            continue;
        if (vars[v].v.debug_only && !is_debug_build)
            continue;
        /* Known to fail (see the header): only when listed. */
        if (vars[v].known && vlist == NULL)
            continue;
        a.cv = &vars[v];
        a.vidx = v;
        bset_t *bs = &g_bsets[g_mode == 1 && !vars[v].cons ? 1 : 0];
        a.faults = bs->faults;
        a.native = bs->native;
        a.valid = bs->valid;
        a.traced = bs->traced;
        a.traces = bs->traces;
        int f = a64p_in_child(mode, &vars[v].v, child, &a);
        for (int s = 0; s < ST_NUM; s++)
            tot[s] += a64p_prog->stat[s];
        fails += f;
        nvar++;
        if (verbose)
            printf("%s variant %-16s: %d failures\n", mode, vars[v].v.name, f);
    }
    /* The liveness oracle for fault-frame differences (drreg). */
    long dead_ok = 0, dead_cons = 0;
    int nq = g_dq->n < MAXQ ? g_dq->n : MAXQ;
    if (nq > 0) {
        a64p_install_handlers(&g_w, 0);
        for (int qi = 0; qi < nq; qi++) {
            deadq_t *q = &g_dq->q[qi];
            uint64_t seed = seed0 + q->block;
            bset_t *bs = &g_bsets[vars[q->variant].cons ? 0 : 1];
            if (!gen(b, seed, bs->traced[q->block], bs->faults)) {
                fails++;
                continue;
            }
            a64p_install_code(&g_w, b, 0);
            int all = 1;
            for (int reg = 0; reg < 32; reg++) {
                if (!(q->mask & (1u << reg)))
                    continue;
                if (!native_dead(b, &bs->native[q->block], q->fault, reg)) {
                    fprintf(stderr,
                            "FAIL [drreg] variant=%s seed=%llu: fault %d frame differs "
                            "in %s%d, which is live there natively\n",
                            vars[q->variant].v.name, (unsigned long long)seed, q->fault,
                            reg == 31 ? "nzcv" : "x", reg == 31 ? 0 : reg);
                    all = 0;
                }
            }
            if (!all) {
                fails++;
                a64p_print_faults(stderr, "native", &bs->native[q->block]);
            } else if (vars[q->variant].cons)
                dead_cons++;
            else
                dead_ok++;
        }
    }
    if (g_dq->n > MAXQ) {
        fprintf(stderr, "FAIL: %d fault-frame differences, more than %d checked\n",
                g_dq->n, MAXQ);
        fails++;
    }

    int nvalid = g_bsets[0].nvalid + g_bsets[1].nvalid;
    int ntraced = g_bsets[0].ntraced + g_bsets[1].ntraced;
    int nsets = g_mode == 1 ? 2 : 1;
    long inconclusive = 0;
    for (int set = 0; set < nsets; set++) {
        inconclusive +=
            g_bsets[set].gen_fail + g_bsets[set].gen_bugs + g_bsets[set].trace_fail;
    }
    a64p_counts_t c = { (long)n * nsets,
                        nvalid,
                        tot[ST_RUNS],
                        tot[ST_BLOCKS_CHECKED],
                        dead_ok + dead_cons + tot[ST_KD_SSBS] + tot[ST_KD_BTYPE],
                        inconclusive };
    a64p_counts_print(stdout, mode, &c);
    if (g_mode == 0) {
        printf("cleancall: records checked %ld (contexts %ld), leaf calls %ld, TPIDR "
               "windows %ld\n",
               tot[ST_RECORDS], tot[ST_CTX], tot[ST_LEAF], tot[ST_TPWIN]);
        printf("cleancall: known deviations: static-tpidr %ld (callees in the window "
               "that saw libc's thread pointer: %ld)\n",
               tot[ST_KD_TPIDR], tot[ST_TP_OK]);
        if (verbose) {
            for (int k = 0; k < NUM_K; k++)
                printf("  %s sites executed: %ld\n", kind_name[k], tot[ST_KIND0 + k]);
        }
        fails += a64p_floor(mode, "records checked", tot[ST_RECORDS], 50L * nvar);
        fails += a64p_floor(mode, "contexts checked", tot[ST_CTX], 10L * nvar);
        fails += a64p_floor(mode, "leaf calls", tot[ST_LEAF], 20L * nvar);
        fails += a64p_floor(mode, "TPIDR windows", tot[ST_TPWIN], 3L * nvar);
    } else {
        printf("drreg: app values records checked %ld, clean-call records %ld, contexts "
               "%ld, "
               "fault-frame differences in dead registers: non-conservative %ld, "
               "conservative (i#3801) %ld\n",
               tot[ST_HASHES], tot[ST_RECORDS], tot[ST_CTX], dead_ok, dead_cons);
        fails +=
            a64p_floor(mode, "app value records checked", tot[ST_HASHES], 100L * nvar);
        fails += a64p_floor(mode, "contexts checked", tot[ST_CTX], 5L * nvar);
    }
    printf("%s: known fault-frame PSTATE deviations: ssbs %ld, btype %ld\n", mode,
           tot[ST_KD_SSBS], tot[ST_KD_BTYPE]);
    if (g_mode == 1) {
        printf("drreg: interrupted contexts checked %ld, budget clean calls taken %ld\n",
               tot[ST_ASYNC_CHECKED], tot[ST_PROGRESS_CALLS]);
        fails += a64p_floor(mode, "interrupted contexts checked", tot[ST_ASYNC_CHECKED],
                            20L * nvar);
        fails += a64p_floor(mode, "budget clean calls taken", tot[ST_PROGRESS_CALLS],
                            100L * nvar);
        printf("drreg: observations not compared after a dead-register fault-frame "
               "difference: %ld, non-conservative NO_APP_VALUE: %ld\n",
               tot[ST_TAINTED], tot[ST_NO_APP_VALUE]);
    }
    if (tot[ST_BAD_PSTATE] > 0) {
        fprintf(stderr,
                "FAIL: %ld fault frames where DR reports a nonzero BTYPE that "
                "differs from native\n",
                tot[ST_BAD_PSTATE]);
        fails++;
    }
    fails += a64p_floor(mode, "natively valid blocks", nvalid, (long)nsets * (n + 1) / 2);
    fails += a64p_floor(mode, "traced blocks", ntraced, (long)nsets * n / 2);
    fails += a64p_floor(mode, "blocks checked per variant", tot[ST_BLOCKS_CHECKED],
                        (long)nvar * n * 9 / 20);
    if (fails == 0)
        printf("%s: all properties hold\n", mode);
    else
        printf("%s: %d failures\n", mode, fails);
    return fails == 0 ? 0 : 1;
}

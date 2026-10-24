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

/* Signal ABI and DR-internal-path properties of AArch64 execution under
 * (static) DynamoRIO.  Each case is a hand-written scenario template (below,
 * in assembly) with seeded parameters: initial GPRs/V registers/NZCV/DIT,
 * the signal, its source, its sigaction flags and masks, and the effects the
 * handler applies to the interrupted context.  Every case runs natively (the
 * paired oracle) and then under DR, and each run is also checked against an
 * independent model of the scenario:
 *
 *   - every handler invocation sees a permitted application context: a PC the
 *     scenario allows at that point (legal deferral of asynchronous delivery
 *     is allowed: any PC of the spin loop the scenario waits in) with exactly
 *     the modelled GPRs, SP, NZCV, DIT, V registers and FPCR, and a frame
 *     whose record list is valid by the kernel ABI (a64p_check_frame_records)
 *     and identical to the native one;
 *   - handler-written GPR, NZCV, DIT, V register, PC (a labelled continuation)
 *     and SP (moved within the live stack) take effect after sigreturn, and
 *     state the handler does not write is preserved (notably DIT);
 *   - nesting (SA_NODEFER, or a second signal raised from the handler) is
 *     delivered inside the outer handler and the inner handler's edit of the
 *     outer handler's context takes effect; sa_mask blocks a signal raised in
 *     the handler until sigreturn, which then delivers it with the restored
 *     mask; sigprocmask inside the block keeps a signal pending until it is
 *     unblocked; sigaltstack enabled and disabled from the block moves the
 *     frame onto and off the alternate stack and reports it in uc_stack and
 *     sigaltstack(); real-time payloads arrive exactly once, lowest signal
 *     first and FIFO per signal; a blocking pipe read interrupted with
 *     SA_RESTART is restarted (frame PC at the svc, x0 the fd) and without it
 *     returns EINTR (frame PC after the svc, x0 -EINTR);
 *   - synchronous signals (UDF, BRK, a load from a guard page) are taken at
 *     the faulting instruction with the native si_code, si_addr, fault_address
 *     and ESR record;
 *   - live stack above the interrupted SP (canaries) is never written;
 *   - nothing hangs (every wait is bounded; a child is killed and reported
 *     after a timeout).
 *
 * Modes:
 *   abi: the scenarios natively and under DR (default, -max_bb_instrs 3 and
 *     -disable_traces, plus -steal_reg 27 and resets at every pending signal
 *     against a debug DR).
 *   paths: the same scenarios plus an IBL-churning spin loop under an
 *     in-process client that adds drreg reservations with clobbered values,
 *     aflags clobbers, drx counters and clean calls (all of them with
 *     A64_DR_PROP_CLEANCALL=1, which one variant always sets) to every
 *     scenario instruction; then "storm": threads exiting while signals are in
 *     flight.  Four threads (the main one included) wait in read() or an
 *     unbounded ppoll() of their own empty pipe, each interrupted by its own
 *     SIGEV_THREAD_ID timer and by tgkills at random moments, while a
 *     SIGEV_THREAD timer spawns notification threads that exit, other threads
 *     with the signals unblocked are created and exit (at most -churn_max, 8,
 *     at a time), a process-directed POSIX timer runs, and another thread sends
 *     sequence-numbered process-directed rt signals one at a time: each must be
 *     delivered exactly once, every expiration of the process timer must be
 *     accounted (deliveries plus overruns, counted exactly at a cut), and no
 *     waiter may stop being interrupted for 3 s (the shape of the hang fixed by
 *     "Deliver a signal that arrives on the way into a syscall before it").
 *   storm: just the storm (-waiters N, -poker 0|1 and -churn_max N vary it).
 *
 * Usage: a64_prop_signal <abi|paths|storm> [-seed S] [-n N] [-only I]
 *        [-rounds R] [-variants a,b] [-waiters N] [-poker 0|1] [-churn_max N] [-v]
 * -n is the number of cases per scenario kind; -only runs one case index.
 *
 * Known deviation (counted as suppressed): rt-overflow-order, see
 * DR_MAX_PENDING_SIGNALS below.  Known issue: memcache-check-race, see
 * STORM_DEBUG_DR_OPS below.
 *
 * Counts are printed as generated / accepted / executed / checked /
 * suppressed / inconclusive, with floors; "all properties hold" is only
 * printed if every check and floor passed.
 */

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drx.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include "a64_prop_support.h"

#ifndef HWCAP_DIT
#    define HWCAP_DIT (1 << 24)
#endif
#ifndef HWCAP2_SME
#    define HWCAP2_SME (1 << 23)
#endif
#ifndef PR_SME_GET_VL
#    define PR_SME_GET_VL 64
#endif

#define PSTATE_NZCV 0xf0000000ULL
#define PSTATE_DIT 0x01000000ULL

/***************************************************************************
 * The scenario context, shared with the assembly (fixed offsets).
 */
#define O_IN_X 0
#define O_IN_NZCV 248
#define O_IN_DIT 256
#define O_IN_SP 264
#define O_BODY 272
#define O_HOST_SP 280
#define O_OUT_X 288
#define O_OUT_SP 536
#define O_OUT_NZCV 544
#define O_OUT_DIT 552
#define O_OUT_CONT 560
#define O_FLAG0 568
#define O_FLAG1 576
#define O_FLAG2 584
#define O_STARTED 600
#define O_HAS_DIT 608
#define O_PID 616
#define O_TID 624
#define O_SIG 632
#define O_AUX 640
#define O_AUX2 648
#define O_COUNT 656
#define O_RESULT 664
#define O_SET 672
#define O_PEND 680
#define O_SCRATCH 688
#define O_TGT 704
#define O_IN_RUN 736
#define O_IN_V 768
#define O_OUT_V 1280
#define O_SS_ON 1792
#define O_SS_OFF 1816
#define O_SS_Q 1840
#define O_RTTAB 2048
#define RT_MAX 16

typedef struct {
    uint64_t in_x[31];
    uint64_t in_nzcv, in_dit, in_sp, body, host_sp;
    uint64_t out_x[31];
    uint64_t out_sp, out_nzcv, out_dit, out_cont;
    volatile uint64_t flag[4];
    volatile uint64_t started;
    uint64_t has_dit, pid, tid, sig, aux, aux2, count;
    volatile int64_t result;
    uint64_t set, pend;
    uint8_t scratch[16];
    uint64_t tgt[4];
    volatile uint64_t in_run; /* set by a64ps_run, cleared by a64ps_capture */
    uint64_t pad0[3];
    __uint128_t in_v[32];
    __uint128_t out_v[32];
    stack_t ss_on, ss_off, ss_q;
    uint8_t pad1[2048 - 1864];
    uint8_t rttab[RT_MAX][128];
} sgctx_t;

_Static_assert(offsetof(sgctx_t, in_nzcv) == O_IN_NZCV, "asm offset");
_Static_assert(offsetof(sgctx_t, in_dit) == O_IN_DIT, "asm offset");
_Static_assert(offsetof(sgctx_t, in_sp) == O_IN_SP, "asm offset");
_Static_assert(offsetof(sgctx_t, body) == O_BODY, "asm offset");
_Static_assert(offsetof(sgctx_t, host_sp) == O_HOST_SP, "asm offset");
_Static_assert(offsetof(sgctx_t, out_x) == O_OUT_X, "asm offset");
_Static_assert(offsetof(sgctx_t, out_sp) == O_OUT_SP, "asm offset");
_Static_assert(offsetof(sgctx_t, out_nzcv) == O_OUT_NZCV, "asm offset");
_Static_assert(offsetof(sgctx_t, out_dit) == O_OUT_DIT, "asm offset");
_Static_assert(offsetof(sgctx_t, out_cont) == O_OUT_CONT, "asm offset");
_Static_assert(offsetof(sgctx_t, flag) == O_FLAG0, "asm offset");
_Static_assert(offsetof(sgctx_t, started) == O_STARTED, "asm offset");
_Static_assert(offsetof(sgctx_t, has_dit) == O_HAS_DIT, "asm offset");
_Static_assert(offsetof(sgctx_t, pid) == O_PID, "asm offset");
_Static_assert(offsetof(sgctx_t, tid) == O_TID, "asm offset");
_Static_assert(offsetof(sgctx_t, sig) == O_SIG, "asm offset");
_Static_assert(offsetof(sgctx_t, aux) == O_AUX, "asm offset");
_Static_assert(offsetof(sgctx_t, aux2) == O_AUX2, "asm offset");
_Static_assert(offsetof(sgctx_t, count) == O_COUNT, "asm offset");
_Static_assert(offsetof(sgctx_t, result) == O_RESULT, "asm offset");
_Static_assert(offsetof(sgctx_t, set) == O_SET, "asm offset");
_Static_assert(offsetof(sgctx_t, pend) == O_PEND, "asm offset");
_Static_assert(offsetof(sgctx_t, scratch) == O_SCRATCH, "asm offset");
_Static_assert(offsetof(sgctx_t, tgt) == O_TGT, "asm offset");
_Static_assert(offsetof(sgctx_t, in_run) == O_IN_RUN, "asm offset");
_Static_assert(offsetof(sgctx_t, in_v) == O_IN_V, "asm offset");
_Static_assert(offsetof(sgctx_t, out_v) == O_OUT_V, "asm offset");
_Static_assert(offsetof(sgctx_t, ss_on) == O_SS_ON, "asm offset");
_Static_assert(offsetof(sgctx_t, ss_off) == O_SS_OFF, "asm offset");
_Static_assert(offsetof(sgctx_t, ss_q) == O_SS_Q, "asm offset");
_Static_assert(offsetof(sgctx_t, rttab) == O_RTTAB, "asm offset");

/* Fixed addresses, so that native and DR runs see identical stacks and frames. */
#define SG_BASE 0x3200000000ULL
#define SG_CTX ((sgctx_t *)SG_BASE)
#define SG_STK_LO (SG_BASE + 0x10000ULL)
#define SG_STK_TOP (SG_BASE + 0x30000ULL)
#define SG_ALT_LO (SG_BASE + 0x40000ULL)
#define SG_ALT_SIZE 0x10000ULL
#define SG_GUARD (SG_BASE + 0x50000ULL) /* PROT_NONE: the SEGV scenario's target */
#define SG_MAP_SIZE 0x51000ULL
#define SG_CANARY 64 /* bytes of canaries the bodies push below in_sp */

#define SGS_(x) #x
#define SGS(x) SGS_(x)

/* clang-format off */
/* Every scenario body starts here: canaries (x0..x7) on the stack, x16 = 0,
 * x17 = 1 and ctx->started = 1.
 */
#define PRELUDE                                    \
    "  sub sp, sp, #64\n"                          \
    "  stp x0, x1, [sp]\n"                         \
    "  stp x2, x3, [sp, #16]\n"                    \
    "  stp x4, x5, [sp, #32]\n"                    \
    "  stp x6, x7, [sp, #48]\n"                    \
    "  mov x16, #0\n"                              \
    "  mov x17, #1\n"                              \
    "  str x17, [x28, #" SGS(O_STARTED) "]\n"
#define TGKILL_SELF                                \
    "  ldr x0, [x28, #" SGS(O_PID) "]\n"           \
    "  ldr x1, [x28, #" SGS(O_TID) "]\n"           \
    "  ldr x2, [x28, #" SGS(O_SIG) "]\n"           \
    "  mov x8, #131\n"                             \
    "  svc #0\n"
#define SIGPROCMASK(how)                           \
    "  mov x0, #" #how "\n"                        \
    "  add x1, x28, #" SGS(O_SET) "\n"             \
    "  mov x2, #0\n"                               \
    "  mov x3, #8\n"                               \
    "  mov x8, #135\n"                             \
    "  svc #0\n"

/* x28 holds the context throughout (it is also DR's default stolen register). */
__asm__(".text\n"
        ".p2align 4\n"
        ".global a64ps_code_lo\n"
        "a64ps_code_lo:\n"
        ".global a64ps_run\n"
        ".type a64ps_run, %function\n"
        "a64ps_run:\n"
        "  hint #34\n"
        "  stp x29, x30, [sp, #-160]!\n"
        "  mov x29, sp\n"
        "  stp x19, x20, [sp, #16]\n"
        "  stp x21, x22, [sp, #32]\n"
        "  stp x23, x24, [sp, #48]\n"
        "  stp x25, x26, [sp, #64]\n"
        "  stp x27, x28, [sp, #80]\n"
        "  stp d8, d9, [sp, #96]\n"
        "  stp d10, d11, [sp, #112]\n"
        "  stp d12, d13, [sp, #128]\n"
        "  stp d14, d15, [sp, #144]\n"
        "  mov x28, x0\n"
        "  mov x1, #1\n"
        "  str x1, [x28, #" SGS(O_IN_RUN) "]\n"
        "  mov x1, sp\n"
        "  str x1, [x28, #" SGS(O_HOST_SP) "]\n"
        "  add x16, x28, #" SGS(O_IN_V) "\n"
        "  ldp q0, q1, [x16, #0]\n"
        "  ldp q2, q3, [x16, #32]\n"
        "  ldp q4, q5, [x16, #64]\n"
        "  ldp q6, q7, [x16, #96]\n"
        "  ldp q8, q9, [x16, #128]\n"
        "  ldp q10, q11, [x16, #160]\n"
        "  ldp q12, q13, [x16, #192]\n"
        "  ldp q14, q15, [x16, #224]\n"
        "  ldp q16, q17, [x16, #256]\n"
        "  ldp q18, q19, [x16, #288]\n"
        "  ldp q20, q21, [x16, #320]\n"
        "  ldp q22, q23, [x16, #352]\n"
        "  ldp q24, q25, [x16, #384]\n"
        "  ldp q26, q27, [x16, #416]\n"
        "  ldp q28, q29, [x16, #448]\n"
        "  ldp q30, q31, [x16, #480]\n"
        "  ldr x1, [x28, #" SGS(O_IN_NZCV) "]\n"
        "  msr nzcv, x1\n"
        "  ldr x1, [x28, #" SGS(O_HAS_DIT) "]\n"
        "  cbz x1, 1f\n"
        "  ldr x1, [x28, #" SGS(O_IN_DIT) "]\n"
        "  msr s3_3_c4_c2_5, x1\n" /* dit */
        "1:\n"
        "  ldr x1, [x28, #" SGS(O_IN_SP) "]\n"
        "  mov sp, x1\n"
        "  add x16, x28, #" SGS(O_IN_X) "\n"
        "  ldp x0, x1, [x16, #0]\n"
        "  ldp x2, x3, [x16, #16]\n"
        "  ldp x4, x5, [x16, #32]\n"
        "  ldp x6, x7, [x16, #48]\n"
        "  ldp x8, x9, [x16, #64]\n"
        "  ldp x10, x11, [x16, #80]\n"
        "  ldp x12, x13, [x16, #96]\n"
        "  ldp x14, x15, [x16, #112]\n"
        "  ldr x17, [x16, #136]\n"
        "  ldp x18, x19, [x16, #144]\n"
        "  ldp x20, x21, [x16, #160]\n"
        "  ldp x22, x23, [x16, #176]\n"
        "  ldp x24, x25, [x16, #192]\n"
        "  ldp x26, x27, [x16, #208]\n"
        "  ldp x29, x30, [x16, #232]\n"
        "  ldr x16, [x28, #" SGS(O_BODY) "]\n"
        "  br x16\n"
        /* Final state capture: every body ends here. */
        ".global a64ps_capture\n"
        "a64ps_capture:\n"
        "  str x16, [x28, #" SGS(O_OUT_X) "+128]\n"
        "  str x17, [x28, #" SGS(O_OUT_X) "+136]\n"
        "  add x16, x28, #" SGS(O_OUT_X) "\n"
        "  stp x0, x1, [x16, #0]\n"
        "  stp x2, x3, [x16, #16]\n"
        "  stp x4, x5, [x16, #32]\n"
        "  stp x6, x7, [x16, #48]\n"
        "  stp x8, x9, [x16, #64]\n"
        "  stp x10, x11, [x16, #80]\n"
        "  stp x12, x13, [x16, #96]\n"
        "  stp x14, x15, [x16, #112]\n"
        "  stp x18, x19, [x16, #144]\n"
        "  stp x20, x21, [x16, #160]\n"
        "  stp x22, x23, [x16, #176]\n"
        "  stp x24, x25, [x16, #192]\n"
        "  stp x26, x27, [x16, #208]\n"
        "  str x28, [x16, #224]\n"
        "  stp x29, x30, [x16, #232]\n"
        "  mov x17, sp\n"
        "  str x17, [x28, #" SGS(O_OUT_SP) "]\n"
        "  mrs x17, nzcv\n"
        "  str x17, [x28, #" SGS(O_OUT_NZCV) "]\n"
        "  ldr x17, [x28, #" SGS(O_HAS_DIT) "]\n"
        "  cbz x17, 1f\n"
        "  mrs x17, s3_3_c4_c2_5\n"
        "  str x17, [x28, #" SGS(O_OUT_DIT) "]\n"
        "  msr s3_3_c4_c2_5, xzr\n"
        "1:\n"
        "  add x16, x28, #" SGS(O_OUT_V) "\n"
        "  stp q0, q1, [x16, #0]\n"
        "  stp q2, q3, [x16, #32]\n"
        "  stp q4, q5, [x16, #64]\n"
        "  stp q6, q7, [x16, #96]\n"
        "  stp q8, q9, [x16, #128]\n"
        "  stp q10, q11, [x16, #160]\n"
        "  stp q12, q13, [x16, #192]\n"
        "  stp q14, q15, [x16, #224]\n"
        "  stp q16, q17, [x16, #256]\n"
        "  stp q18, q19, [x16, #288]\n"
        "  stp q20, q21, [x16, #320]\n"
        "  stp q22, q23, [x16, #352]\n"
        "  stp q24, q25, [x16, #384]\n"
        "  stp q26, q27, [x16, #416]\n"
        "  stp q28, q29, [x16, #448]\n"
        "  stp q30, q31, [x16, #480]\n"
        "  ldr x17, [x28, #" SGS(O_HOST_SP) "]\n"
        "  mov sp, x17\n"
        "  str xzr, [x28, #" SGS(O_IN_RUN) "]\n"
        "  ldp x19, x20, [sp, #16]\n"
        "  ldp x21, x22, [sp, #32]\n"
        "  ldp x23, x24, [sp, #48]\n"
        "  ldp x25, x26, [sp, #64]\n"
        "  ldp x27, x28, [sp, #80]\n"
        "  ldp d8, d9, [sp, #96]\n"
        "  ldp d10, d11, [sp, #112]\n"
        "  ldp d12, d13, [sp, #128]\n"
        "  ldp d14, d15, [sp, #144]\n"
        "  ldp x29, x30, [sp], #160\n"
        "  ret\n"
        /* Synchronous: UDF / guard-page load / BRK at a labelled pc.  The
         * continuations record which way the body left in out_cont (x17).
         */
        "a64ps_body_udf:\n" PRELUDE
        ".global a64ps_udf\n"
        "a64ps_udf:\n"
        "  .inst 0x00000051\n" /* udf #0x51 */
        "  b a64ps_next\n"
        "a64ps_body_segv:\n" PRELUDE
        "  ldr x16, [x28, #" SGS(O_AUX2) "]\n"
        ".global a64ps_segv\n"
        "a64ps_segv:\n"
        "  ldr x16, [x16]\n"
        "  b a64ps_next\n"
        "a64ps_body_brk:\n" PRELUDE
        ".global a64ps_brk\n"
        "a64ps_brk:\n"
        "  brk #0x51\n"
        ".global a64ps_next\n"
        "a64ps_next:\n"
        "  mov x17, #0\n"
        "  b a64ps_exit\n"
        ".global a64ps_cont1\n"
        "a64ps_cont1:\n"
        "  mov x17, #1\n"
        "  b a64ps_exit\n"
        ".global a64ps_cont2\n"
        "a64ps_cont2:\n"
        "  mov x17, #2\n"
        "  nop\n"
        "  b a64ps_exit\n"
        "a64ps_exit:\n"
        "  str x17, [x28, #" SGS(O_OUT_CONT) "]\n"
        "  b a64ps_capture\n"
        /* Asynchronous: raised by the block's own svc, or by another source,
         * then the block spins until the handler sets flag0.
         */
        "a64ps_body_self:\n" PRELUDE TGKILL_SELF
        ".global a64ps_self_after\n"
        "a64ps_self_after:\n"
        "  b a64ps_spin\n"
        "a64ps_body_ext:\n" PRELUDE
        ".global a64ps_spin\n"
        "a64ps_spin:\n"
        "  ldr x16, [x28, #" SGS(O_FLAG0) "]\n"
        "  cbz x16, a64ps_spin\n"
        "  b a64ps_next\n"
        /* The same with indirect calls and returns in the loop (IBL churn). */
        "a64ps_body_ispin:\n" PRELUDE
        ".global a64ps_ispin\n"
        "a64ps_ispin:\n"
        "  ldr x16, [x28, #" SGS(O_FLAG0) "]\n"
        "  cbnz x16, a64ps_next\n"
        "  add x17, x17, #1\n"
        "  and x16, x17, #3\n"
        "  add x16, x28, x16, lsl #3\n"
        "  ldr x16, [x16, #" SGS(O_TGT) "]\n"
        "  blr x16\n"
        ".global a64ps_ispin_ret\n"
        "a64ps_ispin_ret:\n"
        "  b a64ps_ispin\n"
        ".global a64ps_tgt0\n"
        "a64ps_tgt0:\n"
        "  ret\n"
        ".global a64ps_tgt1\n"
        "a64ps_tgt1:\n"
        "  nop\n"
        "  ret\n"
        ".global a64ps_tgt2\n"
        "a64ps_tgt2:\n"
        "  b a64ps_tgt0\n"
        ".global a64ps_tgt3\n"
        "a64ps_tgt3:\n"
        "  mov x16, x30\n"
        "  br x16\n"
        ".global a64ps_ispin_end\n"
        "a64ps_ispin_end:\n"
        /* sigprocmask inside the block: block, raise, wait, record the pending
         * set and the handler count so far, unblock, wait for the handler.
         */
        "a64ps_body_mask:\n" PRELUDE SIGPROCMASK(0) TGKILL_SELF
        "  mov x9, #4000\n"
        "1:\n"
        "  sub x9, x9, #1\n"
        "  cbnz x9, 1b\n"
        "  add x0, x28, #" SGS(O_PEND) "\n"
        "  mov x1, #8\n"
        "  mov x8, #136\n"
        "  svc #0\n"
        "  ldr x9, [x28, #" SGS(O_FLAG0) "]\n"
        "  str x9, [x28, #" SGS(O_RESULT) "]\n" SIGPROCMASK(1)
        ".global a64ps_mask_spin\n"
        "a64ps_mask_spin:\n"
        "  ldr x16, [x28, #" SGS(O_FLAG0) "]\n"
        "  cbz x16, a64ps_mask_spin\n"
        "  b a64ps_next\n"
        /* sigaltstack enabled, signal, disabled, signal, queried. */
        "a64ps_body_alt:\n" PRELUDE
        "  add x0, x28, #" SGS(O_SS_ON) "\n"
        "  mov x1, #0\n"
        "  mov x8, #132\n"
        "  svc #0\n" TGKILL_SELF
        ".global a64ps_alt_spin1\n"
        "a64ps_alt_spin1:\n"
        "  ldr x16, [x28, #" SGS(O_FLAG0) "]\n"
        "  cbz x16, a64ps_alt_spin1\n"
        "  add x0, x28, #" SGS(O_SS_OFF) "\n"
        "  mov x1, #0\n"
        "  mov x8, #132\n"
        "  svc #0\n"
        "  str x0, [x28, #" SGS(O_RESULT) "]\n" TGKILL_SELF
        ".global a64ps_alt_spin2\n"
        "a64ps_alt_spin2:\n"
        "  ldr x16, [x28, #" SGS(O_FLAG1) "]\n"
        "  cbz x16, a64ps_alt_spin2\n"
        "  mov x0, #0\n"
        "  add x1, x28, #" SGS(O_SS_Q) "\n"
        "  mov x8, #132\n"
        "  svc #0\n"
        "  b a64ps_next\n"
        /* Real-time payloads: block, queue count entries, record pending,
         * unblock, wait until the handler saw all of them.
         */
        "a64ps_body_rt:\n" PRELUDE SIGPROCMASK(0)
        "  ldr x9, [x28, #" SGS(O_COUNT) "]\n"
        "  add x10, x28, #" SGS(O_RTTAB) "\n"
        "1:\n"
        "  cbz x9, 2f\n"
        "  ldr x0, [x28, #" SGS(O_PID) "]\n"
        "  ldr x1, [x28, #" SGS(O_TID) "]\n"
        "  ldr w2, [x10]\n"
        "  mov x3, x10\n"
        "  mov x8, #240\n"
        "  svc #0\n"
        "  add x10, x10, #128\n"
        "  sub x9, x9, #1\n"
        "  b 1b\n"
        "2:\n"
        "  add x0, x28, #" SGS(O_PEND) "\n"
        "  mov x1, #8\n"
        "  mov x8, #136\n"
        "  svc #0\n" SIGPROCMASK(1)
        ".global a64ps_rt_spin\n"
        "a64ps_rt_spin:\n"
        "  ldr x16, [x28, #" SGS(O_FLAG0) "]\n"
        "  cbz x16, a64ps_rt_spin\n"
        "  b a64ps_next\n"
        /* A blocking read of an empty pipe. */
        "a64ps_body_pipe:\n" PRELUDE
        "  ldr x0, [x28, #" SGS(O_AUX) "]\n"
        "  add x1, x28, #" SGS(O_SCRATCH) "\n"
        "  mov x2, #1\n"
        "  mov x8, #63\n"
        ".global a64ps_pipe_svc\n"
        "a64ps_pipe_svc:\n"
        "  svc #0\n"
        "  str x0, [x28, #" SGS(O_RESULT) "]\n"
        "  b a64ps_next\n"
        /* Called from a handler: tgkill(x0, x1, x2), then wait (at most x4
         * iterations) for *x3 to become nonzero.  Returns {*x3, x5}: a nested
         * handler sets x5 in this context.
         */
        ".global a64ps_raise_wait\n"
        ".type a64ps_raise_wait, %function\n"
        "a64ps_raise_wait:\n"
        "  hint #34\n"
        "  mov x5, #0\n"
        "  mov x6, #0\n"
        "  mov x8, #131\n"
        "  svc #0\n"
        ".global a64ps_rw_after\n"
        "a64ps_rw_after:\n"
        "  ldr x6, [x3]\n"
        "  cbnz x6, 1f\n"
        "  sub x4, x4, #1\n"
        "  cbnz x4, a64ps_rw_after\n"
        "1:\n"
        "  mov x0, x6\n"
        "  mov x1, x5\n"
        "  ret\n"
        ".global a64ps_rw_end\n"
        "a64ps_rw_end:\n"
        ".global a64ps_code_hi\n"
        "a64ps_code_hi:\n"
        ".section .data\n"
        ".p2align 3\n"
        "a64ps_bodies:\n"
        "  .quad a64ps_body_udf, a64ps_body_brk, a64ps_body_self, a64ps_body_ext\n"
        "  .quad a64ps_body_ispin, a64ps_body_mask, a64ps_body_alt, a64ps_body_rt\n"
        "  .quad a64ps_body_pipe, a64ps_body_segv\n"
        ".global a64ps_bodies\n"
        ".text\n");
/* clang-format on */

extern const char a64ps_code_lo[], a64ps_code_hi[], a64ps_udf[], a64ps_brk[],
    a64ps_segv[], a64ps_next[], a64ps_cont1[], a64ps_cont2[], a64ps_self_after[],
    a64ps_spin[], a64ps_ispin[], a64ps_ispin_ret[], a64ps_ispin_end[], a64ps_tgt0[],
    a64ps_tgt1[], a64ps_tgt2[], a64ps_tgt3[], a64ps_mask_spin[], a64ps_alt_spin1[],
    a64ps_alt_spin2[], a64ps_rt_spin[], a64ps_pipe_svc[], a64ps_rw_after[],
    a64ps_rw_end[];
extern const uint64_t a64ps_bodies[];
void
a64ps_run(sgctx_t *ctx);
typedef struct {
    uint64_t flag, mark;
} rw_ret_t;
rw_ret_t
a64ps_raise_wait(uint64_t pid, uint64_t tid, uint64_t sig, volatile uint64_t *flag,
                 uint64_t iters);

#define PC(sym) ((uint64_t)(uintptr_t)(sym))

/***************************************************************************
 * Scenario kinds and their parameters.
 */
enum {
    K_UDF,    /* synchronous SIGILL at a labelled pc */
    K_BRK,    /* synchronous SIGTRAP */
    K_SEGV,   /* synchronous SIGSEGV (guard page): ESR record and fault address */
    K_SELF,   /* raised by the block's svc, then a spin */
    K_EXT,    /* another thread's tgkill/kill, itimer or POSIX timer, during a spin */
    K_NEST,   /* the handler raises a second signal (SA_NODEFER or another one) */
    K_SAMASK, /* sa_mask blocks a signal the handler raises until sigreturn */
    K_MASK,   /* sigprocmask inside the block */
    K_ALT,    /* sigaltstack enabled and disabled inside the block */
    K_RT,     /* real-time payloads and order */
    K_PIPE,   /* blocking read interrupted, SA_RESTART on or off */
    K_ISPIN,  /* external signal into a spin with indirect calls (paths mode) */
    K_NUM
};
static const char *const kind_name[K_NUM] = { "udf", "brk",  "segv",   "self",
                                              "ext", "nest", "samask", "mask",
                                              "alt", "rt",   "pipe",   "ispin" };
/* Index into a64ps_bodies. */
static const int kind_body[K_NUM] = { 0, 1, 9, 2, 3, 2, 2, 5, 6, 7, 8, 4 };

enum { SRC_SELF, SRC_TGKILL, SRC_KILL, SRC_ITIMER, SRC_PTIMER };
static const char *const src_name[] = { "self", "tgkill", "kill", "itimer", "ptimer" };

enum {
    EFF_GPR = 1,
    EFF_NZCV = 2,
    EFF_DIT = 4,
    EFF_PC = 8,
    EFF_SP = 16,
    EFF_V = 32,
};

typedef struct {
    int kind, idx;
    uint64_t seed;
    int sig, sig2, src, restart, nodefer, onstack;
    uint64_t samask; /* extra signals in the handler's sa_mask */
    unsigned eff;
    int gpr, cont, vreg;
    uint64_t gval, nzcv, dit;
    int64_t spdelta;
    __uint128_t vval;
    int nrt, rt_masked;
    int rt_sig[RT_MAX], rt_val[RT_MAX];
    int nexpect; /* rt: deliveries expected */
} sgcase_t;

/* What a run observed: compared between native and DR, and against the model. */
#define NOBS 24
#define NLOG 24
typedef struct {
    int valid; /* the run completed */
    int conclusive;
    uint64_t out_x[31], out_sp, out_nzcv, out_dit, out_cont;
    __uint128_t out_v[32];
    uint64_t layout; /* record layout of the first handler frame */
    int nobs;
    uint64_t obs[NOBS];
    int nlog;
    uint64_t log[NLOG];
} sgres_t;

/***************************************************************************
 * Global run state (the handlers' view of the current case).
 */
typedef struct {
    sgcase_t *c;
    sgres_t *r;
    volatile int running, depth;
    /* The modelled context at the first (and second) interruption. */
    uint64_t mx[31], msp, mnzcv, mdit;
    __uint128_t mv[32];
    uint64_t fpcr;
    int phase, outer_done, nest_phase;
    uint64_t outer_mask;
    int nrt_log;
    /* Failures inside handlers: counted, the first one described. */
    int fails;
    char fail_msg[512];
    long ctx_checked, eff_applied, frames_ok, strays;
    volatile long other_thread;
    int sve_vl, za_vl;
    long native_za_vl;
} sgrun_t;
static sgrun_t g;

static int verbose;
static int g_is_dr;

/* Counters a child reports to the parent through the progress page. */
enum {
    ST_CTX_CHECKED,
    ST_EFF_APPLIED,
    ST_FRAMES_OK,
    ST_STRAYS,
    ST_KD_RT_ORDER, /* known deviation rt-overflow-order (see below) */
};

/* Known deviation rt-overflow-order (2026-10-14): DR queues at most
 * -max_pending_signals (8) signals per thread and hands a further one back to the
 * kernel with rt_tgsigqueueinfo, which puts it behind the later instances of the
 * same real-time signal still pending there; so when more than 8 distinct
 * signals become deliverable at once, one real-time signal's first instance can
 * be delivered after its later ones.  Every payload must still arrive exactly
 * once; the order difference is counted.
 */
#define DR_MAX_PENDING_SIGNALS 8
static int is_debug_build;
static int has_dit;
static pid_t main_tid;
static int pipe_fd[2] = { -1, -1 };

static int
rt_overflow_deviation(const sgcase_t *c)
{
    uint64_t sigs = 0;
    int n = 0;
    for (int i = 0; i < c->nrt; i++) {
        if (!(sigs & (1ULL << c->rt_sig[i])))
            n++;
        sigs |= 1ULL << c->rt_sig[i];
    }
    return g_is_dr && n > DR_MAX_PENDING_SIGNALS;
}

static int sig_pool[8];

static uint64_t
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void
hfail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void
hfail(const char *fmt, ...)
{
    if (g.fails++ == 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(g.fail_msg, sizeof(g.fail_msg), fmt, ap);
        va_end(ap);
    }
}

static void
add_obs(uint64_t v)
{
    if (g.r->nobs < NOBS)
        g.r->obs[g.r->nobs++] = v;
}

/***************************************************************************
 * Case generation.
 */
static const int rt_choices = 8;

static void
gen_case(int kind, int idx, uint64_t seed, sgcase_t *c, int paths)
{
    rng_t r = { seed * 0x2545f4914f6cdd1dULL + (uint64_t)kind * 0x9e3779b97f4a7c15ULL };
    memset(c, 0, sizeof(*c));
    c->kind = kind;
    c->idx = idx;
    c->seed = seed;
    c->sig = sig_pool[rn(&r, 8)];
    do
        c->sig2 = sig_pool[rn(&r, 8)];
    while (c->sig2 == c->sig);
    c->src = SRC_SELF;
    c->onstack = rp(&r, 30);
    c->restart = rp(&r, 50);
    if (kind == K_EXT || kind == K_ISPIN) {
        c->src = SRC_TGKILL + (int)rn(&r, 4);
        if (c->src == SRC_ITIMER)
            c->sig = SIGALRM;
        else if (c->src == SRC_PTIMER)
            c->sig = SIGRTMIN + 9;
    }
    /* Extra signals blocked during the handler (never the ones the case waits for). */
    for (int i = 0; i < 8; i++) {
        if (sig_pool[i] != c->sig && sig_pool[i] != c->sig2 && rp(&r, 30))
            c->samask |= 1ULL << (sig_pool[i] - 1);
    }
    unsigned allowed = EFF_GPR | EFF_NZCV | EFF_DIT | EFF_PC | EFF_SP | EFF_V;
    if (kind == K_ALT || kind == K_PIPE || kind == K_SAMASK)
        allowed &= ~(EFF_PC | EFF_SP);
    if (kind == K_RT)
        allowed = 0;
    for (int b = 1; b <= EFF_V; b <<= 1) {
        if ((allowed & b) && rp(&r, 50))
            c->eff |= b;
    }
    static const int gprs[] = { 3,  4,  5,  6,  7,  9,  10, 11, 12, 13, 14, 15,
                                18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 29, 30 };
    int ng = (int)(sizeof(gprs) / sizeof(gprs[0]));
    if (kind == K_ISPIN)
        ng--; /* x30 is the loop's link register */
    c->gpr = gprs[rn(&r, ng)];
    c->gval = rval(&r);
    c->nzcv = (uint64_t)rn(&r, 16) << 28;
    c->dit = rp(&r, 50) ? PSTATE_DIT : 0;
    c->cont = 1 + (int)rn(&r, 2);
    static const int64_t deltas[] = { -64, -48, -32, -16, 16, 32, 48, 64 };
    c->spdelta = deltas[rn(&r, 8)];
    c->vreg = (int)rn(&r, 32);
    c->vval = ((__uint128_t)rnext(&r) << 64) | rnext(&r);
    c->nodefer = rp(&r, 50);
    if (kind == K_NEST && c->nodefer)
        c->sig2 = c->sig;
    if (kind == K_RT) {
        c->nrt = 3 + (int)rn(&r, RT_MAX - 3);
        c->rt_masked = rp(&r, 60);
        uint64_t std_seen = 0;
        for (int i = 0; i < c->nrt; i++) {
            int k = (int)rn(&r, rt_choices + 2);
            c->rt_sig[i] = k < rt_choices ? SIGRTMIN + 3 + k
                : k == rt_choices         ? SIGUSR1
                                          : SIGUSR2;
            c->rt_val[i] = (int)(rnext(&r) & 0x7fffffff);
            if (c->rt_sig[i] < SIGRTMIN) {
                /* Standard signals do not queue: only one is delivered. */
                if (!(std_seen & (1ULL << c->rt_sig[i])))
                    c->nexpect++;
                std_seen |= 1ULL << c->rt_sig[i];
            } else
                c->nexpect++;
        }
    }
    (void)paths;
}

/***************************************************************************
 * The model.
 */
static int
kind_effects_once(const sgcase_t *c)
{
    return c->kind != K_RT;
}

/* The modelled register state where the case's (first) signal is taken. */
static void
model_first(const sgcase_t *c, sgctx_t *x)
{
    memcpy(g.mx, x->in_x, sizeof(g.mx));
    g.mx[28] = (uint64_t)(uintptr_t)x;
    g.mx[16] = 0;
    g.mx[17] = 1;
    g.msp = x->in_sp - SG_CANARY;
    g.mnzcv = x->in_nzcv;
    g.mdit = x->in_dit;
    memcpy(g.mv, x->in_v, sizeof(g.mv));
    switch (c->kind) {
    case K_SELF:
    case K_NEST:
    case K_SAMASK:
    case K_ALT:
        g.mx[0] = 0;
        g.mx[1] = x->tid;
        g.mx[2] = x->sig;
        g.mx[8] = 131;
        break;
    case K_MASK:
    case K_RT:
        g.mx[0] = 0;
        g.mx[1] = (uint64_t)(uintptr_t)x + O_SET;
        g.mx[2] = 0;
        g.mx[3] = 8;
        g.mx[8] = 135;
        g.mx[9] = 0;
        if (c->kind == K_RT)
            g.mx[10] = (uint64_t)(uintptr_t)x + O_RTTAB + 128ULL * (uint64_t)c->nrt;
        break;
    case K_PIPE:
        g.mx[0] = c->restart ? x->aux : (uint64_t)-EINTR;
        g.mx[1] = (uint64_t)(uintptr_t)x + O_SCRATCH;
        g.mx[2] = 1;
        g.mx[8] = 63;
        break;
    default: break;
    }
}

/* Applies the case's effects to the model (what the handler writes). */
static void
model_apply(const sgcase_t *c)
{
    if (c->eff & EFF_GPR)
        g.mx[c->gpr] = c->gval;
    if (c->eff & EFF_NZCV)
        g.mnzcv = c->nzcv;
    if (c->eff & EFF_DIT)
        g.mdit = c->dit;
    if (c->eff & EFF_SP)
        g.msp += (uint64_t)c->spdelta;
    if (c->eff & EFF_V)
        g.mv[c->vreg] = c->vval;
}

/* Whether pc is where the case's primary signal may be taken. */
static int
pc_allowed(const sgcase_t *c, uint64_t pc, int phase)
{
    switch (c->kind) {
    case K_UDF: return pc == PC(a64ps_udf);
    case K_BRK: return pc == PC(a64ps_brk);
    case K_SEGV: return pc == PC(a64ps_segv);
    case K_SELF:
    case K_NEST:
    case K_SAMASK:
        return pc == PC(a64ps_self_after) || pc == PC(a64ps_spin) ||
            pc == PC(a64ps_spin) + 4;
    case K_EXT: return pc == PC(a64ps_spin) || pc == PC(a64ps_spin) + 4;
    case K_ISPIN: return pc >= PC(a64ps_ispin) && pc < PC(a64ps_ispin_end);
    case K_MASK: return pc == PC(a64ps_mask_spin) || pc == PC(a64ps_mask_spin) + 4;
    case K_ALT: {
        uint64_t s = phase == 0 ? PC(a64ps_alt_spin1) : PC(a64ps_alt_spin2);
        return pc == s || pc == s + 4;
    }
    case K_RT: return pc == PC(a64ps_rt_spin) || pc == PC(a64ps_rt_spin) + 4;
    case K_PIPE: return pc == PC(a64ps_pipe_svc) + (c->restart ? 0 : 4);
    }
    return 0;
}

/* Compares an interrupted context with the model.  x16 and x17 are the spin
 * loops' scratch registers; in the ISPIN loop x30 is its link register.
 */
static void
check_ctx(const char *what, ucontext_t *uc, struct a64p_fpsimd_rec *fp)
{
    const sgcase_t *c = g.c;
    int bad = 0;
    char buf[256];
    buf[0] = '\0';
    for (int i = 0; i < 31; i++) {
        if (i == 16 || i == 17 || (i == 30 && c->kind == K_ISPIN))
            continue;
        if (uc->uc_mcontext.regs[i] != g.mx[i]) {
            if (bad++ == 0) {
                snprintf(buf, sizeof(buf), "x%d 0x%llx, model 0x%llx", i,
                         (unsigned long long)uc->uc_mcontext.regs[i],
                         (unsigned long long)g.mx[i]);
            }
        }
    }
    if (c->kind == K_ISPIN && uc->uc_mcontext.regs[30] != g.mx[30] &&
        uc->uc_mcontext.regs[30] != PC(a64ps_ispin_ret)) {
        if (bad++ == 0) {
            snprintf(buf, sizeof(buf), "x30 0x%llx",
                     (unsigned long long)uc->uc_mcontext.regs[30]);
        }
    }
    if (uc->uc_mcontext.sp != g.msp && bad++ == 0) {
        snprintf(buf, sizeof(buf), "sp 0x%llx, model 0x%llx",
                 (unsigned long long)uc->uc_mcontext.sp, (unsigned long long)g.msp);
    }
    uint64_t ps = uc->uc_mcontext.pstate;
    if ((ps & PSTATE_NZCV) != g.mnzcv && bad++ == 0) {
        snprintf(buf, sizeof(buf), "pstate 0x%llx: nzcv, model 0x%llx",
                 (unsigned long long)ps, (unsigned long long)g.mnzcv);
    }
    if (has_dit && (ps & PSTATE_DIT) != g.mdit && bad++ == 0) {
        snprintf(buf, sizeof(buf), "pstate 0x%llx: DIT, model 0x%llx",
                 (unsigned long long)ps, (unsigned long long)g.mdit);
    }
    if (fp == NULL) {
        if (bad++ == 0)
            snprintf(buf, sizeof(buf), "no FPSIMD record");
    } else {
        for (int i = 0; i < 32; i++) {
            if (fp->v[i] != g.mv[i] && bad++ == 0) {
                snprintf(
                    buf, sizeof(buf), "v%d 0x%016llx%016llx, model 0x%016llx%016llx", i,
                    (unsigned long long)(fp->v[i] >> 64), (unsigned long long)fp->v[i],
                    (unsigned long long)(g.mv[i] >> 64), (unsigned long long)g.mv[i]);
            }
        }
        if (fp->fpcr != (uint32_t)g.fpcr && bad++ == 0)
            snprintf(buf, sizeof(buf), "fpcr 0x%x, host 0x%llx", fp->fpcr,
                     (unsigned long long)g.fpcr);
    }
    if (bad > 0) {
        hfail("%s: interrupted context at pc 0x%llx (+0x%llx) differs from the model in "
              "%d fields; first: %s",
              what, (unsigned long long)uc->uc_mcontext.pc,
              (unsigned long long)(uc->uc_mcontext.pc - PC(a64ps_code_lo)), bad, buf);
    } else
        g.ctx_checked++;
}

/* Writes the case's effects into the frame.  The PC effect is a labelled
 * continuation; the SP effect moves SP within the live stack.
 */
static void
apply_effects(ucontext_t *uc, struct a64p_fpsimd_rec *fp)
{
    const sgcase_t *c = g.c;
    if (c->eff & EFF_GPR)
        uc->uc_mcontext.regs[c->gpr] = c->gval;
    if (c->eff & EFF_NZCV)
        uc->uc_mcontext.pstate = (uc->uc_mcontext.pstate & ~PSTATE_NZCV) | c->nzcv;
    if (has_dit && (c->eff & EFF_DIT))
        uc->uc_mcontext.pstate = (uc->uc_mcontext.pstate & ~PSTATE_DIT) | c->dit;
    if (c->eff & EFF_SP)
        uc->uc_mcontext.sp += (uint64_t)c->spdelta;
    if (c->eff & EFF_PC)
        uc->uc_mcontext.pc = c->cont == 1 ? PC(a64ps_cont1) : PC(a64ps_cont2);
    if ((c->eff & EFF_V) && fp != NULL)
        fp->v[c->vreg] = c->vval;
    g.eff_applied++;
}

/* Validates the frame's records and placement; returns the FPSIMD record. */
static struct a64p_fpsimd_rec *
check_frame(int sig, ucontext_t *uc, int expect_alt)
{
    char err[200];
    uint64_t layout;
    int sve_vl, za_vl;
    if (a64p_check_frame_records(uc, &layout, &sve_vl, &za_vl, err, sizeof(err)) != 0) {
        hfail("signal %d: invalid frame records: %s", sig, err);
        return NULL;
    }
    if (g.native_za_vl > 0 && za_vl != g.native_za_vl)
        hfail("signal %d: ZA record vl %d, PR_SME_GET_VL %ld", sig, za_vl,
              g.native_za_vl);
    if (g.r != NULL && g.r->layout == 0)
        g.r->layout = layout;
    g.sve_vl = sve_vl;
    g.za_vl = za_vl;
    uint64_t f = (uint64_t)(uintptr_t)uc;
    if (expect_alt >= 0) {
        int on_alt = f >= SG_ALT_LO && f < SG_ALT_LO + SG_ALT_SIZE;
        uint64_t isp = uc->uc_mcontext.sp;
        if (expect_alt && !on_alt)
            hfail("signal %d: frame at 0x%llx, not on the alternate stack", sig,
                  (unsigned long long)f);
        else if (!expect_alt && (f >= isp || f < isp - 0x8000))
            hfail("signal %d: frame at 0x%llx, not just below the interrupted sp 0x%llx",
                  sig, (unsigned long long)f, (unsigned long long)isp);
    }
    g.frames_ok++;
    return (struct a64p_fpsimd_rec *)a64p_find_rec(uc, FPSIMD_MAGIC_);
}

static uint64_t
cur_mask(void)
{
    sigset_t s;
    pthread_sigmask(SIG_BLOCK, NULL, &s);
    uint64_t m = 0;
    for (int i = 1; i <= 64; i++) {
        if (sigismember(&s, i))
            m |= 1ULL << (i - 1);
    }
    return m;
}

static uint64_t
uc_mask(ucontext_t *uc)
{
    uint64_t m;
    memcpy(&m, &uc->uc_sigmask, sizeof(m));
    return m;
}

/***************************************************************************
 * Handlers.
 */
static void
h_sync(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    sgcase_t *c = g.c;
    uint64_t pc = uc->uc_mcontext.pc;
    if (!g.running || c == NULL ||
        (c->kind != K_UDF && c->kind != K_BRK && c->kind != K_SEGV)) {
        char buf[160];
        int len = snprintf(buf, sizeof(buf),
                           "a64_prop_signal: unexpected signal %d at pc 0x%llx addr %p\n",
                           sig, (unsigned long long)pc, si->si_addr);
        if (write(2, buf, len) < 0) {
            /* Nothing to do. */
        }
        signal(sig, SIG_DFL);
        return;
    }
    g.depth++;
    struct a64p_fpsimd_rec *fp = check_frame(sig, uc, c->onstack);
    if (!pc_allowed(c, pc, 0) || SG_CTX->flag[0] != 0) {
        hfail("synchronous signal %d at pc 0x%llx (flag %llu)", sig,
              (unsigned long long)pc, (unsigned long long)SG_CTX->flag[0]);
        uc->uc_mcontext.pc = PC(a64ps_next);
    } else {
        check_ctx("sync", uc, fp);
        add_obs((uint64_t)si->si_code);
        add_obs((uint64_t)(uintptr_t)si->si_addr);
        add_obs(uc->uc_mcontext.fault_address);
        struct a64p_esr_rec *er = (struct a64p_esr_rec *)a64p_find_rec(uc, ESR_MAGIC_);
        add_obs(er == NULL ? ~0ULL : er->esr);
        if (c->kind == K_SEGV &&
            ((uint64_t)(uintptr_t)si->si_addr != SG_GUARD || er == NULL ||
             (er->esr >> 26) != 0x24)) {
            hfail("segv: si_addr %p, ESR record %s 0x%llx", si->si_addr,
                  er == NULL ? "missing" : "present",
                  er == NULL ? 0ULL : (unsigned long long)er->esr);
        }
        apply_effects(uc, fp);
        if (!(c->eff & EFF_PC))
            uc->uc_mcontext.pc += 4;
        SG_CTX->flag[0] = 1;
    }
    g.depth--;
}

static void
h_async(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    sgctx_t *x = SG_CTX;
    sgcase_t *c = g.c;
    /* A process-directed signal (kill, itimer) may go to any thread that does
     * not block it, e.g. the helper while glibc's start_thread still runs it
     * with its creator's mask: not the case's.
     */
    if (syscall(SYS_gettid) != main_tid) {
        __atomic_add_fetch(&g.other_thread, 1, __ATOMIC_RELAXED);
        return;
    }
    int depth = ++g.depth;
    uint64_t pc = uc->uc_mcontext.pc;
    /* Outside a64ps_run's span (in_run) the thread runs host code; a signal
     * delivered there (possibly one that arrived in the scenario but whose
     * delivery DR legitimately deferred past its end) is not the case's.
     */
    if (!g.running || c == NULL || (depth == 1 && !x->in_run)) {
        g.strays++;
        goto out;
    }
    int in_code = pc >= PC(a64ps_code_lo) && pc < PC(a64ps_code_hi);
    /* Real-time signals whose handlers do not mask each other nest: the kernel
     * takes the next one at the previous handler's entry.
     */
    int rt_nesting = c->kind == K_RT && !c->rt_masked;
    /* A signal can arrive while a previous handler returns through the vDSO's
     * sigreturn trampoline.
     */
    uint64_t vdso = getauxval(AT_SYSINFO_EHDR);
    int in_vdso = vdso != 0 && pc >= vdso && pc < vdso + 0x10000;
    if (depth == 1 && !in_code && in_vdso) {
        g.strays++;
        goto out;
    }
    if (depth == 1 && !in_code && !rt_nesting) {
        /* While running, the thread only executes the scenario code. */
        Dl_info di;
        int have = dladdr((void *)(uintptr_t)pc, &di) != 0;
        hfail("signal %d: impossible context: pc 0x%llx outside the scenario code "
              "(%s+0x%llx, %s+0x%llx; sp 0x%llx, x30 0x%llx, tid %s, interrupted mask "
              "0x%llx)",
              sig, (unsigned long long)pc,
              have && di.dli_sname != NULL ? di.dli_sname : "?",
              have && di.dli_saddr != NULL
                  ? (unsigned long long)(pc - (uint64_t)(uintptr_t)di.dli_saddr)
                  : 0ULL,
              have && di.dli_fname != NULL ? di.dli_fname : "?",
              have ? (unsigned long long)(pc - (uint64_t)(uintptr_t)di.dli_fbase) : 0ULL,
              (unsigned long long)uc->uc_mcontext.sp,
              (unsigned long long)uc->uc_mcontext.regs[30],
              syscall(SYS_gettid) == main_tid ? "main" : "other",
              (unsigned long long)uc_mask(uc));
        goto out;
    }
    int on_alt_expected = c->onstack;
    switch (c->kind) {
    case K_SELF:
    case K_EXT:
    case K_ISPIN:
    case K_MASK:
    case K_PIPE: {
        if (sig != c->sig || x->flag[0] != 0 || depth != 1) {
            g.strays++;
            break;
        }
        if (!pc_allowed(c, pc, 0)) {
            if (c->kind == K_EXT || c->kind == K_ISPIN) {
                /* Before the block reached its spin (a timer): not the case's signal. */
                g.strays++;
                break;
            }
            hfail(
                "signal %d delivered at pc +0x%llx, where the scenario does not allow it",
                sig, (unsigned long long)(pc - PC(a64ps_code_lo)));
            x->flag[0] = 0xdead;
            break;
        }
        struct a64p_fpsimd_rec *fp = check_frame(sig, uc, on_alt_expected);
        check_ctx(kind_name[c->kind], uc, fp);
        add_obs((uint64_t)si->si_code);
        add_obs(si->si_code == SI_TKILL || si->si_code == SI_USER
                    ? (uint64_t)(si->si_pid == getpid())
                    : 2);
        add_obs(uc_mask(uc));
        if (c->kind == K_PIPE) {
            add_obs(pc - PC(a64ps_pipe_svc));
            add_obs(uc->uc_mcontext.regs[0]);
        }
        apply_effects(uc, fp);
        x->flag[0] = 1;
        break;
    }
    case K_NEST: {
        if (depth == 1 && sig == c->sig && g.nest_phase == 0 && pc_allowed(c, pc, 0)) {
            struct a64p_fpsimd_rec *fp = check_frame(sig, uc, on_alt_expected);
            check_ctx("nest-outer", uc, fp);
            g.outer_mask = cur_mask();
            add_obs(uc_mask(uc));
            add_obs(g.outer_mask);
            g.nest_phase = 1;
            /* The nested signal must arrive while the handler waits for it. */
            rw_ret_t rr = a64ps_raise_wait(x->pid, x->tid, (uint64_t)c->sig2, &x->flag[2],
                                           4000000000ULL);
            g.nest_phase = 2;
            add_obs(rr.flag);
            add_obs(rr.mark);
            if (rr.flag != 1)
                hfail("nest: the nested signal %d was not delivered during the handler",
                      c->sig2);
            else if (rr.mark != 0x5eedf00dULL) {
                hfail("nest: the nested handler's write of x5 was lost (0x%llx)",
                      (unsigned long long)rr.mark);
            }
            apply_effects(uc, fp);
            x->flag[0] = 1;
        } else if (depth == 2 && sig == c->sig2 && g.nest_phase == 1) {
            /* Interrupting a64ps_raise_wait after its svc. */
            struct a64p_fpsimd_rec *fp = check_frame(sig, uc, -1);
            (void)fp;
            if (pc < PC(a64ps_rw_after) || pc >= PC(a64ps_rw_end) ||
                uc->uc_mcontext.regs[3] != (uint64_t)(uintptr_t)&x->flag[2] ||
                uc->uc_mcontext.regs[2] != (uint64_t)c->sig2 ||
                uc->uc_mcontext.regs[8] != 131) {
                hfail("nest: nested context pc +0x%llx x2 %llu x3 0x%llx x8 %llu",
                      (unsigned long long)(pc - PC(a64ps_code_lo)),
                      (unsigned long long)uc->uc_mcontext.regs[2],
                      (unsigned long long)uc->uc_mcontext.regs[3],
                      (unsigned long long)uc->uc_mcontext.regs[8]);
            } else
                g.ctx_checked++;
            add_obs(uc_mask(uc));
            uc->uc_mcontext.regs[5] = 0x5eedf00dULL;
            x->flag[2] = 1;
        } else
            g.strays++;
        break;
    }
    case K_SAMASK: {
        if (depth == 1 && sig == c->sig && !g.outer_done && pc_allowed(c, pc, 0)) {
            struct a64p_fpsimd_rec *fp = check_frame(sig, uc, on_alt_expected);
            check_ctx("samask-outer", uc, fp);
            add_obs(uc_mask(uc));
            add_obs(cur_mask());
            rw_ret_t rr =
                a64ps_raise_wait(x->pid, x->tid, (uint64_t)c->sig2, &x->flag[2], 300000);
            add_obs(rr.flag);
            if (rr.flag != 0)
                hfail("samask: signal %d was delivered although sa_mask blocks it",
                      c->sig2);
            sigset_t p;
            sigpending(&p);
            add_obs((uint64_t)sigismember(&p, c->sig2));
            if (!sigismember(&p, c->sig2))
                hfail("samask: signal %d is not pending in the handler", c->sig2);
            apply_effects(uc, fp);
            model_apply(c);
            g.outer_done = 1;
        } else if (depth == 1 && sig == c->sig2 && g.outer_done && x->flag[0] == 0) {
            if (!pc_allowed(c, pc, 0))
                hfail("samask: signal %d taken at pc +0x%llx after sigreturn", sig,
                      (unsigned long long)(pc - PC(a64ps_code_lo)));
            struct a64p_fpsimd_rec *fp = check_frame(sig, uc, on_alt_expected);
            /* The outer handler's effects are in this context already. */
            check_ctx("samask-after", uc, fp);
            add_obs(uc_mask(uc));
            x->flag[2] = 1;
            x->flag[0] = 1;
        } else if (sig == c->sig2) {
            hfail("samask: signal %d delivered at depth %d before the handler returned",
                  sig, depth);
            x->flag[2] = 1;
        } else
            g.strays++;
        break;
    }
    case K_ALT: {
        if (sig != c->sig || depth != 1 || x->flag[1] != 0) {
            g.strays++;
            break;
        }
        int phase = x->flag[0] == 0 ? 0 : 1;
        if (!pc_allowed(c, pc, phase)) {
            hfail("alt: signal %d (phase %d) at pc +0x%llx", sig, phase,
                  (unsigned long long)(pc - PC(a64ps_code_lo)));
            x->flag[phase] = 0xdead;
            break;
        }
        if (phase == 1) {
            /* The second signal: after the tgkill, with phase 1's effects. */
            g.mx[0] = 0;
            g.mx[1] = x->tid;
            g.mx[2] = x->sig;
            g.mx[8] = 131;
        }
        struct a64p_fpsimd_rec *fp = check_frame(sig, uc, phase == 0);
        check_ctx(phase == 0 ? "alt-on" : "alt-off", uc, fp);
        int local;
        uint64_t la = (uint64_t)(uintptr_t)&local;
        add_obs(la >= SG_ALT_LO && la < SG_ALT_LO + SG_ALT_SIZE);
        add_obs((uint64_t)(uintptr_t)uc->uc_stack.ss_sp);
        add_obs((uint64_t)uc->uc_stack.ss_size);
        add_obs((uint64_t)uc->uc_stack.ss_flags);
        stack_t q;
        sigaltstack(NULL, &q);
        add_obs((uint64_t)q.ss_flags);
        add_obs((uint64_t)(uintptr_t)q.ss_sp);
        if (phase == 0) {
            apply_effects(uc, fp);
            model_apply(c);
            x->flag[0] = 1;
        } else
            x->flag[1] = 1;
        break;
    }
    case K_RT: {
        if (depth == 1 && (in_code || !rt_nesting)) {
            if (!pc_allowed(c, pc, 0)) {
                hfail("rt: signal %d at pc +0x%llx", sig,
                      (unsigned long long)(pc - PC(a64ps_code_lo)));
            } else {
                struct a64p_fpsimd_rec *fp = check_frame(sig, uc, c->onstack);
                check_ctx("rt", uc, fp);
            }
        } else
            check_frame(sig, uc, -1);
        if (g.r->nlog < NLOG) {
            g.r->log[g.r->nlog++] = (uint64_t)sig << 40 |
                (uint64_t)(uint8_t)si->si_code << 32 | (uint32_t)si->si_value.sival_int;
        }
        if (si->si_pid != getpid())
            hfail("rt: signal %d si_pid %d, not %d", sig, si->si_pid, getpid());
        if (++g.nrt_log >= c->nexpect)
            x->flag[0] = 1;
        break;
    }
    default: g.strays++; break;
    }
out:
    g.depth--;
}

/***************************************************************************
 * Helper thread: external signal sources and the watchdog.
 */
enum { H_NONE, H_TGKILL, H_KILL, H_PIPE };
typedef struct {
    volatile int req, done, quit;
    volatile uint64_t deadline;
    volatile int hung;
    int sig, restart;
    pthread_t thr;
} helper_t;
static helper_t hp;

static void
sleep_us(long us)
{
    struct timespec ts = { us / 1000000, (us % 1000000) * 1000 };
    nanosleep(&ts, NULL);
}

/* Whether the main thread is blocked in read(fd). */
static int
main_in_read(int fd)
{
    char path[64], buf[256];
    snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", main_tid);
    int f = open(path, O_RDONLY);
    if (f < 0)
        return 0;
    ssize_t n = read(f, buf, sizeof(buf) - 1);
    close(f);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    unsigned long nr = 0, a0 = 0;
    if (sscanf(buf, "%lu 0x%lx", &nr, &a0) != 2)
        return 0;
    return nr == 63 && a0 == (unsigned long)fd;
}

static void
helper_wake_all(void)
{
    sgctx_t *x = SG_CTX;
    for (int i = 0; i < 4; i++) {
        if (x->flag[i] == 0)
            x->flag[i] = 0xdead;
    }
    if (write(pipe_fd[1], "h", 1) < 0) {
        /* Nothing more we can do. */
    }
}

static void *
helper_main(void *arg)
{
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, NULL);
    sgctx_t *x = SG_CTX;
    while (!hp.quit) {
        int req = __atomic_load_n(&hp.req, __ATOMIC_ACQUIRE);
        if (req != H_NONE && !hp.done) {
            int stage = 0;
            uint64_t last = 0;
            while (!hp.hung) {
                if (now_ns() > hp.deadline) {
                    hp.hung = 1;
                    helper_wake_all();
                    break;
                }
                if (req == H_PIPE) {
                    if (stage == 0 && main_in_read((int)x->aux)) {
                        syscall(SYS_tgkill, getpid(), main_tid, hp.sig);
                        stage = 1;
                    } else if (stage == 1 && x->flag[0] != 0) {
                        if (hp.restart && write(pipe_fd[1], "p", 1) < 0)
                            break;
                        break;
                    }
                    sleep_us(50);
                    continue;
                }
                if (x->flag[0] != 0)
                    break;
                if (x->started && now_ns() - last > 1000000) {
                    last = now_ns();
                    if (req == H_TGKILL)
                        syscall(SYS_tgkill, getpid(), main_tid, hp.sig);
                    else
                        kill(getpid(), hp.sig);
                }
                sleep_us(20);
            }
            __atomic_store_n(&hp.done, 1, __ATOMIC_RELEASE);
        } else if (g.running && now_ns() > hp.deadline && !hp.hung) {
            hp.hung = 1;
            helper_wake_all();
        }
        sleep_us(100);
    }
    return NULL;
}

static void
helper_start(void)
{
    hp.quit = 0;
    hp.req = H_NONE;
    hp.done = 1;
    /* Created with every signal blocked: it never takes the cases' signals. */
    sigset_t all, old;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &old);
    int res = pthread_create(&hp.thr, NULL, helper_main, NULL);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    if (res != 0) {
        fprintf(stderr, "ERROR: cannot create the helper thread\n");
        exit(3);
    }
}

static void
helper_stop(void)
{
    hp.quit = 1;
    pthread_join(hp.thr, NULL);
}

/***************************************************************************
 * Running one case.
 */
static timer_t ptimer;
static int ptimer_ok;

static void
set_handler(int sig, void (*h)(int, siginfo_t *, void *), int flags, uint64_t mask)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = h;
    sa.sa_flags = SA_SIGINFO | flags;
    sigemptyset(&sa.sa_mask);
    for (int i = 1; i <= 64; i++) {
        if (mask & (1ULL << (i - 1)))
            sigaddset(&sa.sa_mask, i);
    }
    if (sigaction(sig, &sa, NULL) != 0) {
        perror("sigaction");
        exit(3);
    }
}

static void
drain_pipe(void)
{
    int n = 0;
    char b[64];
    while (ioctl(pipe_fd[0], FIONREAD, &n) == 0 && n > 0) {
        if (read(pipe_fd[0], b, n > 64 ? 64 : n) <= 0)
            break;
    }
}

static void
setup_ctx(sgcase_t *c)
{
    sgctx_t *x = SG_CTX;
    rng_t r = { c->seed * 0x9e3779b97f4a7c15ULL + 77 + (uint64_t)c->kind };
    memset(x, 0, sizeof(*x));
    for (int i = 0; i < 31; i++)
        x->in_x[i] = rval(&r);
    x->in_x[28] = (uint64_t)(uintptr_t)x;
    for (int i = 0; i < 32; i++)
        x->in_v[i] = ((__uint128_t)rnext(&r) << 64) | rnext(&r);
    x->in_nzcv = (uint64_t)rn(&r, 16) << 28;
    x->in_dit = has_dit && rp(&r, 60) ? PSTATE_DIT : 0;
    x->in_sp = SG_STK_TOP - 0x100 - 16 * rn(&r, 8);
    x->body = a64ps_bodies[kind_body[c->kind]];
    x->has_dit = has_dit;
    x->pid = (uint64_t)getpid();
    x->tid = (uint64_t)main_tid;
    x->sig = (uint64_t)c->sig;
    x->aux = (uint64_t)pipe_fd[0];
    x->aux2 = SG_GUARD;
    x->tgt[0] = PC(a64ps_tgt0);
    x->tgt[1] = PC(a64ps_tgt1);
    x->tgt[2] = PC(a64ps_tgt2);
    x->tgt[3] = PC(a64ps_tgt3);
    x->set = 1ULL << (c->sig - 1);
    if (c->kind == K_RT) {
        x->set = 0;
        x->count = (uint64_t)c->nrt;
        for (int i = 0; i < c->nrt; i++) {
            siginfo_t *si = (siginfo_t *)x->rttab[i];
            memset(si, 0, 128);
            si->si_signo = c->rt_sig[i];
            si->si_code = SI_QUEUE;
            si->si_pid = getpid();
            si->si_uid = getuid();
            si->si_value.sival_int = c->rt_val[i];
            x->set |= 1ULL << (c->rt_sig[i] - 1);
        }
    }
    x->ss_on.ss_sp = (void *)SG_ALT_LO;
    x->ss_on.ss_size = SG_ALT_SIZE - 16 * rn(&r, 64);
    x->ss_on.ss_flags = 0;
    x->ss_off.ss_flags = SS_DISABLE;
}

/* Runs case c, filling res.  Returns the number of property failures. */
static int
run_case(sgcase_t *c, sgres_t *res)
{
    sgctx_t *x = SG_CTX;
    memset(res, 0, sizeof(*res));
    setup_ctx(c);
    memset(&g.mx, 0, sizeof(g) - offsetof(sgrun_t, mx));
    g.c = c;
    g.r = res;
    __asm__ volatile("mrs %0, fpcr" : "=r"(g.fpcr));
    model_first(c, x);
    g.native_za_vl =
        (getauxval(AT_HWCAP2) & HWCAP2_SME) ? (long)(prctl(PR_SME_GET_VL) & 0xffff) : -1;

    /* Handlers. */
    int flags = SA_RESTART;
    if (c->kind == K_PIPE)
        flags = c->restart ? SA_RESTART : 0;
    if (c->onstack || c->kind == K_ALT)
        flags |= SA_ONSTACK;
    if (c->kind == K_UDF || c->kind == K_BRK || c->kind == K_SEGV) {
        set_handler(c->kind == K_UDF       ? SIGILL
                        : c->kind == K_BRK ? SIGTRAP
                                           : SIGSEGV,
                    h_sync, flags | (c->nodefer ? SA_NODEFER : 0), c->samask);
    } else if (c->kind == K_NEST) {
        set_handler(c->sig, h_async, flags | (c->nodefer ? SA_NODEFER : 0), c->samask);
        if (c->sig2 != c->sig)
            set_handler(c->sig2, h_async, flags, c->samask);
    } else if (c->kind == K_SAMASK) {
        set_handler(c->sig, h_async, flags, c->samask | 1ULL << (c->sig2 - 1));
        set_handler(c->sig2, h_async, flags, c->samask);
    } else if (c->kind == K_RT) {
        uint64_t all = SG_CTX->set;
        for (int i = 0; i < c->nrt; i++)
            set_handler(c->rt_sig[i], h_async, flags, c->rt_masked ? all : 0);
    } else
        set_handler(c->sig, h_async, flags, c->samask);

    /* Alternate stack before the run. */
    stack_t ss;
    if (c->onstack && c->kind != K_ALT) {
        ss.ss_sp = (void *)SG_ALT_LO;
        ss.ss_size = SG_ALT_SIZE;
        ss.ss_flags = 0;
    } else {
        ss.ss_sp = NULL;
        ss.ss_size = 0;
        ss.ss_flags = SS_DISABLE;
    }
    if (sigaltstack(&ss, NULL) != 0) {
        perror("sigaltstack");
        exit(3);
    }
    sigset_t none;
    sigemptyset(&none);
    pthread_sigmask(SIG_SETMASK, &none, NULL);
    drain_pipe();

    /* Sources. */
    hp.deadline = now_ns() + 4000000000ULL;
    hp.hung = 0;
    hp.sig = c->sig;
    hp.restart = c->restart;
    if (c->src == SRC_ITIMER) {
        struct itimerval it = { { 0, 400 }, { 0, 400 } };
        setitimer(ITIMER_REAL, &it, NULL);
    } else if (c->src == SRC_PTIMER) {
        struct itimerspec its = { { 0, 300000 }, { 0, 300000 } };
        if (!ptimer_ok || timer_settime(ptimer, 0, &its, NULL) != 0) {
            fprintf(stderr, "ERROR: POSIX timer unavailable\n");
            exit(3);
        }
    }
    int req = c->kind == K_PIPE ? H_PIPE
        : c->src == SRC_TGKILL  ? H_TGKILL
        : c->src == SRC_KILL    ? H_KILL
                                : H_NONE;
    hp.done = 0;
    __atomic_store_n(&hp.req, req, __ATOMIC_RELEASE);

    a64p_prog->block = c->idx;
    a64p_prog->seed = c->seed;
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "case %d %s", c->idx,
             kind_name[c->kind]);
    g.running = 1;
    a64ps_run(x);
    g.running = 0;

    if (c->src == SRC_ITIMER) {
        struct itimerval it;
        memset(&it, 0, sizeof(it));
        setitimer(ITIMER_REAL, &it, NULL);
    } else if (c->src == SRC_PTIMER) {
        struct itimerspec its;
        memset(&its, 0, sizeof(its));
        timer_settime(ptimer, 0, &its, NULL);
    }
    if (req != H_NONE) {
        while (!__atomic_load_n(&hp.done, __ATOMIC_ACQUIRE))
            sleep_us(50);
    }
    __atomic_store_n(&hp.req, H_NONE, __ATOMIC_RELEASE);
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, NULL);

    /* Results. */
    int fails = g.fails;
    char why[640];
    snprintf(why, sizeof(why), "%s", g.fail_msg);
    if (hp.hung) {
        fails++;
        snprintf(
            why, sizeof(why),
            "HANG: the case did not finish within 4 s (flags %llx %llx %llx, started "
            "%llu, result %lld)%s%s",
            (unsigned long long)x->flag[0], (unsigned long long)x->flag[1],
            (unsigned long long)x->flag[2], (unsigned long long)x->started,
            (long long)x->result, g.fails ? "; first: " : "", g.fail_msg);
    }
    res->valid = 1;
    res->conclusive = 1;
    memcpy(res->out_x, x->out_x, sizeof(res->out_x));
    res->out_sp = x->out_sp;
    res->out_nzcv = x->out_nzcv & PSTATE_NZCV;
    res->out_dit = x->out_dit;
    res->out_cont = x->out_cont;
    memcpy(res->out_v, x->out_v, sizeof(res->out_v));
    add_obs((uint64_t)x->result);
    add_obs(x->pend);
    if (c->kind == K_ALT) {
        add_obs((uint64_t)(uintptr_t)x->ss_q.ss_sp);
        add_obs((uint64_t)x->ss_q.ss_flags);
        add_obs((uint64_t)x->ss_q.ss_size);
    }

    /* The model of the final state. */
    if (!hp.hung) {
        char buf[256];
        int bad = 0;
        if (c->kind != K_SAMASK && c->kind != K_ALT && kind_effects_once(c))
            model_apply(c);
        if (c->kind == K_ALT) {
            g.mx[0] = 0;
            g.mx[1] = (uint64_t)(uintptr_t)x + O_SS_Q;
            g.mx[2] = x->sig;
            g.mx[8] = 132;
        } else if (c->kind == K_PIPE)
            g.mx[0] = c->restart ? 1 : (uint64_t)-EINTR;
        uint64_t cont = (c->eff & EFF_PC) ? (uint64_t)c->cont : 0;
        buf[0] = '\0';
        for (int i = 0; i < 31; i++) {
            if (i == 16 || (i == 30 && c->kind == K_ISPIN))
                continue;
            uint64_t want = i == 17 ? cont : g.mx[i];
            if (res->out_x[i] != want && bad++ == 0) {
                snprintf(buf, sizeof(buf), "x%d 0x%llx, model 0x%llx", i,
                         (unsigned long long)res->out_x[i], (unsigned long long)want);
            }
        }
        if (res->out_sp != g.msp && bad++ == 0) {
            snprintf(buf, sizeof(buf), "sp 0x%llx, model 0x%llx",
                     (unsigned long long)res->out_sp, (unsigned long long)g.msp);
        }
        if (res->out_nzcv != g.mnzcv && bad++ == 0) {
            snprintf(buf, sizeof(buf), "nzcv 0x%llx, model 0x%llx",
                     (unsigned long long)res->out_nzcv, (unsigned long long)g.mnzcv);
        }
        if (has_dit && res->out_dit != g.mdit && bad++ == 0) {
            snprintf(buf, sizeof(buf), "DIT 0x%llx, model 0x%llx",
                     (unsigned long long)res->out_dit, (unsigned long long)g.mdit);
        }
        if (res->out_cont != cont && bad++ == 0) {
            snprintf(buf, sizeof(buf), "continuation %llu, model %llu",
                     (unsigned long long)res->out_cont, (unsigned long long)cont);
        }
        for (int i = 0; i < 32; i++) {
            if (res->out_v[i] != g.mv[i] && bad++ == 0)
                snprintf(buf, sizeof(buf), "v%d differs from the model", i);
        }
        /* Live stack above the final SP: the canaries. */
        uint64_t lo = x->in_sp - SG_CANARY;
        if (g.msp > lo)
            lo = g.msp;
        for (uint64_t a = lo; a < x->in_sp; a += 8) {
            uint64_t want = x->in_x[(a - (x->in_sp - SG_CANARY)) / 8];
            if (*(uint64_t *)a != want && bad++ == 0) {
                snprintf(buf, sizeof(buf),
                         "live stack word at 0x%llx: 0x%llx, canary 0x%llx",
                         (unsigned long long)a, (unsigned long long)*(uint64_t *)a,
                         (unsigned long long)want);
            }
        }
        /* Scenario-specific expectations. */
        if (c->kind == K_MASK) {
            if (x->result != 0 && bad++ == 0)
                snprintf(buf, sizeof(buf), "handler ran %lld times while blocked",
                         (long long)x->result);
            if (!(x->pend & (1ULL << (c->sig - 1))) && bad++ == 0)
                snprintf(buf, sizeof(buf), "blocked signal not pending (0x%llx)",
                         (unsigned long long)x->pend);
        } else if (c->kind == K_RT) {
            if (x->pend != x->set && bad++ == 0)
                snprintf(buf, sizeof(buf), "pending 0x%llx, queued 0x%llx",
                         (unsigned long long)x->pend, (unsigned long long)x->set);
            if (res->nlog != c->nexpect && bad++ == 0)
                snprintf(buf, sizeof(buf), "%d deliveries, expected %d", res->nlog,
                         c->nexpect);
            /* Each payload once (strict); per signal in queue order and, with
             * the handlers masking each other, lowest signal first (the order;
             * see the rt-overflow-order known deviation).
             */
            int used[RT_MAX];
            memset(used, 0, sizeof(used));
            int prev_sig = 0, order_bad = 0;
            char obuf[128];
            obuf[0] = '\0';
            for (int k = 0; k < res->nlog; k++) {
                int s = (int)(res->log[k] >> 40);
                uint32_t v = (uint32_t)res->log[k];
                int found = -1, first = -1;
                for (int i = 0; i < c->nrt; i++) {
                    if (c->rt_sig[i] != s || used[i])
                        continue;
                    if (first < 0)
                        first = i;
                    if (found < 0 && (s < SIGRTMIN || (uint32_t)c->rt_val[i] == v))
                        found = i;
                }
                if (found < 0) {
                    if (bad++ == 0)
                        snprintf(buf, sizeof(buf), "delivery %d: signal %d value %u", k,
                                 s, v);
                    break;
                }
                if (found != first && order_bad++ == 0) {
                    snprintf(obuf, sizeof(obuf),
                             "delivery %d: signal %d value %u ahead of earlier %u", k, s,
                             v, (unsigned)c->rt_val[first]);
                }
                used[found] = 1;
                if (s < SIGRTMIN) {
                    /* Coalesced: consume every queued instance. */
                    for (int i = 0; i < c->nrt; i++) {
                        if (c->rt_sig[i] == s)
                            used[i] = 1;
                    }
                }
                if (c->rt_masked && s < prev_sig && order_bad++ == 0) {
                    snprintf(obuf, sizeof(obuf), "signal %d delivered after %d", s,
                             prev_sig);
                }
                prev_sig = s;
            }
            if (order_bad > 0) {
                if (rt_overflow_deviation(c)) {
                    a64p_prog->stat[ST_KD_RT_ORDER]++;
                    if (verbose)
                        fprintf(stderr,
                                "  case %d: known deviation rt-overflow-order: %s\n",
                                c->idx, obuf);
                } else if (bad++ == 0)
                    snprintf(buf, sizeof(buf), "%s", obuf);
            }
        } else if (c->kind == K_PIPE) {
            int64_t want = c->restart ? 1 : -EINTR;
            if (x->result != want && bad++ == 0)
                snprintf(buf, sizeof(buf), "read returned %lld, expected %lld",
                         (long long)x->result, (long long)want);
        } else if (c->kind == K_ALT) {
            if (x->result != 0 && bad++ == 0)
                snprintf(buf, sizeof(buf), "disabling the altstack returned %lld",
                         (long long)x->result);
            if (x->ss_q.ss_flags != SS_DISABLE && bad++ == 0)
                snprintf(buf, sizeof(buf), "final sigaltstack flags %d",
                         x->ss_q.ss_flags);
        }
        if (g.eff_applied == 0 && kind_effects_once(c) && bad++ == 0)
            snprintf(buf, sizeof(buf), "the handler never applied its effects");
        if (bad > 0) {
            fails++;
            if (why[0] == '\0') {
                snprintf(why, sizeof(why),
                         "final state differs from the model in %d fields; "
                         "first: %s",
                         bad, buf);
            }
        }
    }
    if (fails > 0) {
        fprintf(stderr, "  case %d (%s, seed %llu): %s\n", c->idx, kind_name[c->kind],
                (unsigned long long)c->seed, why);
    }
    /* The native and DR runs are different processes: compare the thread id a
     * register holds (after a tgkill) as a token.
     */
    for (int i = 0; i < 31; i++) {
        if (res->out_x[i] == x->tid)
            res->out_x[i] = 0x7d7d7d7dULL;
    }
    a64p_prog->stat[ST_CTX_CHECKED] += g.ctx_checked;
    a64p_prog->stat[ST_EFF_APPLIED] += g.eff_applied;
    a64p_prog->stat[ST_FRAMES_OK] += g.frames_ok;
    a64p_prog->stat[ST_STRAYS] += g.strays + g.other_thread;
    g.c = NULL;
    return fails;
}

static void
print_case(FILE *o, const sgcase_t *c)
{
    fprintf(
        o,
        "    case %d kind %s seed %llu sig %d sig2 %d src %s restart %d nodefer %d "
        "onstack %d samask 0x%llx eff 0x%x gpr x%d=0x%llx nzcv 0x%llx dit 0x%llx cont "
        "%d sp%+lld v%d nrt %d masked %d\n",
        c->idx, kind_name[c->kind], (unsigned long long)c->seed, c->sig, c->sig2,
        src_name[c->src], c->restart, c->nodefer, c->onstack,
        (unsigned long long)c->samask, c->eff, c->gpr, (unsigned long long)c->gval,
        (unsigned long long)c->nzcv, (unsigned long long)c->dit, c->cont,
        (long long)c->spdelta, c->vreg, c->nrt, c->rt_masked);
    if (c->kind == K_RT) {
        fprintf(o, "      queued:");
        for (int i = 0; i < c->nrt; i++)
            fprintf(o, " %d:%u", c->rt_sig[i], (unsigned)c->rt_val[i]);
        fprintf(o, "\n");
    }
}

static void
print_log(FILE *o, const char *who, const sgres_t *r)
{
    fprintf(o, "      %s deliveries:", who);
    for (int i = 0; i < r->nlog; i++)
        fprintf(o, " %d:%u", (int)(r->log[i] >> 40), (unsigned)(uint32_t)r->log[i]);
    fprintf(o, "\n");
}

/* Native vs DR: everything the scenario determines. */
static int
cmp_res(const sgcase_t *c, const sgres_t *n, const sgres_t *d)
{
    int bad = 0;
    char buf[256];
    buf[0] = '\0';
    for (int i = 0; i < 31; i++) {
        if (i == 16 || (c->kind == K_ISPIN && i == 30))
            continue;
        if (n->out_x[i] != d->out_x[i] && bad++ == 0)
            snprintf(buf, sizeof(buf), "x%d native 0x%llx dr 0x%llx", i,
                     (unsigned long long)n->out_x[i], (unsigned long long)d->out_x[i]);
    }
#define RC(f)                                                             \
    do {                                                                  \
        if (n->f != d->f && bad++ == 0)                                   \
            snprintf(buf, sizeof(buf), #f " native 0x%llx dr 0x%llx",     \
                     (unsigned long long)n->f, (unsigned long long)d->f); \
    } while (0)
    RC(out_sp);
    RC(out_nzcv);
    RC(out_dit);
    RC(out_cont);
    RC(layout);
    RC(nobs);
    RC(nlog);
#undef RC
    if (memcmp(n->out_v, d->out_v, sizeof(n->out_v)) != 0 && bad++ == 0)
        snprintf(buf, sizeof(buf), "V registers differ");
    for (int i = 0; i < n->nobs && i < d->nobs; i++) {
        if (n->obs[i] != d->obs[i] && bad++ == 0)
            snprintf(buf, sizeof(buf), "observation %d native 0x%llx dr 0x%llx", i,
                     (unsigned long long)n->obs[i], (unsigned long long)d->obs[i]);
    }
    if (c->kind == K_RT) {
        /* With nesting allowed, only per-signal order is determined (checked
         * against the model); with masking handlers the whole order is.
         */
        for (int i = 0;
             c->rt_masked && !rt_overflow_deviation(c) && i < n->nlog && i < d->nlog;
             i++) {
            if (n->log[i] != d->log[i] && bad++ == 0)
                snprintf(buf, sizeof(buf), "delivery %d native 0x%llx dr 0x%llx", i,
                         (unsigned long long)n->log[i], (unsigned long long)d->log[i]);
        }
    }
    if (bad > 0) {
        fprintf(stderr,
                "  case %d (%s): DR differs from native in %d fields; first: %s\n",
                c->idx, kind_name[c->kind], bad, buf);
    }
    if (c->kind == K_RT && (bad > 0 || verbose)) {
        print_log(stderr, "native", n);
        print_log(stderr, "dr", d);
    }
    return bad;
}

/***************************************************************************
 * In-process client (paths mode).
 */
static int g_instr_on;
static int g_cleancall_all;
static volatile uint64_t g_dyn_count;
static volatile uint64_t g_cc_count;
static uint64_t g_instr_seed = 0x5157;

static void
cc_callee(uint64_t pc, uint64_t val)
{
    /* Clobbers caller-saved GPRs and vector registers as a C callee may. */
    g_cc_count += pc ^ val;
    __asm__ volatile("movi v0.16b, #0x5a\n"
                     "movi v1.16b, #0xa5\n"
                     "movi v7.16b, #0x11\n"
                     "movi v16.16b, #0x22\n"
                     "movi v31.16b, #0x33\n"
                     "mov x9, #0x1234\n"
                     "mov x15, #0x5678\n"
                     :
                     :
                     : "v0", "v1", "v7", "v16", "v31", "x9", "x15", "memory");
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
    uint64_t pc = (uint64_t)(uintptr_t)instr_get_app_pc(inst);
    if (pc < PC(a64ps_code_lo) || pc >= PC(a64ps_code_hi))
        return DR_EMIT_DEFAULT;
    /* Deterministic per pc, so translation re-creates identical code. */
    rng_t r = { g_instr_seed ^ (pc * 0x9e3779b97f4a7c15ULL) };
    drx_insert_counter_update(dc, bb, inst, (dr_spill_slot_t)(SPILL_SLOT_MAX + 1),
                              (dr_spill_slot_t)(SPILL_SLOT_MAX + 1), (void *)&g_dyn_count,
                              1, DRX_COUNTER_64BIT);
    if (rp(&r, 60)) {
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
    if (g_cleancall_all || rp(&r, 25)) {
        int reg = (int)rn(&r, 31);
        dr_insert_clean_call(dc, bb, inst, (void *)cc_callee, false, 2,
                             OPND_CREATE_INTPTR(pc), opnd_create_reg(DR_REG_X0 + reg));
    }
    return DR_EMIT_DEFAULT;
}

static void
client_exit(void)
{
    drx_exit();
    drreg_exit();
    drmgr_exit();
}

static int g_dr_itimer;
static void
dr_itimer_cb(void *drcontext, dr_mcontext_t *mc);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    if (g_dr_itimer) {
        /* DR then multiplexes each kernel timer between itself and the app. */
        if (!dr_set_itimer(ITIMER_REAL, 3, dr_itimer_cb) ||
            !dr_set_itimer(ITIMER_VIRTUAL, 4, dr_itimer_cb) ||
            !dr_set_itimer(ITIMER_PROF, 5, dr_itimer_cb))
            DR_ASSERT(false);
    }
    if (!g_instr_on)
        return;
    /* Conservative, so that every interrupted context is exactly the app's. */
    drreg_options_t ops = { sizeof(ops), 3, true };
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drx_init())
        DR_ASSERT(false);
    drmgr_register_bb_instrumentation_event(NULL, event_insert, NULL);
    dr_register_exit_event(client_exit);
}

/***************************************************************************
 * Driving the cases.
 */
typedef struct {
    const variant_t *v; /* NULL: native */
    int instr, cleancall_all;
    int ncases;
    sgcase_t *cases;
    sgres_t *native; /* shared with the parent */
    long *stats;     /* shared: per kind generated/executed/checked/inconclusive */
} batch_t;

enum { ST_EXEC, ST_CHECKED, ST_INCONCL, ST_NUM_PER_KIND };

static void
child_setup(void)
{
    main_tid = (pid_t)syscall(SYS_gettid);
    if (pipe(pipe_fd) != 0) {
        perror("pipe");
        exit(3);
    }
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = SIGRTMIN + 9;
    sev._sigev_un._tid = main_tid;
    ptimer_ok = timer_create(CLOCK_MONOTONIC, &sev, &ptimer) == 0;
    /* Every signal a case may use has a handler, so a late one is harmless. */
    for (int i = 0; i < 8; i++)
        set_handler(sig_pool[i], h_async, SA_RESTART, 0);
    set_handler(SIGALRM, h_async, SA_RESTART, 0);
    set_handler(SIGRTMIN + 9, h_async, SA_RESTART, 0);
    for (int i = 0; i < 8; i++)
        set_handler(SIGRTMIN + 3 + i, h_async, SA_RESTART, 0);
    helper_start();
}

static void
child_teardown(void)
{
    helper_stop();
    if (ptimer_ok)
        timer_delete(ptimer);
    close(pipe_fd[0]);
    close(pipe_fd[1]);
}

static int
batch_child(void *arg)
{
    batch_t *b = (batch_t *)arg;
    int fails = 0;
    sgres_t *res = malloc(sizeof(*res));
    g_is_dr = b->v != NULL;
    if (b->v != NULL) {
        g_instr_on = b->instr;
        g_cleancall_all = b->cleancall_all || getenv("A64_DR_PROP_CLEANCALL") != NULL;
        snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "dr start");
        a64p_start_dr(b->v->dr_ops);
    }
    child_setup();
    for (int i = 0; i < b->ncases; i++) {
        sgcase_t *c = &b->cases[i];
        int f = run_case(c, res);
        long *st = &b->stats[c->kind * ST_NUM_PER_KIND];
        st[ST_EXEC]++;
        if (b->v == NULL) {
            b->native[i] = *res;
            if (f > 0) {
                fprintf(stderr, "FAIL [native] the oracle itself fails:\n");
                print_case(stderr, c);
                b->native[i].valid = 0;
                st[ST_INCONCL]++;
            } else
                st[ST_CHECKED]++;
        } else {
            if (!b->native[i].valid) {
                st[ST_INCONCL]++;
                continue;
            }
            f += cmp_res(c, &b->native[i], res);
            if (f > 0) {
                fprintf(stderr, "FAIL [%s] variant=%s%s:\n", kind_name[c->kind],
                        b->v->name, b->instr ? " +client" : "");
                print_case(stderr, c);
            } else
                st[ST_CHECKED]++;
        }
        fails += f;
    }
    child_teardown();
    if (b->v != NULL) {
        snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "dr stop");
        a64p_stop_dr();
    }
    free(res);
    return fails;
}

/***************************************************************************
 * The storm: threads exiting while signals are in flight.
 */
#define STORM_Q 24
/* Known issue memcache-check-race (2026-10-14, pre-existing on master
 * 909601994): under thread churn, a debug DR's level-2 consistency check in
 * memcache_query_memory() (core/unix/memcache.c:383, "found") intermittently
 * finds a region in its memory cache that /proc/self/maps does not have, and
 * kills the process (about half of "storm -rounds 40" runs against a debug DR,
 * with the -checklevel default).  The storm checks signal delivery, so it runs
 * with level-1 checks; "A64P_STORM_DEBUG_OPS= a64_prop_signal storm" reproduces
 * the failure.
 */
#define STORM_DEBUG_DR_OPS                                                   \
    (getenv("A64P_STORM_DEBUG_OPS") != NULL ? getenv("A64P_STORM_DEBUG_OPS") \
                                            : "-checklevel 1")
/* Threads (the main one included) blocked in read()/ppoll() of their own empty
 * pipe, each interrupted by its own SIGEV_THREAD_ID timer.
 */
#define STORM_WAITERS 4
typedef struct {
    volatile long weintr[STORM_WAITERS];
    volatile pid_t wtid[STORM_WAITERS];
    volatile long eintr, t3_acct, t2_notify, q_dup, q_seen_n;
    volatile long churn_live, t2_inflight;
    volatile uint8_t q_seen[STORM_Q + 1];
    volatile int round_over, sender_done, churn_on;
    volatile long lost, hang;
    uint64_t t1_period_ns, t3_period_ns;
} storm_t;
static storm_t st;
static int sig_t1, sig_t3, sig_q;
static timer_t storm_timers[3];
/* -churn_max: live churn threads (default 8). */
static long storm_churn_max = 8;
/* -waiters N (1..STORM_WAITERS), -poker 0|1. */
static int storm_waiters = STORM_WAITERS, storm_poker = 1;
static int wpipe[STORM_WAITERS][2];
static timer_t wtimer[STORM_WAITERS];
static volatile int wtimer_ok[STORM_WAITERS];
static __thread int my_waiter = -1;

static void
h_t1(int sig, siginfo_t *si, void *uc)
{
    /* Thread-directed: only a waiter may get its timer's signal (the poker can
     * race with a waiter's exit).
     */
    if (my_waiter < 0 && si->si_code == SI_TIMER)
        __atomic_add_fetch(&st.lost, 1000, __ATOMIC_RELAXED);
}

static void
storm_stop_timers(void)
{
    struct itimerspec zero;
    memset(&zero, 0, sizeof(zero));
    for (int i = 0; i < 3; i++)
        timer_settime(storm_timers[i], 0, &zero, NULL);
    for (int w = 0; w < STORM_WAITERS; w++) {
        if (wtimer_ok[w])
            timer_settime(wtimer[w], 0, &zero, NULL);
    }
}

static void
storm_wake_waiters(void)
{
    for (int w = 0; w < STORM_WAITERS; w++) {
        if (write(wpipe[w][1], "e", 1) < 0) {
            /* The waiter will be reported as hung. */
        }
    }
}

/* Waits in read() or an unbounded ppoll() of its pipe, interrupted by its own
 * timer, until the pipe gets a byte.  The ppoll is issued by DR from its
 * syscall gencode after delivering pending signals: the path of "Deliver a
 * signal that arrives on the way into a syscall before it".
 */
static void
waiter_loop(int w)
{
    my_waiter = w;
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = sig_t1;
    sev._sigev_un._tid = (pid_t)syscall(SYS_gettid);
    st.wtid[w] = sev._sigev_un._tid;
    if (timer_create(CLOCK_MONOTONIC, &sev, &wtimer[w]) != 0) {
        fprintf(stderr, "ERROR: storm: timer_create failed\n");
        exit(3);
    }
    long period = (long)st.t1_period_ns * (2 + w) / 2;
    struct itimerspec it = { { 0, period }, { 0, period } };
    timer_settime(wtimer[w], 0, &it, NULL);
    wtimer_ok[w] = 1;
    char b;
    for (int iter = 0;; iter++) {
        ssize_t n;
        if ((iter + w) % 2 == 0)
            n = read(wpipe[w][0], &b, 1);
        else {
            struct pollfd pfd = { wpipe[w][0], POLLIN, 0 };
            n = syscall(SYS_ppoll, &pfd, 1, NULL, NULL, 0);
            if (n == 1)
                n = read(wpipe[w][0], &b, 1);
        }
        if (n == 1)
            break;
        if (n < 0 && errno == EINTR)
            __atomic_add_fetch(&st.weintr[w], 1, __ATOMIC_RELAXED);
        else {
            fprintf(stderr, "  storm: waiter %d: read returned %zd errno %d\n", w, n,
                    errno);
            st.hang++;
            break;
        }
    }
    st.wtid[w] = 0;
    wtimer_ok[w] = 0;
    timer_delete(wtimer[w]);
    my_waiter = -1;
}

/* Sends the waiters' signal at random moments, so that some arrive while a
 * waiter is on its way into a syscall (the timers' signals arrive a fixed
 * delay after the waiter re-entered its wait).
 */
static void *
poker_main(void *arg)
{
    rng_t r = { (uint64_t)(uintptr_t)arg };
    while (!st.round_over) {
        int w = (int)rn(&r, (uint32_t)storm_waiters);
        pid_t t = st.wtid[w];
        if (t != 0 && st.weintr[w] > 0)
            syscall(SYS_tgkill, getpid(), t, sig_t1);
        for (volatile int i = (int)rn(&r, 20000); i > 0; i--)
            ;
    }
    return NULL;
}

static void *
waiter_thread(void *arg)
{
    sigset_t none;
    sigemptyset(&none);
    pthread_sigmask(SIG_SETMASK, &none, NULL);
    waiter_loop((int)(uintptr_t)arg);
    return NULL;
}

static void
h_t3(int sig, siginfo_t *si, void *uc)
{
    __atomic_add_fetch(&st.t3_acct, 1 + si->si_overrun, __ATOMIC_RELAXED);
}

static void
h_q(int sig, siginfo_t *si, void *uc)
{
    int v = si->si_value.sival_int;
    if (v < 1 || v > STORM_Q)
        return;
    if (st.q_seen[v])
        __atomic_add_fetch(&st.q_dup, 1, __ATOMIC_RELAXED);
    st.q_seen[v] = 1;
    __atomic_add_fetch(&st.q_seen_n, 1, __ATOMIC_RELEASE);
}

static void
t2_notify(union sigval v)
{
    __atomic_add_fetch(&st.t2_inflight, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&st.t2_notify, 1, __ATOMIC_RELAXED);
    /* A little work while signals arrive, then the thread exits. */
    for (volatile int i = 0; i < 2000; i++)
        ;
    __atomic_sub_fetch(&st.t2_inflight, 1, __ATOMIC_RELAXED);
}

static void *
churn_child(void *arg)
{
    sigset_t none;
    sigemptyset(&none);
    pthread_sigmask(SIG_SETMASK, &none, NULL);
    for (volatile long i = (long)(uintptr_t)arg; i > 0; i--)
        ;
    __atomic_sub_fetch(&st.churn_live, 1, __ATOMIC_RELAXED);
    return NULL;
}

static void *
churn_main(void *arg)
{
    rng_t *r = (rng_t *)arg;
    while (st.churn_on) {
        /* Bounded: thread creation and exit are much slower under (debug) DR
         * than natively, so an unbounded creator piles up thousands of threads.
         */
        if (st.churn_live >= storm_churn_max) {
            sleep_us(200);
            continue;
        }
        pthread_t t;
        pthread_attr_t a;
        pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        __atomic_add_fetch(&st.churn_live, 1, __ATOMIC_RELAXED);
        if (pthread_create(&t, &a, churn_child, (void *)(uintptr_t)(rn(r, 20000))) != 0) {
            __atomic_sub_fetch(&st.churn_live, 1, __ATOMIC_RELAXED);
            sleep_us(200);
        }
        pthread_attr_destroy(&a);
        sleep_us(50 + rn(r, 300));
    }
    return NULL;
}

static void *
sender_main(void *arg)
{
    for (int q = 1; q <= STORM_Q && !st.round_over; q++) {
        union sigval v;
        v.sival_int = q;
        if (sigqueue(getpid(), sig_q, v) != 0) {
            __atomic_add_fetch(&st.lost, 1, __ATOMIC_RELAXED);
            break;
        }
        uint64_t t0 = now_ns();
        while (!st.q_seen[q]) {
            if (now_ns() - t0 > 3000000000ULL) {
                fprintf(stderr, "  storm: process-directed signal %d (payload %d) lost\n",
                        sig_q, q);
                __atomic_add_fetch(&st.lost, 1, __ATOMIC_RELAXED);
                break;
            }
            sleep_us(20);
        }
        sleep_us(100);
    }
    st.sender_done = 1;
    return NULL;
}

/* Watches the waiters: one that stops being interrupted while its timer runs
 * hangs.  Ends the round by writing to the pipes.
 */
static void *
controller_main(void *arg)
{
    uint64_t dur = *(uint64_t *)arg;
    uint64_t t0 = now_ns(), last_change[STORM_WAITERS];
    long last[STORM_WAITERS];
    for (int w = 0; w < storm_waiters; w++) {
        last[w] = st.weintr[w];
        last_change[w] = t0;
    }
    for (;;) {
        sleep_us(500);
        uint64_t t = now_ns();
        int hung = -1;
        for (int w = 0; w < storm_waiters; w++) {
            long e = st.weintr[w];
            if (e != last[w]) {
                last[w] = e;
                last_change[w] = t;
            } else if (t - last_change[w] > 3000000000ULL)
                hung = w;
        }
        if (hung >= 0) {
            /* Stop the timers: a waiter that was only kept busy by them now
             * returns, else it hangs (and the child times out).
             */
            storm_stop_timers();
            fprintf(stderr,
                    "  storm: HANG: waiter %d (of %d) was not interrupted for 3 s (%ld "
                    "EINTRs so far; timer period %llu us)\n",
                    hung, STORM_WAITERS, last[hung],
                    (unsigned long long)(st.t1_period_ns * (2 + hung) / 2 / 1000));
            st.hang++;
            break;
        }
        if (t - t0 > dur && st.sender_done)
            break;
        if (t - t0 > dur + 20000000000ULL)
            break;
    }
    st.round_over = 1;
    storm_wake_waiters();
    return NULL;
}

static void
drain_fd(int fd)
{
    int n = 0;
    char b[64];
    while (ioctl(fd, FIONREAD, &n) == 0 && n > 0) {
        if (read(fd, b, n > 64 ? 64 : n) <= 0)
            break;
    }
}

static int
storm_round(int round, rng_t *r, timer_t t2, timer_t t3, long *eintr_total)
{
    memset((void *)&st, 0, sizeof(st));
    for (int w = 0; w < STORM_WAITERS; w++)
        drain_fd(wpipe[w][0]);
    /* Short enough to often catch the thread on its way into read(), long
     * enough for a debug DR to keep up.
     */
    st.t1_period_ns = 40000 + rn(r, 260) * 1000ULL;
    st.t3_period_ns = 50000 + rn(r, 450) * 1000ULL;
    uint64_t t2_period = 500000 + rn(r, 2500) * 1000ULL;
    uint64_t dur = 40000000ULL + rn(r, 80) * 1000000ULL;
    st.churn_on = 1;
    sigset_t all, none;
    sigfillset(&all);
    sigemptyset(&none);
    /* The helper threads block the test signals; the main thread and the
     * exiting threads do not.
     */
    pthread_sigmask(SIG_BLOCK, &all, NULL);
    pthread_t churn, sender, ctl, poker, waiters[STORM_WAITERS];
    rng_t cr = { rnext(r) };
    int ok = pthread_create(&churn, NULL, churn_main, &cr) == 0;
    ok = ok && pthread_create(&sender, NULL, sender_main, NULL) == 0;
    for (int w = 1; w < storm_waiters; w++)
        ok = ok &&
            pthread_create(&waiters[w], NULL, waiter_thread, (void *)(uintptr_t)w) == 0;
    ok = ok && pthread_create(&ctl, NULL, controller_main, &dur) == 0;
    uint64_t poker_seed = rnext(r);
    if (storm_poker)
        ok = ok &&
            pthread_create(&poker, NULL, poker_main, (void *)(uintptr_t)poker_seed) == 0;
    pthread_sigmask(SIG_SETMASK, &none, NULL);
    if (!ok) {
        fprintf(stderr, "ERROR: storm: cannot create threads\n");
        exit(3);
    }
    struct itimerspec i2 = { { 0, (long)t2_period }, { 0, (long)t2_period } };
    struct itimerspec i3 = { { 0, (long)st.t3_period_ns }, { 0, (long)st.t3_period_ns } };
    struct itimerspec zero;
    memset(&zero, 0, sizeof(zero));
    /* Under DR the first timer_settime can take milliseconds (new code): bound
     * the arming time from both sides.
     */
    uint64_t t3_start = now_ns();
    timer_settime(t3, 0, &i3, NULL);
    uint64_t t3_armed = now_ns();
    timer_settime(t2, 0, &i2, NULL);
    waiter_loop(0);
    for (int w = 1; w < storm_waiters; w++)
        pthread_join(waiters[w], NULL);
    timer_settime(t2, 0, &zero, NULL);
    st.churn_on = 0;
    st.round_over = 1;
    pthread_join(ctl, NULL);
    if (storm_poker)
        pthread_join(poker, NULL);
    pthread_join(sender, NULL);
    pthread_join(churn, NULL);
    /* Count the process timer's expirations exactly: once the threads that may
     * take its signal are gone, block it here (every other thread blocks it)
     * and take the pending instance, with its overruns, synchronously.
     */
    for (int i = 0; i < 4000 && (st.churn_live > 0 || st.t2_inflight > 0); i++)
        sleep_us(500);
    sigset_t s3;
    sigemptyset(&s3);
    sigaddset(&s3, sig_t3);
    pthread_sigmask(SIG_BLOCK, &s3, NULL);
    /* The kernel counts the expirations up to the moment it dequeues the
     * signal (it forwards the timer then); wait for one to be queued, as a
     * loaded host can delay the timer interrupt by several periods.
     */
    uint64_t t3_cut = now_ns();
    siginfo_t si3;
    struct timespec wait3 = { 0, 200000000 };
    int got3 = sigtimedwait(&s3, &si3, &wait3) == sig_t3;
    uint64_t t3_end = now_ns();
    if (got3)
        st.t3_acct += 1 + si3.si_overrun;
    timer_settime(t3, 0, &zero, NULL);
    if (st.churn_live > 0 || st.t2_inflight > 0) {
        /* Not a failure by itself: they may still take a signal. */
        fprintf(stderr, "  storm round %d: %ld helper threads still running\n", round,
                st.churn_live + st.t2_inflight);
    }
    int fails = 0;
    long expirations = (long)((t3_end - t3_start) / st.t3_period_ns);
    long expirations_min = (long)((t3_cut - t3_armed) / st.t3_period_ns);
    long acct = st.t3_acct;
    if (st.hang > 0 || st.lost > 0 || st.q_dup > 0) {
        fprintf(stderr, "  storm round %d: hang %ld lost %ld duplicated %ld\n", round,
                st.hang, st.lost, st.q_dup);
        fails++;
    }
    /* Each expiration is a delivery or an overrun of one: allow for the cut. */
    if (!got3 || acct < expirations_min - 2 || acct > expirations + 2) {
        fprintf(stderr,
                "  storm round %d: process timer expirations %ld, accounted %ld (period "
                "%llu us)\n",
                round, expirations, acct, (unsigned long long)(st.t3_period_ns / 1000));
        fails++;
    }
    for (int w = 0; w < STORM_WAITERS; w++)
        *eintr_total += st.weintr[w];
    return fails;
}

typedef struct {
    const variant_t *v;
    int instr, rounds;
    uint64_t seed;
    long *stats; /* rounds, eintr, t2 notifications, failures */
} storm_arg_t;

static int
storm_child(void *arg)
{
    storm_arg_t *a = (storm_arg_t *)arg;
    if (a->v != NULL) {
        g_instr_on = a->instr;
        char ops[256];
        /* Known issue memcache-check-race: see STORM_DEBUG_DR_OPS. */
        snprintf(ops, sizeof(ops), "%s %s", a->v->dr_ops,
                 is_debug_build ? STORM_DEBUG_DR_OPS : "");
        a64p_start_dr(ops);
    }
    main_tid = (pid_t)syscall(SYS_gettid);
    for (int w = 0; w < STORM_WAITERS; w++) {
        if (pipe(wpipe[w]) != 0)
            return 1;
    }
    sig_t1 = SIGRTMIN + 10;
    sig_t3 = SIGRTMIN + 11;
    sig_q = SIGRTMIN + 12;
    set_handler(sig_t1, h_t1, 0, 0);
    set_handler(sig_t3, h_t3, SA_RESTART, 0);
    set_handler(sig_q, h_q, SA_RESTART, 0);
    timer_t t2, t3;
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = t2_notify;
    int ok = timer_create(CLOCK_MONOTONIC, &sev, &t2) == 0;
    storm_timers[0] = storm_timers[1] = t2;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = sig_t3;
    ok = ok && timer_create(CLOCK_MONOTONIC, &sev, &t3) == 0;
    storm_timers[2] = t3;
    if (!ok) {
        fprintf(stderr, "ERROR: storm: timer_create failed\n");
        return 1;
    }
    rng_t r = { a->seed * 0x9e3779b97f4a7c15ULL + 3 };
    int fails = 0;
    long eintr = 0, notify = 0;
    for (int i = 0; i < a->rounds; i++) {
        snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "storm round %d", i);
        a64p_prog->block = i;
        fails += storm_round(i, &r, t2, t3, &eintr);
        notify += st.t2_notify;
        a->stats[0]++;
    }
    a->stats[1] += eintr;
    a->stats[2] += notify;
    timer_delete(t2);
    timer_delete(t3);
    if (a->v != NULL)
        a64p_stop_dr();
    return fails;
}

/***************************************************************************
 * Modes.
 */
static const variant_t v_native = { "native", "", 0, 0, 0, 0 };

static const variant_t *
variant_named(const char *name)
{
    for (int i = 0; i < a64p_num_variants; i++) {
        if (strcmp(a64p_variants[i].name, name) == 0)
            return &a64p_variants[i];
    }
    return NULL;
}

static int
run_cases(const char *mode, uint64_t seed, int n, int only, const char *vlist,
          const char *const *vnames, int nv, int paths, long *nvariants)
{
    int nk = paths ? K_NUM : K_ISPIN;
    int ncases = n * nk;
    sgcase_t *cases = malloc(sizeof(*cases) * ncases);
    sgres_t *native = mmap(NULL, sizeof(sgres_t) * ncases, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    long *stats = mmap(NULL, sizeof(long) * K_NUM * ST_NUM_PER_KIND * (nv + 1),
                       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    int k = 0;
    for (int i = 0; i < n; i++) {
        for (int kind = 0; kind < nk; kind++, k++)
            gen_case(kind, k, seed + (uint64_t)k, &cases[k], paths);
    }
    if (only >= 0) {
        if (only >= ncases) {
            fprintf(stderr, "-only %d: there are %d cases\n", only, ncases);
            return 1;
        }
        cases[0] = cases[only];
        ncases = 1;
    }
    if (verbose) {
        for (int i = 0; i < ncases; i++)
            print_case(stdout, &cases[i]);
    }
    int fails = 0;
    batch_t b = { NULL, 0, 0, ncases, cases, native, stats };
    fails += a64p_in_child_timeout(mode, &v_native, batch_child, &b, 120);
    long ctx_native = a64p_prog->stat[0];
    long totals[5] = { 0 };
    long gen[K_NUM] = { 0 }, exe[K_NUM] = { 0 }, chk[K_NUM] = { 0 }, inc[K_NUM] = { 0 };
    for (int i = 0; i < ncases; i++)
        gen[cases[i].kind]++;
    for (int vi = 0; vi < nv; vi++) {
        const char *name = vnames[vi];
        int cleancall = 0;
        if (strcmp(name, "default+cc") == 0) {
            name = "default";
            cleancall = 1;
        }
        const variant_t *v = variant_named(name);
        if (v == NULL || (v->debug_only && !is_debug_build))
            continue;
        if (vlist != NULL && !a64p_variant_selected(vlist, v))
            continue;
        b.v = v;
        b.instr = paths;
        b.cleancall_all = cleancall;
        b.stats = stats + (vi + 1) * K_NUM * ST_NUM_PER_KIND;
        int f = a64p_in_child_timeout(mode, v, batch_child, &b, 240);
        fails += f;
        (*nvariants)++;
        for (int s = 0; s < 5; s++)
            totals[s] += a64p_prog->stat[s];
        for (int kind = 0; kind < K_NUM; kind++) {
            long *s = &b.stats[kind * ST_NUM_PER_KIND];
            exe[kind] += s[ST_EXEC];
            chk[kind] += s[ST_CHECKED];
            inc[kind] += s[ST_INCONCL];
        }
        if (verbose || f > 0) {
            printf("%s: variant %s%s: %d failures\n", mode, v->name,
                   paths ? (cleancall ? " +client (clean call everywhere)" : " +client")
                         : "",
                   f);
        }
    }
    a64p_counts_t cnt = { 0 };
    for (int kind = 0; kind < nk; kind++) {
        cnt.generated += gen[kind] * (*nvariants);
        cnt.executed += exe[kind];
        cnt.checked += chk[kind];
        cnt.inconclusive += inc[kind];
        if (verbose) {
            printf("%s:   %-7s generated %ld executed %ld checked %ld inconclusive %ld\n",
                   mode, kind_name[kind], gen[kind] * (*nvariants), exe[kind], chk[kind],
                   inc[kind]);
        }
        /* Every kind must be checked in most of its runs. */
        if (only < 0) {
            char what[64];
            snprintf(what, sizeof(what), "%s cases checked", kind_name[kind]);
            fails +=
                a64p_floor(mode, what, chk[kind], (gen[kind] * (*nvariants) * 9) / 10);
        }
    }
    cnt.accepted = cnt.generated - cnt.inconclusive;
    cnt.suppressed = totals[ST_KD_RT_ORDER];
    char label[64];
    snprintf(label, sizeof(label), "%s (case x variant)", mode);
    a64p_counts_print(stdout, label, &cnt);
    printf(
        "%s: interrupted contexts checked %ld (native %ld), handler effects applied %ld, "
        "frames validated %ld, stray signals %ld\n",
        mode, totals[0], ctx_native, totals[1], totals[2], totals[3]);
    printf("%s: known deviations: rt-overflow-order %ld\n", mode, totals[ST_KD_RT_ORDER]);
    if (only < 0) {
        fails += a64p_floor(mode, "interrupted contexts checked under DR", totals[0],
                            (long)ncases * (*nvariants));
        fails += a64p_floor(mode, "native contexts checked", ctx_native, ncases);
    }
    munmap(native, sizeof(sgres_t) * ncases);
    munmap(stats, sizeof(long) * K_NUM * ST_NUM_PER_KIND * (nv + 1));
    free(cases);
    return fails;
}

static int
run_storm(const char *mode, uint64_t seed, int rounds, const char *vlist, int instr,
          long *nvariants_out)
{
    long nv = 0, *nvariants = &nv;
    long *stats =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    int fails = 0;
    storm_arg_t a = { NULL, 0, rounds, seed, stats };
    int nf = a64p_in_child_timeout(mode, &v_native, storm_child, &a, 60 + rounds * 5);
    if (nf > 0)
        printf("storm: native (the oracle itself): %d failures\n", nf);
    fails += nf;
    long nat_rounds = stats[0], nat_eintr = stats[1];
    const char *vnames[] = { "default", "notraces" };
    long dr_rounds = 0, dr_eintr = 0, dr_notify = 0;
    for (int vi = 0; vi < 2; vi++) {
        const variant_t *v = variant_named(vnames[vi]);
        if (vlist != NULL && !a64p_variant_selected(vlist, v))
            continue;
        memset(stats, 0, 64);
        a.v = v;
        a.instr = instr && vi == 1;
        int f = a64p_in_child_timeout(mode, v, storm_child, &a, 60 + rounds * 5);
        fails += f;
        (*nvariants)++;
        dr_rounds += stats[0];
        dr_eintr += stats[1];
        dr_notify += stats[2];
        if (verbose || f > 0)
            printf("storm: variant %s: %d failures\n", v->name, f);
    }
    if (is_debug_build) {
        printf("storm: debug DR runs with %s (known issue memcache-check-race)\n",
               STORM_DEBUG_DR_OPS);
    }
    printf("storm: rounds native %ld, dr %ld; main-thread EINTRs native %ld, dr %ld; "
           "SIGEV_THREAD notifications under dr %ld\n",
           nat_rounds, dr_rounds, nat_eintr, dr_eintr, dr_notify);
    fails +=
        a64p_floor("storm", "rounds under DR", dr_rounds, (long)rounds * (*nvariants));
    fails += a64p_floor("storm", "main-thread EINTRs under DR", dr_eintr, dr_rounds * 10);
    fails +=
        a64p_floor("storm", "SIGEV_THREAD notifications under DR", dr_notify, dr_rounds);
    munmap(stats, 4096);
    *nvariants_out += nv;
    return fails;
}

/***************************************************************************
 * Mode itimer: setitimer/alarm/getitimer sequences.
 *
 * Random sequences on one of ITIMER_REAL, ITIMER_VIRTUAL and ITIMER_PROF: arm,
 * re-arm sooner or later while the timer runs, disarm, one-shot or periodic,
 * alarm() including alarm(0), some ITIMER_REAL calls made from another thread
 * (the timer is the process's).  Between calls the main thread spins.  Checked
 * natively and under DR, against a model of the kernel's timer measured in the
 * timer's own clock (CLOCK_MONOTONIC, process user time, process CPU time):
 *   - the old value setitimer/alarm return and getitimer's value are the
 *     timer's remaining time (within a tolerance);
 *   - each arming's first expiry, if it is due before the next call, is
 *     delivered no earlier than due and at most a tolerance later, and later
 *     periodic expiries are delivered (allowing some to coalesce);
 *   - no expiry is delivered at a time no timer was due;
 * Variants run DR with its own itimers alongside the app's: a client with
 * dr_set_itimer() on all three timers, and -prof_pcs (ITIMER_VIRTUAL) against a
 * debug DR; see the known deviation itimer-mux and the known issue
 * itimer-reroute below.  A case whose thread was off the CPU for long is
 * inconclusive (counted).
 */
#define IT_MAX_OPS 8
#define IT_MAX_LOG 512
enum { IT_SET, IT_GET, IT_ALARM };
typedef struct {
    int op, other_thread, alarm_sec;
    int64_t value, interval, wait; /* microseconds */
} itop_t;
typedef struct {
    int which, nops;
    uint64_t seed;
    itop_t op[IT_MAX_OPS];
} itcase_t;
typedef struct {
    int valid, nexp, stalled;
    long deliveries;
} itres_t;
/* A case whose thread was off the CPU for longer than this is inconclusive. */
#define STALL_US 4000

static volatile long g_dr_itimer_cbs;
static volatile int it_nlog;
static int64_t it_log[IT_MAX_LOG];
static int it_which;

static int64_t
it_clock(int which)
{
    struct timespec ts;
    if (which == ITIMER_VIRTUAL) {
        struct rusage ru;
        if (getrusage(RUSAGE_SELF, &ru) != 0) {
            perror("ERROR: getrusage");
            _exit(2);
        }
        return (int64_t)ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec;
    }
    if (clock_gettime(which == ITIMER_REAL ? CLOCK_MONOTONIC : CLOCK_PROCESS_CPUTIME_ID,
                      &ts) != 0) {
        perror("ERROR: clock_gettime");
        _exit(2);
    }
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int64_t
thread_cpu_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static volatile int it_wrong_thread;
/* DR's own timer period on each itimer in this run (0: none); see the known
 * deviation itimer-mux.
 */
static int64_t it_mux[3];
/* No helper thread, so calls of "other thread" ops run on the main thread:
 * with DR's own itimers (known issue itimer-reroute) or A64P_IT_NOHELPER.
 */
static int it_nohelper;
static long it_suppressed;

/* Known deviation itimer-mux (2026-10-14): with a DR timer of the same type, DR
 * runs the kernel timer at the sooner of the two and accounts the app's timer
 * by the expiries it handles.  Its signal latency and any expiries the kernel
 * merges while one is pending are lost, and an expiry handled during the app's
 * itimer call is charged to the wrong settings: the app's timer runs off by up
 * to a DR period per call, and late by about 1-2% of the elapsed time under a
 * light load (tens of percent on a loaded host).  Values and expiries off by
 * at most 10 ms + a DR period + 50% of the time since arming are counted, not
 * failed.
 */
static int64_t
it_mux_slack(int which, int64_t elapsed)
{
    return it_mux[which] == 0 ? 0 : 10000 + it_mux[which] + elapsed / 2;
}

static void
h_itimer(int sig, siginfo_t *si, void *uc)
{
    /* The helper thread blocks every signal. */
    if (syscall(SYS_gettid) != main_tid) {
        it_wrong_thread++;
        return;
    }
    int n = it_nlog;
    if (n < IT_MAX_LOG) {
        it_log[n] = it_clock(it_which);
        it_nlog = n + 1;
    }
}

static int
it_sig(int which)
{
    return which == ITIMER_REAL ? SIGALRM : which == ITIMER_VIRTUAL ? SIGVTALRM : SIGPROF;
}

static void
dr_itimer_cb(void *drcontext, dr_mcontext_t *mc)
{
    __atomic_add_fetch(&g_dr_itimer_cbs, 1, __ATOMIC_RELAXED);
}

/* Tolerances (us): the CPU-time timers are checked at scheduler ticks. */
static int64_t
it_late_tol(int which)
{
    /* Generous: the test VM is shared and a loaded host delays signals by tens
     * of ms; the bugs this checks for lose an expiry or shift it by about a
     * whole timer value.
     */
    return which == ITIMER_REAL ? 50000 : 100000;
}
static int64_t
it_early_tol(int which)
{
    /* The kernel checks the CPU-time timers against its own sample of the
     * process's time, which can run a few ms ahead of the clocks we read.
     */
    return which == ITIMER_REAL ? 500 : 30000;
}
static int64_t
it_val_tol(int which)
{
    /* The kernel accounts the CPU-time timers lazily: on this test VM its value
     * lagged the process's CPU clock by up to about 20 ms.
     */
    return which == ITIMER_REAL ? 3000 : 50000;
}

static void
gen_itcase(uint64_t seed, itcase_t *c)
{
    rng_t r = { seed * 0x9e3779b97f4a7c15ULL + 11 };
    memset(c, 0, sizeof(*c));
    c->seed = seed;
    /* Half the cases on ITIMER_REAL, whose checks are much tighter. */
    c->which = rp(&r, 50) ? ITIMER_REAL : 1 + (int)rn(&r, 2);
    c->nops = 3 + (int)rn(&r, IT_MAX_OPS - 3);
    int alarm_armed = 0;
    for (int i = 0; i < c->nops; i++) {
        itop_t *o = &c->op[i];
        int k = (int)rn(&r, 10);
        if (c->which == ITIMER_REAL && k == 0 && !alarm_armed && i < c->nops - 1) {
            o->op = IT_ALARM;
            o->alarm_sec = 1 + (int)rn(&r, 2); /* re-armed or disarmed before it fires */
            alarm_armed = 1;
        } else if (c->which == ITIMER_REAL && k == 1) {
            o->op = IT_ALARM; /* alarm(0) */
            alarm_armed = 0;
        } else if (k == 2) {
            o->op = IT_GET;
        } else {
            o->op = IT_SET;
            alarm_armed = 0;
            if (!rp(&r, 15)) {
                o->value = 3000 + rn(&r, 97000);
                o->interval = rp(&r, 40) ? 15000 + rn(&r, 35000) : 0;
            }
        }
        if (c->which == ITIMER_REAL)
            o->other_thread = rp(&r, 30);
        o->wait = 2000 + rn(&r, 100000);
    }
    /* Whatever is left armed is disarmed at the end (and checked). */
}

static volatile itop_t *it_req;
/* The helper runs request it_req_seq and then sets it_req_done to it. */
static volatile int it_req_seq, it_req_done;
static struct itimerval it_req_old;
static unsigned it_req_alarm_old;
static volatile int it_helper_quit;

static void
it_do(const volatile itop_t *o, int which, struct itimerval *old, unsigned *alarm_old)
{
    if (o->op == IT_ALARM)
        *alarm_old = alarm((unsigned)o->alarm_sec);
    else if (o->op == IT_GET)
        getitimer(which, old);
    else {
        struct itimerval nv;
        nv.it_value.tv_sec = o->value / 1000000;
        nv.it_value.tv_usec = o->value % 1000000;
        nv.it_interval.tv_sec = o->interval / 1000000;
        nv.it_interval.tv_usec = o->interval % 1000000;
        setitimer(which, &nv, old);
    }
}

static void *
it_helper(void *arg)
{
    while (!it_helper_quit) {
        int seq = __atomic_load_n(&it_req_seq, __ATOMIC_ACQUIRE);
        if (seq != it_req_done) {
            it_do(it_req, ITIMER_REAL, &it_req_old, &it_req_alarm_old);
            __atomic_store_n(&it_req_done, seq, __ATOMIC_RELEASE);
        }
        sleep_us(50);
    }
    return NULL;
}

/* The model: the timer's remaining time at t for an arming at s. */
typedef struct {
    int armed;
    int64_t s0, s1; /* the arming happened in [s0, s1] */
    int64_t value, interval;
} itarm_t;

static int64_t
it_rem(const itarm_t *a, int64_t s, int64_t t)
{
    if (!a->armed)
        return 0;
    int64_t d = s + a->value;
    if (t < d)
        return d - t;
    if (a->interval == 0)
        return 0;
    return a->interval - (t - d) % a->interval;
}

/* Whether an expiry of a may fall in [lo, hi]. */
static int
it_due_in(const itarm_t *a, int64_t lo, int64_t hi)
{
    if (!a->armed)
        return 0;
    for (int64_t j = 0;; j++) {
        int64_t d0 = a->s0 + a->value + j * a->interval;
        int64_t d1 = a->s1 + a->value + j * a->interval;
        if (d0 > hi)
            return 0;
        if (d1 >= lo)
            return 1;
        if (a->interval == 0)
            return 0;
    }
}

/* alarm()'s rounding of a remaining time to seconds. */
static unsigned
it_alarm_secs(int64_t us)
{
    if (us <= 0)
        return 0;
    unsigned s = (unsigned)(us / 1000000);
    if ((s == 0 && us % 1000000 != 0) || us % 1000000 >= 500000)
        s++;
    return s;
}

static int
it_run_case(const itcase_t *c, itres_t *res, int is_dr)
{
    int which = c->which, fails = 0;
    char why[256];
    why[0] = '\0';
#define ITFAIL(...)                                  \
    do {                                             \
        if (fails++ == 0)                            \
            snprintf(why, sizeof(why), __VA_ARGS__); \
    } while (0)
    struct itimerval zero;
    memset(&zero, 0, sizeof(zero));
    setitimer(which, &zero, NULL);
    it_which = which;
    it_nlog = 0;
    it_wrong_thread = 0;
    set_handler(it_sig(which), h_itimer, SA_RESTART, 0);
    int64_t late = it_late_tol(which), early = it_early_tol(which),
            vtol = it_val_tol(which);
    itarm_t arm = { 0 };
    /* Off-CPU time is tracked across the whole case, calls included. */
    int64_t max_gap = 0, wlast = it_clock(ITIMER_REAL), clast = thread_cpu_us();
    int64_t ends[IT_MAX_OPS + 1], ends_hi[IT_MAX_OPS + 1];
    itarm_t arms[IT_MAX_OPS + 1];
    int narms = 0;
    for (int i = 0; i <= c->nops; i++) {
        itop_t fin = { IT_SET, 0, 0, 0, 0, late };
        const itop_t *o = i < c->nops ? &c->op[i] : &fin; /* final disarm */
        struct itimerval old;
        unsigned alarm_old = 0;
        memset(&old, 0, sizeof(old));
        int64_t t0 = it_clock(which);
        if (o->other_thread && !it_nohelper) {
            it_req = (volatile itop_t *)o;
            int seq = it_req_seq + 1;
            __atomic_store_n(&it_req_seq, seq, __ATOMIC_RELEASE);
            int64_t give_up = it_clock(ITIMER_REAL) + 10000000;
            while (__atomic_load_n(&it_req_done, __ATOMIC_ACQUIRE) != seq) {
                if (it_clock(ITIMER_REAL) > give_up) {
                    fprintf(stderr,
                            "ERROR: itimer: the helper thread did not run a call in "
                            "10 s\n");
                    _exit(2);
                }
            }
            old = it_req_old;
            alarm_old = it_req_alarm_old;
        } else
            it_do(o, which, &old, &alarm_old);
        int64_t t1 = it_clock(which);
        /* The old (or current) value. */
        int64_t got = (int64_t)old.it_value.tv_sec * 1000000 + old.it_value.tv_usec;
        int64_t hi = it_rem(&arm, arm.s0, t0), lo = it_rem(&arm, arm.s1, t1);
        if (lo > hi) {
            int64_t tmp = lo;
            lo = hi;
            hi = tmp;
        }
        int ambiguous = it_due_in(&arm, t0 - vtol, t1 + vtol) || t1 - t0 > vtol;
        if (o->op == IT_ALARM) {
            unsigned want_lo = it_alarm_secs(lo - vtol),
                     want_hi = it_alarm_secs(hi + vtol);
            if (!ambiguous && (alarm_old < want_lo || alarm_old > want_hi))
                ITFAIL("op %d: alarm returned %u, model %u..%u", i, alarm_old, want_lo,
                       want_hi);
        } else if (!ambiguous &&
                   ((got > hi + vtol &&
                     got <= hi + vtol + it_mux_slack(which, t1 - arm.s0)) ||
                    (got < lo - vtol &&
                     got >= lo - vtol - it_mux_slack(which, t1 - arm.s0)))) {
            it_suppressed++;
        } else if (!ambiguous && (got < lo - vtol || got > hi + vtol)) {
            ITFAIL("op %d (%s): %s value %lld us, model %lld..%lld", i,
                   o->op == IT_GET ? "getitimer" : "setitimer",
                   o->op == IT_GET ? "current" : "old", (long long)got, (long long)lo,
                   (long long)hi);
        }
        if (o->op != IT_GET && !ambiguous && arm.armed &&
            old.it_interval.tv_sec * 1000000 + old.it_interval.tv_usec != arm.interval &&
            o->op != IT_ALARM) {
            ITFAIL(
                "op %d: old interval %lld us, model %lld", i,
                (long long)(old.it_interval.tv_sec * 1000000 + old.it_interval.tv_usec),
                (long long)arm.interval);
        }
        if (o->op != IT_GET) {
            /* A new arming (or a disarm) starts an epoch. */
            if (narms > 0) {
                ends[narms - 1] = t0;
                ends_hi[narms - 1] = t1;
            }
            arm.armed = o->op == IT_ALARM ? o->alarm_sec > 0 : o->value > 0;
            arm.value = o->op == IT_ALARM ? (int64_t)o->alarm_sec * 1000000 : o->value;
            arm.interval = o->op == IT_ALARM ? 0 : o->interval;
            arm.s0 = t0;
            arm.s1 = t1;
            arms[narms] = arm;
            ends[narms] = ends_hi[narms] = INT64_MAX;
            narms++;
        }
        /* Spin (the CPU-time timers need it), watching for the thread being
         * descheduled: a loaded host can stall it for longer than any
         * tolerance, and then a late delivery or reading proves nothing.
         */
        int64_t until = t1 + o->wait;
        /* Bounded in wall time too: a clock that does not advance must not hang
         * the test.
         */
        int64_t wall_limit = it_clock(ITIMER_REAL) + 10 * o->wait + 5000000;
        while (it_clock(which) < until) {
            if (it_clock(ITIMER_REAL) > wall_limit) {
                ITFAIL("op %d: the %s clock advanced only %lld of %lld us in %lld s of "
                       "spinning",
                       i, which == ITIMER_REAL ? "real" : "CPU",
                       (long long)(it_clock(which) - t1), (long long)o->wait,
                       (long long)((10 * o->wait + 5000000) / 1000000));
                break;
            }
            /* Off-CPU time: wall time that is not this thread's CPU time (time
             * spent handling signals, DR's included, is).
             */
            int64_t w = it_clock(ITIMER_REAL), cpu = thread_cpu_us();
            if ((w - wlast) - (cpu - clast) > max_gap)
                max_gap = (w - wlast) - (cpu - clast);
            wlast = w;
            clast = cpu;
        }
    }
    setitimer(which, &zero, NULL);
    int nlog = it_nlog;
    res->deliveries = nlog;
    if (it_wrong_thread > 0)
        ITFAIL("%d expiries delivered to the helper thread, which blocks the signal",
               it_wrong_thread);
    res->stalled = max_gap > STALL_US;
    if (res->stalled) {
        /* Inconclusive: only the value checks above (for calls that did not
         * stall) count.
         */
        res->valid = 1;
        res->deliveries = -1;
        goto report;
    }
    /* Deliveries against the epochs. */
    int expected = 0;
    for (int k = 0; k < narms; k++) {
        itarm_t *a = &arms[k];
        if (!a->armed)
            continue;
        int64_t end = ends[k];
        int nreq = 0, nmiss = 0;
        for (int64_t j = 0;; j++) {
            int64_t dlo = a->s0 + a->value + j * a->interval;
            int64_t dhi = a->s1 + a->value + j * a->interval;
            if (dhi + late > end || (a->interval == 0 && j > 0))
                break;
            nreq++;
            expected++;
            int found = 0;
            for (int m = 0; m < nlog && !found; m++)
                found = it_log[m] >= dlo - early && it_log[m] <= dhi + late;
            for (int m = 0; m < nlog && !found; m++) {
                found = it_log[m] >= dlo - early &&
                    it_log[m] <= dhi + late + it_mux_slack(which, dhi - a->s0);
                if (found)
                    it_suppressed++;
            }
            if (!found) {
                if (j == 0) {
                    int64_t next = -1;
                    for (int m = 0; m < nlog; m++) {
                        if (it_log[m] >= dlo && (next < 0 || it_log[m] < next))
                            next = it_log[m];
                    }
                    ITFAIL("arming %d (value %lld interval %lld us): expiry due at "
                           "+%lld..%lld us not delivered within %lld us (next delivery "
                           "%lld us after it)",
                           k, (long long)a->value, (long long)a->interval,
                           (long long)(dlo - a->s0), (long long)(dhi - a->s0),
                           (long long)late, next < 0 ? -1LL : (long long)(next - dlo));
                } else
                    nmiss++;
            }
            if (a->interval == 0)
                break;
        }
        if (nmiss > 1 + nreq / 5)
            ITFAIL("arming %d: %d of %d periodic expiries not delivered", k, nmiss, nreq);
    }
    /* Nothing delivered when no expiry could explain it. */
    for (int m = 0; m < nlog; m++) {
        int ok = 0;
        for (int k = 0; k < narms && !ok; k++) {
            itarm_t *a = &arms[k];
            if (!a->armed)
                continue;
            for (int64_t j = 0;; j++) {
                int64_t dlo = a->s0 + a->value + j * a->interval;
                int64_t dhi = a->s1 + a->value + j * a->interval;
                if (dlo - early > ends_hi[k] || dlo > it_log[m] + early)
                    break;
                if (it_log[m] >= dlo - early && it_log[m] <= dhi + late) {
                    ok = 1;
                    break;
                }
                if (it_log[m] >= dlo - early &&
                    it_log[m] <= dhi + late + it_mux_slack(which, dhi - a->s0)) {
                    ok = 1;
                    it_suppressed++;
                    break;
                }
                if (a->interval == 0)
                    break;
            }
        }
        if (!ok) {
            ITFAIL("delivery %d at +%lld us matches no expiry", m,
                   (long long)(it_log[m] - arms[0].s0));
        }
    }
    res->nexp = expected;
    res->valid = 1;
report:
    if (fails > 0) {
        fprintf(stderr, "  itimer case seed %llu (%s, %s): %s\n",
                (unsigned long long)c->seed,
                which == ITIMER_REAL          ? "REAL"
                    : which == ITIMER_VIRTUAL ? "VIRTUAL"
                                              : "PROF",
                is_dr ? "dr" : "native", why);
        for (int i = 0; i < c->nops; i++) {
            const itop_t *o = &c->op[i];
            fprintf(stderr,
                    "      op %d: %s value %lld interval %lld alarm %d%s wait %lld\n", i,
                    o->op == IT_SET       ? "set"
                        : o->op == IT_GET ? "get"
                                          : "alarm",
                    (long long)o->value, (long long)o->interval, o->alarm_sec,
                    o->other_thread ? " (other thread)" : "", (long long)o->wait);
        }
    }
#undef ITFAIL
    return fails;
}

typedef struct {
    const char *name, *dr_ops; /* name NULL: native */
    int dr_itimer;
    int ncases;
    itcase_t *cases;
    itres_t *native, *dr;
} itbatch_t;

static int
it_child(void *arg)
{
    itbatch_t *b = (itbatch_t *)arg;
    memset(it_mux, 0, sizeof(it_mux));
    if (b->name != NULL) {
        g_dr_itimer = b->dr_itimer;
        if (b->dr_itimer) {
            it_mux[ITIMER_REAL] = 3000;
            it_mux[ITIMER_VIRTUAL] = 4000;
            it_mux[ITIMER_PROF] = 5000;
        } else if (strstr(b->dr_ops, "prof_pcs") != NULL)
            it_mux[ITIMER_VIRTUAL] = 10000;
        a64p_start_dr(b->dr_ops);
    }
    main_tid = (pid_t)syscall(SYS_gettid);
    sigset_t all, old;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &old);
    pthread_t h;
    it_helper_quit = 0;
    /* Known issue itimer-reroute (2026-10-14): with DR's own itimers the alarm
     * signals stay unblocked in the kernel, so a process-directed itimer signal
     * can go to a thread that blocks it; we then reroute it to the main thread
     * only late (90 ms seen) or, in some runs, never ("A64P_IT_HELPER=1
     * a64_prop_signal itimer -variants dr-itimers" reproduces it).
     */
    int nohelper = getenv("A64P_IT_NOHELPER") != NULL ||
        ((it_mux[0] | it_mux[1] | it_mux[2]) != 0 && getenv("A64P_IT_HELPER") == NULL);
    it_nohelper = nohelper;
    int ok = nohelper || pthread_create(&h, NULL, it_helper, NULL) == 0;
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    if (!ok)
        return 1;
    int fails = 0;
    for (int i = 0; i < b->ncases; i++) {
        snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "itimer case %d", i);
        a64p_prog->block = i;
        itres_t *r = b->name == NULL ? &b->native[i] : &b->dr[i];
        fails += it_run_case(&b->cases[i], r, b->name != NULL);
    }
    it_helper_quit = 1;
    if (!nohelper)
        pthread_join(h, NULL);
    if (b->name != NULL && b->dr_itimer && g_dr_itimer_cbs == 0) {
        fprintf(stderr, "  itimer: the client's dr_set_itimer callbacks never ran\n");
        fails++;
    }
    a64p_prog->stat[0] = g_dr_itimer_cbs;
    a64p_prog->stat[1] = it_suppressed;
    if (b->name != NULL)
        a64p_stop_dr();
    return fails;
}

static int
run_itimer(const char *mode, uint64_t seed, int n, int only, const char *vlist,
           long *nvariants)
{
    itcase_t *cases = malloc(sizeof(*cases) * n);
    itres_t *native = mmap(NULL, sizeof(itres_t) * n * 2, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    itres_t *dr = native + n;
    int ncases = 0;
    for (int i = 0; i < n; i++) {
        if (only < 0 || only == i)
            gen_itcase(seed + (uint64_t)i, &cases[ncases++]);
    }
    int fails = 0;
    itbatch_t b = { NULL, "", 0, ncases, cases, native, dr };
    variant_t vn = { "native", "", 0, 0, 0, 0 };
    int f = a64p_in_child_timeout(mode, &vn, it_child, &b, 120);
    if (f > 0)
        printf("itimer: native (the oracle itself): %d failures\n", f);
    fails += f;
    struct {
        const char *name, *ops;
        int dr_itimer, debug_only;
    } vs[] = {
        { "default", "", 0, 0 },
        { "dr-itimers", "", 1, 0 },
        { "prof-pcs", "-prof_pcs", 0, 1 },
    };
    long total = 0, checked = 0, cbs = 0, inconclusive = 0, suppressed = 0;
    int ran_dr_itimer = 0;
    for (int k = 0; k < (int)(sizeof(vs) / sizeof(vs[0])); k++) {
        if (vs[k].debug_only && !is_debug_build)
            continue;
        if (vlist != NULL && strstr(vlist, vs[k].name) == NULL)
            continue;
        b.name = vs[k].name;
        b.dr_ops = vs[k].ops;
        b.dr_itimer = vs[k].dr_itimer;
        ran_dr_itimer |= vs[k].dr_itimer;
        memset(dr, 0, sizeof(itres_t) * n);
        variant_t v = { vs[k].name, vs[k].ops, 0, 0, 0, 0 };
        f = a64p_in_child_timeout(mode, &v, it_child, &b, 120);
        cbs += a64p_prog->stat[0];
        suppressed += a64p_prog->stat[1];
        (*nvariants)++;
        for (int i = 0; i < ncases; i++) {
            if (!native[i].valid || !dr[i].valid)
                continue;
            if (native[i].stalled || dr[i].stalled) {
                inconclusive++;
                continue;
            }
            total += dr[i].deliveries;
            checked++;
            (void)native[i].deliveries;
        }
        if (verbose || f > 0)
            printf("itimer: variant %s: %d failures\n", vs[k].name, f);
        fails += f;
    }
    printf("itimer: cases %d per variant, compared %ld, inconclusive (descheduled) %ld, "
           "expiries delivered under DR %ld, DR itimer callbacks %ld\n",
           ncases, checked, inconclusive, total, cbs);
    printf("itimer: known deviations: itimer-mux %ld\n", suppressed);
    if (only < 0) {
        fails += a64p_floor(mode, "case runs compared", checked,
                            (long)ncases * (*nvariants) / 4);
        if (ran_dr_itimer)
            fails += a64p_floor(mode, "DR itimer callbacks", cbs, 1);
    }
    munmap(native, sizeof(itres_t) * n * 2);
    free(cases);
    return fails;
}

int
main(int argc, const char *argv[])
{
    const char *mode = argc > 1 ? argv[1] : "abi";
    uint64_t seed = 1;
    int n = -1, only = -1, rounds = -1;
    const char *vlist = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc)
            seed = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            n = atoi(argv[++i]);
        else if (strcmp(argv[i], "-only") == 0 && i + 1 < argc)
            only = atoi(argv[++i]);
        else if (strcmp(argv[i], "-rounds") == 0 && i + 1 < argc)
            rounds = atoi(argv[++i]);
        else if (strcmp(argv[i], "-variants") == 0 && i + 1 < argc)
            vlist = argv[++i];
        else if (strcmp(argv[i], "-waiters") == 0 && i + 1 < argc) {
            storm_waiters = atoi(argv[++i]);
            if (storm_waiters < 1 || storm_waiters > STORM_WAITERS)
                storm_waiters = STORM_WAITERS;
        } else if (strcmp(argv[i], "-poker") == 0 && i + 1 < argc)
            storm_poker = atoi(argv[++i]);
        else if (strcmp(argv[i], "-churn_max") == 0 && i + 1 < argc)
            storm_churn_max = atol(argv[++i]);
        else if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if (vlist != NULL && strcmp(mode, "itimer") != 0 &&
        a64p_unknown_variant(vlist) != NULL) {
        fprintf(stderr, "unknown variant '%s' in -variants %s\n",
                a64p_unknown_variant(vlist), vlist);
        return 2;
    }
#ifdef A64_DR_PROP_DEBUG_DR
    is_debug_build = 1;
#endif
    if (getenv("A64_DR_PROP_DEBUG_DR") != NULL)
        is_debug_build = atoi(getenv("A64_DR_PROP_DEBUG_DR"));
    has_dit = (getauxval(AT_HWCAP) & HWCAP_DIT) != 0;
    int pool[8] = { SIGUSR1,      SIGUSR2,      SIGRTMIN + 3, SIGRTMIN + 4,
                    SIGRTMIN + 5, SIGRTMIN + 6, SIGRTMIN + 7, SIGRTMIN + 8 };
    memcpy(sig_pool, pool, sizeof(pool));
    a64p_progress_init("a64_prop_signal");
    void *p = mmap((void *)SG_BASE, SG_MAP_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p != (void *)SG_BASE) {
        fprintf(stderr, "ERROR: cannot map the scenario area at 0x%llx\n",
                (unsigned long long)SG_BASE);
        return 2;
    }
    if (mprotect((void *)SG_GUARD, 0x1000, PROT_NONE) != 0) {
        perror("mprotect");
        return 2;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!has_dit)
        printf("%s: note: no FEAT_DIT; DIT is not checked\n", mode);
    int fails = 0;
    long nvariants = 0;
    if (strcmp(mode, "abi") == 0) {
        const char *vn[] = { "default", "maxbb3", "notraces", "steal27", "reset" };
        fails +=
            run_cases(mode, seed, n < 0 ? 600 : n, only, vlist, vn, 5, 0, &nvariants);
    } else if (strcmp(mode, "paths") == 0) {
        const char *vn[] = { "default", "default+cc", "notraces" };
        fails +=
            run_cases(mode, seed, n < 0 ? 150 : n, only, vlist, vn, 3, 1, &nvariants);
        if (only < 0)
            fails +=
                run_storm(mode, seed, rounds < 0 ? 40 : rounds, vlist, 1, &nvariants);
    } else if (strcmp(mode, "itimer") == 0) {
        fails += run_itimer(mode, seed, n < 0 ? 7 : n, only, vlist, &nvariants);
    } else if (strcmp(mode, "storm") == 0) {
        fails += run_storm(mode, seed, rounds < 0 ? 40 : rounds, vlist, 0, &nvariants);
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    fails += a64p_floor(mode, "variants run", nvariants, 1);
    printf("%s: %s\n", mode, fails == 0 ? "all properties hold" : "FAILURES");
    return fails == 0 ? 0 : 1;
}

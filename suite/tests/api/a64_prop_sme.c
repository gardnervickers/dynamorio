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

/* SME support-boundary probe for DR on AArch64, with native runs as the
 * oracle.  DR has no SME support: it decodes SME words as OP_xx and re-emits
 * them verbatim, does not track PSTATE.SM/PSTATE.ZA, and its own context
 * switches, clean calls and signal code run in whatever mode the application
 * left.  This test does not presuppose what that does; it runs hand-written,
 * architecturally legal templates natively and under static DR and
 * classifies what DR does with each:
 *
 *   equivalent    every run's captured state equals the native one;
 *   unsupported   DR refuses SME explicitly (a DR message naming SME as
 *                 unsupported) instead of running it -- never counted as
 *                 transparency;
 *   divergence    an unexpected signal in the application (e.g. SIGILL), a DR
 *                 crash or assertion, a hang, or different state.
 *
 * Each template runs in forked children, three runs per child: natively (two
 * children, which must agree), and under DR in two modes.  "cold": DR builds
 * each block when it is first reached, as usual.  "warm": every block of the
 * templates is built and every indirect target added before dr_app_start()
 * (dr_prepopulate_cache()), so that what remains is the transition itself.
 * Signal templates first take the same signal outside streaming mode, so the
 * handler's blocks exist too.  Templates:
 *   sm_basic     smstart sm; Q-register LDR/STR/LDP/STP, scalar FP, GPR ops,
 *                RDSVL/CNTD, streaming SVE (PTRUE, WHILELO, DUP, INDEX, ADD,
 *                ST1D, LD1D); dump of Z/P; smstop sm.  No branches.
 *   za_basic     smstart za (not streaming); ZERO {ZA}; LDR/STR ZA; an AdvSIMD
 *                op (legal outside streaming mode); smstop za.
 *   smza_basic   smstart; ZA and streaming state, MOVA in both directions.
 *   sm_direct, sm_ibr, sm_cc, sm_cc_neon: a direct branch to a new block,
 *                an indirect branch and a call/return, a clean call (inserted
 *                by the in-process client at a marker hint) and a clean call
 *                whose callee executes AdvSIMD, all while streaming mode is
 *                live, with Z/P state set before and checked after.
 *   sm_svc       a syscall while streaming (Linux leaves streaming mode at a
 *                syscall, discarding Z/P: the state after it must match).
 *   za_ibr, za_svc, za_cc: the same transitions while only ZA is live.
 *   sm_brk, smza_brk, za_brk, sm_async, smza_async, za_async: a signal
 *                (BRK, or SIGUSR1 from another thread while the template spins
 *                in a loop, which DR delays to a block boundary) while
 *                streaming mode and/or ZA is live.  With ZA live the kernel's
 *                frame overflows __reserved into an EXTRA record.  The
 *                handler validates the frame's record list, records whether
 *                the SVE record carries the streaming flag and vector length,
 *                the ZA record, where an EXTRA record's data is, SVCR at its
 *                entry and hashes of the saved state, and edits a GPR, a Z
 *                byte above bit 127, a P register and a ZA byte, which must
 *                all apply on return.  (It executes SMSTOP first, a no-op
 *                natively, so that it survives being entered in streaming
 *                mode and can report the rest.)
 *   sm_illegal   an AdvSIMD vector instruction in streaming mode (illegal
 *                without FEAT_SME_FA64): the SIGILL and its frame must match.
 *
 * Templates that diverge under today's DR are named, dated known issues
 * (known_issues[]): they still run and their outcome is reported and counted,
 * but they only fail the test with -known.  Every other template must be
 * equivalent.  Without HWCAP2_SME, or if PR_SME_SET_VL fails, the test says
 * so and skips.
 *
 * Usage: a64_prop_sme [-only NAME] [-mode cold|warm] [-runs N] [-known] [-v]
 */

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include "dr_api.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include "a64_prop_support.h"

#ifndef HWCAP2_SME
#    define HWCAP2_SME (1UL << 23)
#endif
#ifndef HWCAP2_SME_FA64
#    define HWCAP2_SME_FA64 (1UL << 30)
#endif
#ifndef PR_SME_SET_VL
#    define PR_SME_SET_VL 63
#endif
#ifndef PR_SME_GET_VL
#    define PR_SME_GET_VL 64
#endif
#define SME_VL_LEN_MASK 0xffff

#define PSTATE_BTYPE 0xc00ULL
#define PSTATE_SSBS 0x1000ULL

/* Signal frame records (arch/arm64/include/uapi/asm/sigcontext.h). */
#define SVE_REC_MAGIC 0x53564501
#define ZA_REC_MAGIC 0x54366345
#define SVE_FLAG_SM 1
#define REC_REGS_OFFSET 16
#define SVE_ZREG_OFF(vq, n) (REC_REGS_OFFSET + (n) * (vq) * 16)
#define SVE_PREG_OFF(vq, n) (REC_REGS_OFFSET + 32 * (vq) * 16 + (n) * (vq) * 2)
#define SVE_CTX_SIZE(vq) (REC_REGS_OFFSET + 32 * (vq) * 16 + 17 * (vq) * 2)

/***************************************************************************
 * Template state.  The templates load registers from an in_t and store what
 * they computed to an out_t; offsets are shared with the assembly below.
 */
#define MAX_SVL 256
#define ZA_ROWS 16

typedef struct {
    uint64_t x[32];
    __uint128_t q[32];
    uint8_t za[ZA_ROWS * MAX_SVL]; /* rows at a stride of SVL bytes */
    uint8_t mem[512];
} in_t;

typedef struct {
    uint64_t x[32]; /* x[31]: SVCR at the end of the template */
    uint64_t fpsr, fpcr, svl, pad;
    __uint128_t q[32];
    uint8_t z[32 * MAX_SVL];       /* 32 vectors at a stride of SVL */
    uint8_t p[16 * MAX_SVL / 8];   /* 16 predicates at a stride of SVL/8 */
    uint8_t za[ZA_ROWS * MAX_SVL]; /* rows 0..15 at a stride of SVL */
    uint8_t mem[512];
} out_t;

_Static_assert(offsetof(in_t, q) == 256, "asm I_Q");
_Static_assert(offsetof(in_t, za) == 768, "asm I_ZA");
_Static_assert(offsetof(in_t, mem) == 4864, "asm I_MEM");
_Static_assert(offsetof(out_t, fpsr) == 256, "asm O_FPSR");
_Static_assert(offsetof(out_t, fpcr) == 264, "asm O_FPCR");
_Static_assert(offsetof(out_t, q) == 288, "asm O_Q");
_Static_assert(offsetof(out_t, z) == 800, "asm O_Z");
_Static_assert(offsetof(out_t, p) == 8992, "asm O_P");
_Static_assert(offsetof(out_t, za) == 9504, "asm O_ZA");
_Static_assert(offsetof(out_t, mem) == 13600, "asm O_MEM");

/* SME and SVE instructions are emitted as .inst words so that no assembler
 * SME support is needed.  Each encoding was checked against llvm-mc
 * (-mattr=+sme,+sme2,+sve) and the assembled templates against
 * llvm-objdump; the mnemonic is in each macro's name.
 */
__asm__("    .equ O_FPSR, 256\n"
        "    .equ O_FPCR, 264\n"
        "    .equ O_Q, 288\n"
        "    .equ O_Z, 800\n"
        "    .equ O_P, 8992\n"
        "    .equ O_ZA, 9504\n"
        "    .equ O_MEM, 13600\n"
        "    .equ I_Q, 256\n"
        "    .equ I_ZA, 768\n"
        /* smstart sm / smstop sm / smstart za / smstop za / smstart / smstop */
        "    .macro SMSTART_SM\n .inst 0xd503437f\n .endm\n"
        "    .macro SMSTOP_SM\n .inst 0xd503427f\n .endm\n"
        "    .macro SMSTART_ZA\n .inst 0xd503457f\n .endm\n"
        "    .macro SMSTOP_ZA\n .inst 0xd503447f\n .endm\n"
        "    .macro SMSTART_ALL\n .inst 0xd503477f\n .endm\n"
        "    .macro SMSTOP_ALL\n .inst 0xd503467f\n .endm\n"
        /* mrs xt, svcr */
        "    .macro MRS_SVCR rt\n .inst 0xd53b4240 | \\rt\n .endm\n"
        /* rdsvl xd, #1 */
        "    .macro RDSVL rd\n .inst 0x04bf5820 | \\rd\n .endm\n"
        /* cntd xd */
        "    .macro CNTD rd\n .inst 0x04e0e3e0 | \\rd\n .endm\n"
        /* zero {za} */
        "    .macro ZERO_ZA\n .inst 0xc00800ff\n .endm\n"
        /* ptrue pd.d / ptrue pd.s */
        "    .macro PTRUE_D pd\n .inst 0x25d8e3e0 | \\pd\n .endm\n"
        "    .macro PTRUE_S pd\n .inst 0x2598e3e0 | \\pd\n .endm\n"
        /* whilelo pd.d, xn, xm */
        "    .macro WHILELO_D pd, rn, rm\n"
        "    .inst 0x25e01c00 | (\\rm << 16) | (\\rn << 5) | \\pd\n .endm\n"
        /* mov zd.d, xn (dup) */
        "    .macro DUP_D zd, rn\n .inst 0x05e03800 | (\\rn << 5) | \\zd\n .endm\n"
        /* index zd.d, #a, #b */
        "    .macro INDEX_D zd, a, b\n"
        "    .inst 0x04e04000 | ((\\b) << 16) | ((\\a) << 5) | \\zd\n .endm\n"
        /* add zd.d, zn.d, zm.d */
        "    .macro ADD_D zd, zn, zm\n"
        "    .inst 0x04e00000 | (\\zm << 16) | (\\zn << 5) | \\zd\n .endm\n"
        /* add zdn.d, zdn.d, #imm */
        "    .macro ADDI_D zdn, imm\n .inst 0x25e0c000 | ((\\imm) << 5) | \\zdn\n .endm\n"
        /* st1d {zt.d}, pg, [xn] / ld1d {zt.d}, pg/z, [xn] */
        "    .macro ST1D zt, pg, rn\n"
        "    .inst 0xe5e0e000 | (\\pg << 10) | (\\rn << 5) | \\zt\n .endm\n"
        "    .macro LD1D zt, pg, rn\n"
        "    .inst 0xa5e0a000 | (\\pg << 10) | (\\rn << 5) | \\zt\n .endm\n"
        /* str zt, [xn, #imm, mul vl] / str pt, [xn, #imm, mul vl] */
        "    .macro STR_Z zt, rn, imm\n"
        "    .inst 0xe5804000 | (((\\imm) & 7) << 10) | (((\\imm) >> 3) << 16) | "
        "(\\rn << 5) | \\zt\n .endm\n"
        "    .macro STR_P pt, rn, imm\n"
        "    .inst 0xe5800000 | (((\\imm) & 7) << 10) | (((\\imm) >> 3) << 16) | "
        "(\\rn << 5) | \\pt\n .endm\n"
        /* ldr za[w12, #imm], [xn, #imm, mul vl] / str za[w12, #imm], [...] */
        "    .macro LDR_ZA imm, rn\n .inst 0xe1000000 | (\\rn << 5) | (\\imm)\n .endm\n"
        "    .macro STR_ZA imm, rn\n .inst 0xe1200000 | (\\rn << 5) | (\\imm)\n .endm\n"
        /* mova za0h.s[w12, #i], pg/m, zn.s / mova zd.s, pg/m, za0h.s[w12, #i] */
        "    .macro MOVA_TO_ZA0H_S i, pg, zn\n"
        "    .inst 0xc0800000 | (\\pg << 10) | (\\zn << 5) | (\\i)\n .endm\n"
        "    .macro MOVA_FROM_ZA0H_S zd, pg, i\n"
        "    .inst 0xc0820000 | (\\pg << 10) | ((\\i) << 5) | \\zd\n .endm\n"
        /* Prologue: x19 = out, x20 = in; GPRs and Q registers from in. */
        "    .macro TPRO\n"
        "    stp x29, x30, [sp, #-176]!\n"
        "    mov x29, sp\n"
        "    stp x19, x20, [sp, #16]\n"
        "    stp x21, x22, [sp, #32]\n"
        "    stp x23, x24, [sp, #48]\n"
        "    stp x25, x26, [sp, #64]\n"
        "    stp x27, x28, [sp, #80]\n"
        "    stp d8, d9, [sp, #96]\n"
        "    stp d10, d11, [sp, #112]\n"
        "    stp d12, d13, [sp, #128]\n"
        "    stp d14, d15, [sp, #144]\n"
        "    mov x19, x0\n"
        "    mov x20, x1\n"
        "    add x16, x20, #I_Q\n"
        "    ldp q0, q1, [x16, #0]\n"
        "    ldp q2, q3, [x16, #32]\n"
        "    ldp q4, q5, [x16, #64]\n"
        "    ldp q6, q7, [x16, #96]\n"
        "    ldp q8, q9, [x16, #128]\n"
        "    ldp q10, q11, [x16, #160]\n"
        "    ldp q12, q13, [x16, #192]\n"
        "    ldp q14, q15, [x16, #224]\n"
        "    ldp q16, q17, [x16, #256]\n"
        "    ldp q18, q19, [x16, #288]\n"
        "    ldp q20, q21, [x16, #320]\n"
        "    ldp q22, q23, [x16, #352]\n"
        "    ldp q24, q25, [x16, #384]\n"
        "    ldp q26, q27, [x16, #416]\n"
        "    ldp q28, q29, [x16, #448]\n"
        "    ldp q30, q31, [x16, #480]\n"
        "    ldp x0, x1, [x20, #0]\n"
        "    ldp x2, x3, [x20, #16]\n"
        "    ldp x4, x5, [x20, #32]\n"
        "    ldp x6, x7, [x20, #48]\n"
        "    ldp x8, x9, [x20, #64]\n"
        "    ldp x10, x11, [x20, #80]\n"
        "    ldp x12, x13, [x20, #96]\n"
        "    ldp x14, x15, [x20, #112]\n"
        "    ldp x16, x17, [x20, #128]\n"
        "    ldr x21, [x20, #168]\n"
        "    ldp x22, x23, [x20, #176]\n"
        "    ldp x24, x25, [x20, #192]\n"
        "    ldp x26, x27, [x20, #208]\n"
        "    ldr x28, [x20, #224]\n"
        "    .endm\n"
        /* Epilogue: GPRs, FPSR/FPCR, SVCR and Q registers to out; return. */
        "    .macro TEPI\n"
        "    stp x0, x1, [x19, #0]\n"
        "    stp x2, x3, [x19, #16]\n"
        "    stp x4, x5, [x19, #32]\n"
        "    stp x6, x7, [x19, #48]\n"
        "    stp x8, x9, [x19, #64]\n"
        "    stp x10, x11, [x19, #80]\n"
        "    stp x12, x13, [x19, #96]\n"
        "    stp x14, x15, [x19, #112]\n"
        "    stp x16, x17, [x19, #128]\n"
        "    str x21, [x19, #168]\n"
        "    stp x22, x23, [x19, #176]\n"
        "    stp x24, x25, [x19, #192]\n"
        "    stp x26, x27, [x19, #208]\n"
        "    str x28, [x19, #224]\n"
        "    mrs x16, fpsr\n"
        "    str x16, [x19, #O_FPSR]\n"
        "    mrs x16, fpcr\n"
        "    str x16, [x19, #O_FPCR]\n"
        "    MRS_SVCR 16\n"
        "    str x16, [x19, #248]\n"
        "    add x16, x19, #O_Q\n"
        "    stp q0, q1, [x16, #0]\n"
        "    stp q2, q3, [x16, #32]\n"
        "    stp q4, q5, [x16, #64]\n"
        "    stp q6, q7, [x16, #96]\n"
        "    stp q8, q9, [x16, #128]\n"
        "    stp q10, q11, [x16, #160]\n"
        "    stp q12, q13, [x16, #192]\n"
        "    stp q14, q15, [x16, #224]\n"
        "    stp q16, q17, [x16, #256]\n"
        "    stp q18, q19, [x16, #288]\n"
        "    stp q20, q21, [x16, #320]\n"
        "    stp q22, q23, [x16, #352]\n"
        "    stp q24, q25, [x16, #384]\n"
        "    stp q26, q27, [x16, #416]\n"
        "    stp q28, q29, [x16, #448]\n"
        "    stp q30, q31, [x16, #480]\n"
        "    ldp d14, d15, [sp, #144]\n"
        "    ldp d12, d13, [sp, #128]\n"
        "    ldp d10, d11, [sp, #112]\n"
        "    ldp d8, d9, [sp, #96]\n"
        "    ldp x27, x28, [sp, #80]\n"
        "    ldp x25, x26, [sp, #64]\n"
        "    ldp x23, x24, [sp, #48]\n"
        "    ldp x21, x22, [sp, #32]\n"
        "    ldp x19, x20, [sp, #16]\n"
        "    ldp x29, x30, [sp], #176\n"
        "    ret\n"
        "    .endm\n"
        /* Streaming state with content above bit 127 (needs PSTATE.SM): Q-register
         * loads/stores, scalar FP, GPR ops, SVE ops.
         */
        "    .macro SETZ\n"
        "    PTRUE_D 0\n"
        "    WHILELO_D 1, 31, 10\n"
        "    DUP_D 10, 11\n"
        "    INDEX_D 11, 1, 2\n"
        "    ADD_D 12, 10, 11\n"
        "    ADDI_D 13, 7\n"
        "    add x14, x20, #I_Q\n"
        "    ldp q2, q3, [x14, #32]\n"
        "    ldr q4, [x14, #64]\n"
        "    ldr q5, [x14, #80]\n"
        "    fadd d6, d2, d3\n"
        "    fmul d7, d4, d5\n"
        "    fmov d8, x12\n"
        "    mov x14, #13600\n" /* O_MEM */
        "    add x14, x19, x14\n"
        "    stp q2, q3, [x14]\n"
        "    str q6, [x14, #32]\n"
        "    ldr q9, [x14, #16]\n"
        "    add x13, x14, #64\n"
        "    ST1D 12, 1, 13\n"
        "    LD1D 14, 0, 13\n"
        "    add x2, x2, x3\n"
        "    eor x4, x4, x5\n"
        "    mul x6, x6, x7\n"
        "    RDSVL 8\n"
        "    CNTD 9\n"
        "    MRS_SVCR 15\n"
        "    .endm\n"
        "    .macro DUMPZ\n"
        "    mov x17, #800\n" /* O_Z */
        "    add x17, x19, x17\n"
        "    .irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,"
        "25,26,27,28,29,30,31\n"
        "    STR_Z \\i, 17, \\i\n"
        "    .endr\n"
        "    .endm\n"
        "    .macro DUMPP\n"
        "    mov x17, #8992\n" /* O_P */
        "    add x17, x19, x17\n"
        "    .irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15\n"
        "    STR_P \\i, 17, \\i\n"
        "    .endr\n"
        "    .endm\n"
        "    .macro LOADZA\n"
        "    add x16, x20, #I_ZA\n"
        "    mov w12, #0\n"
        "    .irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15\n"
        "    LDR_ZA \\i, 16\n"
        "    .endr\n"
        "    .endm\n"
        "    .macro DUMPZA\n"
        "    mov x17, #9504\n" /* O_ZA */
        "    add x17, x19, x17\n"
        "    mov w12, #0\n"
        "    .irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15\n"
        "    STR_ZA \\i, 17\n"
        "    .endr\n"
        "    .endm\n"
        /* Says it is ready (out->pad = 1) and spins until the handler of the
         * signal another thread then sends sets out->pad to 2.
         */
        "    .macro ASYNC_SPIN\n"
        "    mov x9, #1\n"
        "    str x9, [x19, #280]\n"
        "1:  ldr x9, [x19, #280]\n" /* SPIN_LDR */
        "    cmp x9, #2\n"          /* SPIN_CMP */
        "    b.ne 1b\n"             /* SPIN_BNE */
        "    .endm\n"
        /* The templates: void t(out_t *out, const in_t *in). */
        "    .text\n"
        "    .p2align 6\n"
        "    .globl sme_tmpl_lo\n"
        "sme_tmpl_lo:\n"
        "    .p2align 4\n"
        "sme_t_sm_basic:\n"
        "    TPRO\n"
        "    SMSTART_SM\n"
        "    SETZ\n"
        "    DUMPZ\n"
        "    DUMPP\n"
        "    SMSTOP_SM\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_za_basic:\n"
        "    TPRO\n"
        "    SMSTART_ZA\n"
        "    ZERO_ZA\n"
        "    LOADZA\n"
        "    add v1.4s, v1.4s, v2.4s\n"
        "    MRS_SVCR 15\n"
        "    DUMPZA\n"
        "    SMSTOP_ZA\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_smza_basic:\n"
        "    TPRO\n"
        "    SMSTART_ALL\n"
        "    ZERO_ZA\n"
        "    SETZ\n"
        "    LOADZA\n"
        "    PTRUE_S 2\n"
        "    MOVA_TO_ZA0H_S 0, 2, 12\n"
        "    MOVA_FROM_ZA0H_S 15, 2, 1\n"
        "    MRS_SVCR 15\n"
        "    DUMPZ\n"
        "    DUMPP\n"
        "    DUMPZA\n"
        "    SMSTOP_ALL\n"
        "    TEPI\n"
        /* Transitions while streaming. */
        "    .p2align 4\n"
        "sme_t_sm_direct:\n"
        "    TPRO\n"
        "    SMSTART_SM\n"
        "    SETZ\n"
        "    b 1f\n"
        "1:  ADDI_D 13, 1\n"
        "    DUMPZ\n"
        "    DUMPP\n"
        "    SMSTOP_SM\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_leaf:\n"
        "    add x3, x3, #1\n"
        "    ret\n"
        "    .p2align 4\n"
        "sme_t_sm_ibr:\n"
        "    TPRO\n"
        "    SMSTART_SM\n"
        "    SETZ\n"
        "    adr x9, 1f\n"
        "    br x9\n"
        "1:  bl sme_leaf\n"
        "    ADDI_D 13, 1\n"
        "    DUMPZ\n"
        "    DUMPP\n"
        "    SMSTOP_SM\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_sm_svc:\n"
        "    TPRO\n"
        "    SMSTART_SM\n"
        "    SETZ\n"
        "    mov x8, #173\n" /* getppid: equal in both children */
        "    svc #0\n"
        /* Linux exits streaming mode at a syscall (Z/P discarded, as if by
         * smstop sm): only non-streaming state can be checked after it.
         */
        "    MRS_SVCR 15\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_sm_cc:\n"
        "    TPRO\n"
        "    SMSTART_SM\n"
        "    SETZ\n"
        "    hint #127\n" /* clean call marker */
        "    ADDI_D 13, 1\n"
        "    DUMPZ\n"
        "    DUMPP\n"
        "    SMSTOP_SM\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_sm_cc_neon:\n"
        "    TPRO\n"
        "    SMSTART_SM\n"
        "    SETZ\n"
        "    hint #126\n" /* clean call marker: the callee uses AdvSIMD */
        "    ADDI_D 13, 1\n"
        "    DUMPZ\n"
        "    DUMPP\n"
        "    SMSTOP_SM\n"
        "    TEPI\n"
        /* Transitions while only ZA is live. */
        "    .p2align 4\n"
        "sme_t_za_ibr:\n"
        "    TPRO\n"
        "    SMSTART_ZA\n"
        "    ZERO_ZA\n"
        "    LOADZA\n"
        "    adr x9, 1f\n"
        "    br x9\n"
        "1:  bl sme_leaf\n"
        "    add v1.4s, v1.4s, v2.4s\n"
        "    MRS_SVCR 15\n"
        "    DUMPZA\n"
        "    SMSTOP_ZA\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_za_svc:\n"
        "    TPRO\n"
        "    SMSTART_ZA\n"
        "    ZERO_ZA\n"
        "    LOADZA\n"
        "    mov x8, #173\n"
        "    svc #0\n"
        "    MRS_SVCR 15\n"
        "    DUMPZA\n"
        "    SMSTOP_ZA\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_za_cc:\n"
        "    TPRO\n"
        "    SMSTART_ZA\n"
        "    ZERO_ZA\n"
        "    LOADZA\n"
        "    hint #127\n"
        "    MRS_SVCR 15\n"
        "    DUMPZA\n"
        "    SMSTOP_ZA\n"
        "    TEPI\n"
        /* Signals. */
        "    .p2align 4\n"
        "sme_t_sm_brk:\n"
        "    TPRO\n"
        "    SMSTART_SM\n"
        "    SETZ\n"
        "    brk #0x5e\n"
        "    ADDI_D 13, 1\n"
        "    DUMPZ\n"
        "    DUMPP\n"
        "    SMSTOP_SM\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_smza_brk:\n"
        "    TPRO\n"
        "    SMSTART_ALL\n"
        "    ZERO_ZA\n"
        "    SETZ\n"
        "    LOADZA\n"
        "    brk #0x5e\n"
        "    DUMPZ\n"
        "    DUMPP\n"
        "    DUMPZA\n"
        "    SMSTOP_ALL\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_za_brk:\n"
        "    TPRO\n"
        "    SMSTART_ZA\n"
        "    ZERO_ZA\n"
        "    LOADZA\n"
        "    brk #0x5e\n"
        "    MRS_SVCR 15\n"
        "    DUMPZA\n"
        "    SMSTOP_ZA\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_sm_async:\n"
        "    TPRO\n"
        "    SMSTART_SM\n"
        "    SETZ\n"
        "    ASYNC_SPIN\n"
        "    ADDI_D 13, 1\n"
        "    DUMPZ\n"
        "    DUMPP\n"
        "    SMSTOP_SM\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_smza_async:\n"
        "    TPRO\n"
        "    SMSTART_ALL\n"
        "    ZERO_ZA\n"
        "    SETZ\n"
        "    LOADZA\n"
        "    ASYNC_SPIN\n"
        "    DUMPZ\n"
        "    DUMPP\n"
        "    DUMPZA\n"
        "    SMSTOP_ALL\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_za_async:\n"
        "    TPRO\n"
        "    SMSTART_ZA\n"
        "    ZERO_ZA\n"
        "    LOADZA\n"
        "    ASYNC_SPIN\n"
        "    MRS_SVCR 15\n"
        "    DUMPZA\n"
        "    SMSTOP_ZA\n"
        "    TEPI\n"
        "    .p2align 4\n"
        "sme_t_sm_illegal:\n"
        "    TPRO\n"
        "    SMSTART_SM\n"
        "    SETZ\n"
        "    add v0.4s, v1.4s, v2.4s\n" /* illegal in streaming mode without FA64 */
        "    ADDI_D 13, 1\n"
        "    DUMPZ\n"
        "    DUMPP\n"
        "    SMSTOP_SM\n"
        "    TEPI\n"
        "    .globl sme_tmpl_hi\n"
        "sme_tmpl_hi:\n"
        /* Warm-up signals outside streaming mode (see child_main()). */
        "    .p2align 4\n"
        "    .globl sme_warm_brk\n"
        "sme_warm_brk:\n" /* the handler writes x25 */
        "    str x25, [sp, #-16]!\n"
        "    brk #0x5e\n"
        "    ldr x25, [sp], #16\n"
        "    ret\n"
        "    .globl sme_warm_udf\n"
        "sme_warm_udf:\n"
        "    str x25, [sp, #-16]!\n"
        "    .inst 0x00000000\n" /* udf #0 */
        "    ldr x25, [sp], #16\n"
        "    ret\n"
        "    .globl sme_warm_spin\n"
        "sme_warm_spin:\n" /* x0 = out: ASYNC_SPIN outside streaming mode */
        "    stp x19, x25, [sp, #-16]!\n"
        "    mov x19, x0\n"
        "    ASYNC_SPIN\n"
        "    ldp x19, x25, [sp], #16\n"
        "    ret\n"
        "    .globl sme_t_sm_basic, sme_t_za_basic, sme_t_smza_basic, sme_t_sm_direct\n"
        "    .globl sme_t_sm_ibr, sme_t_sm_svc, sme_t_sm_cc, sme_t_sm_cc_neon\n"
        "    .globl sme_t_za_ibr, sme_t_za_svc, sme_t_za_cc, sme_t_sm_brk\n"
        "    .globl sme_t_smza_brk, sme_t_za_brk, sme_t_sm_async, sme_t_smza_async, "
        "sme_t_za_async, sme_t_sm_illegal\n");

typedef void (*tmpl_fn_t)(out_t *out, const in_t *in);
extern const char sme_tmpl_lo[], sme_tmpl_hi[];
extern void
sme_warm_brk(void);
extern void
sme_warm_udf(void);
extern void
sme_warm_spin(out_t *out);
#define DECL_T(n) extern void sme_t_##n(out_t *out, const in_t *in)
DECL_T(sm_basic);
DECL_T(za_basic);
DECL_T(smza_basic);
DECL_T(sm_direct);
DECL_T(sm_ibr);
DECL_T(sm_svc);
DECL_T(sm_cc);
DECL_T(sm_cc_neon);
DECL_T(za_ibr);
DECL_T(za_svc);
DECL_T(za_cc);
DECL_T(sm_brk);
DECL_T(smza_brk);
DECL_T(za_brk);
DECL_T(sm_async);
DECL_T(smza_async);
DECL_T(za_async);
DECL_T(sm_illegal);

enum { USES_Z = 1, USES_ZA = 2, SIG_TRAP = 4, SIG_USR1 = 8, SIG_ILL = 16, CC = 32 };

typedef struct {
    const char *name;
    tmpl_fn_t fn;
    int flags;
} tmpl_t;

static const tmpl_t tmpls[] = {
    { "sm_basic", sme_t_sm_basic, USES_Z },
    { "za_basic", sme_t_za_basic, USES_ZA },
    { "smza_basic", sme_t_smza_basic, USES_Z | USES_ZA },
    { "sm_direct", sme_t_sm_direct, USES_Z },
    { "sm_ibr", sme_t_sm_ibr, USES_Z },
    { "sm_svc", sme_t_sm_svc, USES_Z },
    { "sm_cc", sme_t_sm_cc, USES_Z | CC },
    { "sm_cc_neon", sme_t_sm_cc_neon, USES_Z | CC },
    { "za_ibr", sme_t_za_ibr, USES_ZA },
    { "za_svc", sme_t_za_svc, USES_ZA },
    { "za_cc", sme_t_za_cc, USES_ZA | CC },
    { "sm_brk", sme_t_sm_brk, USES_Z | SIG_TRAP },
    { "smza_brk", sme_t_smza_brk, USES_Z | USES_ZA | SIG_TRAP },
    { "za_brk", sme_t_za_brk, USES_ZA | SIG_TRAP },
    { "sm_async", sme_t_sm_async, USES_Z | SIG_USR1 },
    { "smza_async", sme_t_smza_async, USES_Z | USES_ZA | SIG_USR1 },
    { "za_async", sme_t_za_async, USES_ZA | SIG_USR1 },
    { "sm_illegal", sme_t_sm_illegal, USES_Z | SIG_ILL },
};
#define NTMPL ((int)(sizeof(tmpls) / sizeof(tmpls[0])))

/* Known divergences of today's DR, which has no SME support (2026-10-14).
 * They run and are reported (with the outcome, which can differ between debug
 * and release DR); they only fail the test with -known.  The mechanisms:
 *
 * sme-dr-in-streaming: DR runs its own compiled C code (the dispatcher, the
 *   block builder, signal delivery) in whatever mode the application left.
 *   With PSTATE.SM set, AdvSIMD instructions in that code are illegal (no
 *   FEAT_SME_FA64): e.g. the "movi v31.4s, #0" the compiler emits in
 *   init_build_bb() (core/arch/interp.c) raises SIGILL inside DR, which a
 *   debug DR reports as "signal.c:5956 false" (a signal in DR code) and a
 *   release DR as "Tool internal crash".  Building any block while streaming
 *   triggers it: a direct branch or IBL miss to a new block, a loop head, the
 *   resume point after a signal handler.
 * sme-zupper-lost: DR's context switch and clean-call SIMD save/restore use
 *   Q registers (this CPU has no SVE, so FEATURE_SVE is off).  In streaming
 *   mode Q-register loads are legal but zero bits 128 and up of the Z
 *   registers, so streaming Z state above the V registers is lost across any
 *   clean call or trip through DR (P registers survive: DR does not write
 *   them).
 * sme-callee-streaming: clean-call callees (client code) run with PSTATE.SM
 *   set; a callee that uses AdvSIMD (as compiled code routinely does) raises
 *   SIGILL inside the client.
 * sme-handler-mode: the kernel enters signal handlers with PSTATE.SM and
 *   PSTATE.ZA clear and the state in the frame; DR enters the application's
 *   handler with the interrupted SVCR still set (DR's own handler returns
 *   through the kernel's frame, whose SVE/ZA records restore the mode), so a
 *   handler using AdvSIMD (e.g. glibc's memset) raises SIGILL.
 *
 * An entry can be limited to state divergences: then a crash, a hang or an
 * unexpected application signal is not the known issue and fails the test.
 * The ZA templates' frames have an EXTRA record, which DR used to leave
 * pointing into its own signal stack, so that the kernel rejected the
 * application's rt_sigreturn with SIGSEGV; they must now get through.
 */
typedef struct {
    const char *tmpl; /* template/mode */
    const char *id;
    int state_only; /* only explains a divergence in state */
} known_t;
static const known_t known_issues[] = {
    { "sm_direct/cold", "sme-dr-in-streaming" },
    { "sm_ibr/cold", "sme-dr-in-streaming" },
    { "sm_cc/cold", "sme-zupper-lost" },
    { "sm_cc/warm", "sme-zupper-lost" },
    { "sm_cc_neon/cold", "sme-callee-streaming" },
    { "sm_cc_neon/warm", "sme-callee-streaming" },
    { "sm_brk/cold", "sme-handler-mode,sme-dr-in-streaming" },
    { "sm_brk/warm", "sme-handler-mode,sme-zupper-lost" },
    { "smza_brk/cold", "sme-handler-mode,sme-dr-in-streaming" },
    { "smza_brk/warm", "sme-handler-mode,sme-zupper-lost", 1 },
    { "za_brk/cold", "sme-handler-mode", 1 },
    { "za_brk/warm", "sme-handler-mode", 1 },
    { "sm_async/cold", "sme-dr-in-streaming" },
    { "sm_async/warm", "sme-dr-in-streaming,sme-zupper-lost" },
    { "smza_async/cold", "sme-dr-in-streaming" },
    { "smza_async/warm", "sme-dr-in-streaming" },
    { "za_async/cold", "sme-handler-mode", 1 },
    { "za_async/warm", "sme-handler-mode", 1 },
    { "sm_illegal/cold", "sme-handler-mode,sme-dr-in-streaming" },
    { "sm_illegal/warm", "sme-handler-mode,sme-dr-in-streaming" },
};

/* The spin loop's instructions (ASYNC_SPIN). */
#define SPIN_LDR 0xf9408e69 /* ldr x9, [x19, #280] */
#define SPIN_CMP 0xf100093f /* cmp x9, #2 */
#define SPIN_BNE 0x54000001 /* b.ne (any offset) */

/***************************************************************************
 * What a signal handler saw.
 */
typedef struct {
    int signo, code;
    uint64_t pc_off;
    uint32_t insn;
    uint64_t pstate, svcr_in;
    int frame_ok;
    int sve_present, sve_vl, sve_flags, sve_data;
    int za_present, za_vl, za_data;
    uint32_t fpsr, fpcr;
    uint64_t xhash, vhash, zhash, phash, zahash;
    /* An EXTRA record's data pointer relative to the end of __reserved. */
    int extra_present;
    int64_t extra_delta;
    /* How far the handler got (4: to the end). */
    int stage;
} hrec_t;

#define MAXRUNS 4
#define MAXH 2

/* Shared with the parent. */
typedef struct {
    volatile int runs_done;
    volatile int unexpected_sig;
    uint64_t unexpected_pc, unexpected_svcr, unexpected_addr;
    uint32_t unexpected_insn;
    volatile long cc_count;
    volatile uint64_t cc_svcr;
    volatile long pre_count;
    volatile uint64_t pre_svcr;
    /* SVCR at the planned handler's entry, written before it calls anything
     * (natively the kernel runs handlers with PSTATE.SM and PSTATE.ZA clear).
     */
    volatile uint64_t entry_svcr[MAXRUNS];
    char frame_err[160];
    out_t out[MAXRUNS];
    hrec_t h[MAXRUNS][MAXH];
    int nh[MAXRUNS];
} shres_t;

static shres_t *g_res;
static int g_run;
static int g_svl;
static int verbose;
static in_t g_in;
static out_t g_out;
static uint64_t g_tmpl_lo;

static inline uint64_t
read_svcr(void)
{
    register uint64_t x0 __asm__("x0");
    __asm__ volatile(".inst 0xd53b4240" : "=r"(x0)); /* mrs x0, svcr */
    return x0;
}

static struct a64p_rec_head *
find_rec(ucontext_t *uc, uint32_t magic)
{
    return a64p_find_rec(uc, magic);
}

static void
planned_handler(int sig, siginfo_t *si, void *ucv)
{
    uint64_t svcr = read_svcr();
    /* The kernel enters handlers with PSTATE.SM and PSTATE.ZA clear (the
     * frame holds that state).  If they are not (under DR), record it -- a
     * divergence -- and clear them, so that this (compiled, AdvSIMD-using)
     * handler can go on to check the frame and its edits.  Unconditionally
     * (a no-op when they are clear): a branch would need a new block, which
     * DR would build in streaming mode.
     */
    __asm__ volatile(".inst 0xd503467f" ::: "memory"); /* smstop */
    ucontext_t *uc = (ucontext_t *)ucv;
    int r = g_run;
    if (r < 0 || r >= MAXRUNS || g_res->nh[r] >= MAXH)
        _exit(97);
    g_res->entry_svcr[r] = svcr | (1ULL << 63);
    hrec_t *h = &g_res->h[r][g_res->nh[r]++];
    memset(h, 0, sizeof(*h));
    h->svcr_in = svcr;
    h->stage = 1;
    h->signo = sig;
    h->code = si->si_code;
    uint64_t pc = uc->uc_mcontext.pc;
    h->pc_off = pc - g_tmpl_lo;
    h->insn = *(uint32_t *)(uintptr_t)pc;
    if (sig == SIGUSR1) {
        /* Asynchronous: anywhere in the template's spin loop. */
        int in_spin = pc >= g_tmpl_lo && pc < (uint64_t)(uintptr_t)sme_tmpl_hi &&
            (h->insn == SPIN_LDR || h->insn == SPIN_CMP ||
             (h->insn & 0xff00001f) == SPIN_BNE);
        h->pc_off = in_spin ? 1 : h->pc_off | (1ULL << 40);
        h->insn = 0;
        __atomic_store_n(&g_out.pad, 2, __ATOMIC_RELEASE);
    }
    h->pstate = uc->uc_mcontext.pstate & ~(PSTATE_BTYPE | PSTATE_SSBS);
    uint64_t layout;
    int svl, zavl;
    char err[160];
    h->stage = 2;
    h->frame_ok =
        a64p_check_frame_records(uc, &layout, &svl, &zavl, err, sizeof(err)) == 0;
    h->stage = 3;
    if (!h->frame_ok)
        snprintf(g_res->frame_err, sizeof(g_res->frame_err), "%s", err);
    /* x0/x1 and x16-x22 are inputs, pointers or scratch. */
    uint64_t xh = 0;
    for (int i = 2; i < 16; i++)
        xh = a64p_hash_bytes(&uc->uc_mcontext.regs[i], 8, xh);
    for (int i = 23; i < 29; i++)
        xh = a64p_hash_bytes(&uc->uc_mcontext.regs[i], 8, xh);
    h->xhash = xh;
    {
        uint8_t *p = (uint8_t *)uc->uc_mcontext.__reserved;
        uint8_t *end = p + sizeof(uc->uc_mcontext.__reserved);
        while (p + sizeof(struct a64p_rec_head) <= end) {
            struct a64p_rec_head *rh = (struct a64p_rec_head *)p;
            if (rh->magic == 0 || rh->size == 0)
                break;
            if (rh->magic == EXTRA_MAGIC_) {
                h->extra_present = 1;
                h->extra_delta = (int64_t)(((struct a64p_extra_rec *)rh)->datap -
                                           (uint64_t)(uintptr_t)end);
            }
            p += rh->size;
        }
    }
    struct a64p_fpsimd_rec *fp = (struct a64p_fpsimd_rec *)find_rec(uc, FPSIMD_MAGIC_);
    if (fp != NULL) {
        h->fpsr = fp->fpsr;
        h->fpcr = fp->fpcr;
        h->vhash = a64p_hash_bytes(fp->v, sizeof(fp->v), 1);
    }
    uint8_t *sve = (uint8_t *)find_rec(uc, SVE_REC_MAGIC);
    if (sve != NULL) {
        uint32_t size = ((struct a64p_rec_head *)sve)->size;
        h->sve_present = 1;
        h->sve_vl = *(uint16_t *)(sve + 8);
        h->sve_flags = *(uint16_t *)(sve + 10);
        int vq = h->sve_vl / 16;
        h->sve_data = vq > 0 && size >= SVE_CTX_SIZE(vq);
        if (h->sve_data) {
            h->zhash = a64p_hash_bytes(sve + SVE_ZREG_OFF(vq, 0), 32 * vq * 16, 1);
            h->phash = a64p_hash_bytes(sve + SVE_PREG_OFF(vq, 0), 16 * vq * 2, 1);
            /* Edits that must apply on return: a Z byte above bit 127 and a
             * predicate.
             */
            if (vq > 1)
                sve[SVE_ZREG_OFF(vq, 12) + 16 + 8] ^= 0xa5;
            sve[SVE_PREG_OFF(vq, 3)] ^= 0x55;
        }
    }
    uint8_t *za = (uint8_t *)find_rec(uc, ZA_REC_MAGIC);
    if (za != NULL) {
        uint32_t size = ((struct a64p_rec_head *)za)->size;
        h->za_present = 1;
        h->za_vl = *(uint16_t *)(za + 8);
        h->za_data = h->za_vl > 0 &&
            size >= REC_REGS_OFFSET + (uint32_t)h->za_vl * (uint32_t)h->za_vl;
        if (h->za_data) {
            h->zahash = a64p_hash_bytes(za + REC_REGS_OFFSET, ZA_ROWS * h->za_vl, 1);
            za[REC_REGS_OFFSET + 2 * h->za_vl + 7] ^= 0x3c;
        }
    }
    uc->uc_mcontext.regs[25] = 0x5eed0000ULL + (uint64_t)sig;
    h->stage = 4;
    if (sig != SIGUSR1)
        uc->uc_mcontext.pc += 4;
}

static void
unexpected_handler(int sig, siginfo_t *si, void *ucv)
{
    uint64_t svcr = read_svcr();
    ucontext_t *uc = (ucontext_t *)ucv;
    g_res->unexpected_svcr = svcr;
    g_res->unexpected_pc = uc->uc_mcontext.pc;
    g_res->unexpected_addr = (uint64_t)(uintptr_t)si->si_addr;
    g_res->unexpected_insn = *(uint32_t *)(uintptr_t)uc->uc_mcontext.pc;
    g_res->unexpected_sig = sig;
    _exit(42);
}

static void
install_handlers(int flags)
{
    static const int sigs[] = { SIGILL, SIGTRAP, SIGSEGV, SIGBUS, SIGFPE, SIGUSR1 };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        int planned = (sigs[i] == SIGTRAP && (flags & SIG_TRAP)) ||
            (sigs[i] == SIGUSR1 && (flags & SIG_USR1)) ||
            (sigs[i] == SIGILL && (flags & SIG_ILL));
        sa.sa_sigaction = planned ? planned_handler : unexpected_handler;
        sa.sa_flags = SA_SIGINFO;
        sigaction(sigs[i], &sa, NULL);
    }
}

/***************************************************************************
 * The in-process client: a clean call at each marker hint in the templates.
 */
static void
cc_plain(void)
{
    g_res->cc_svcr = read_svcr();
    __atomic_add_fetch(&g_res->cc_count, 1, __ATOMIC_RELAXED);
}

static void
cc_neon(void)
{
    g_res->cc_svcr = read_svcr();
    /* What compiled client code routinely does (e.g. zeroing a structure). */
    __asm__ volatile("movi v16.16b, #1\n\t"
                     "add v16.4s, v16.4s, v16.4s" ::
                         : "v16");
    __atomic_add_fetch(&g_res->cc_count, 1, __ATOMIC_RELAXED);
}

static dr_emit_flags_t
event_bb(void *dc, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    for (instr_t *in = instrlist_first_app(bb); in != NULL; in = instr_get_next_app(in)) {
        app_pc pc = instr_get_app_pc(in);
        if (pc < (app_pc)sme_tmpl_lo || pc >= (app_pc)sme_tmpl_hi)
            continue;
        uint32_t w = *(uint32_t *)pc;
        if (w == 0xd5032fff) /* hint #127 */
            dr_insert_clean_call(dc, bb, in, (void *)cc_plain, false, 0);
        else if (w == 0xd5032fdf) /* hint #126 */
            dr_insert_clean_call(dc, bb, in, (void *)cc_neon, false, 0);
    }
    return DR_EMIT_DEFAULT;
}

/* The getppid of the svc templates: in which mode DR's syscall handling and a
 * client's pre-syscall event run.
 */
static bool
event_filter_syscall(void *dc, int sysnum)
{
    return sysnum == SYS_getppid;
}

static bool
event_pre_syscall(void *dc, int sysnum)
{
    if (sysnum == SYS_getppid) {
        g_res->pre_svcr = read_svcr();
        __atomic_add_fetch(&g_res->pre_count, 1, __ATOMIC_RELAXED);
    }
    return true;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_register_bb_event(event_bb);
    dr_register_filter_syscall_event(event_filter_syscall);
    dr_register_pre_syscall_event(event_pre_syscall);
}

/***************************************************************************
 * Running a template in a child.
 */
static void
init_input(in_t *in)
{
    memset(in, 0, sizeof(*in));
    rng_t r = { 0x5e5eULL };
    for (int i = 0; i < 32; i++)
        in->x[i] = rnext(&r);
    in->x[10] = 3; /* whilelo bound */
    for (int i = 0; i < 32; i++) {
        in->q[i] = ((__uint128_t)rnext(&r) << 64) | rnext(&r);
    }
    /* Plausible doubles for the scalar FP ops. */
    for (int i = 2; i < 6; i++)
        in->q[i] = (__uint128_t)(0x3ff0000000000000ULL + (rnext(&r) >> 12));
    for (size_t i = 0; i < sizeof(in->za); i++)
        in->za[i] = (uint8_t)(rnext(&r) | 1);
}

/* dr: 0 native, 1 "cold" (DR builds each block when first executed),
 * 2 "warm" (every block of the templates is built before dr_app_start(), with
 * dr_prepopulate_cache(), so that only the transitions themselves remain).
 */
typedef struct {
    int t, dr, runs;
} child_arg_t;

static int
is_block_end(uint32_t w)
{
    return (w & 0x7c000000) == 0x14000000 || /* b, bl */
        (w & 0xff000010) == 0x54000000 ||    /* b.cond */
        (w & 0x7e000000) == 0x34000000 ||    /* cbz, cbnz */
        (w & 0x7e000000) == 0x36000000 ||    /* tbz, tbnz */
        (w & 0xff9ffc1f) == 0xd61f0000 ||    /* br, blr, ret */
        (w & 0xffe0001f) == 0xd4000001 ||    /* svc */
        (w & 0xffe0001f) == 0xd4200000;      /* brk */
}

/* Block starts in the templates: each template, after each branch, svc or
 * brk, and each direct branch target.
 */
static int
template_tags(app_pc *tags, int max)
{
    int n = 0;
    for (int i = 0; i < NTMPL && n < max; i++)
        tags[n++] = (app_pc)tmpls[i].fn;
    for (const uint32_t *p = (const uint32_t *)sme_tmpl_lo;
         p < (const uint32_t *)sme_tmpl_hi && n < max - 2; p++) {
        uint32_t w = *p;
        if (!is_block_end(w))
            continue;
        tags[n++] = (app_pc)(p + 1);
        int64_t off = 0;
        if ((w & 0x7c000000) == 0x14000000)
            off = (int64_t)((int32_t)(w << 6) >> 6) * 4;
        else if ((w & 0xff000010) == 0x54000000 || (w & 0x7e000000) == 0x34000000)
            off = (int64_t)((int32_t)((w >> 5) << 13) >> 13) * 4;
        if (off != 0)
            tags[n++] = (app_pc)p + off;
    }
    return n;
}

static void
start_dr_warm(void)
{
    static app_pc tags[1024];
    int n = template_tags(tags, 1024);
    if (dr_app_setup() != 0) {
        fprintf(stderr, "ERROR: dr_app_setup failed\n");
        _exit(3);
    }
    if (!dr_prepopulate_cache(tags, n) ||
        !dr_prepopulate_indirect_targets(DR_INDIRECT_JUMP, tags, n) ||
        !dr_prepopulate_indirect_targets(DR_INDIRECT_RETURN, tags, n)) {
        fprintf(stderr, "ERROR: dr_prepopulate_* failed\n");
        _exit(3);
    }
    dr_app_start();
    if (!dr_app_running_under_dynamorio()) {
        fprintf(stderr, "ERROR: not running under DR\n");
        _exit(3);
    }
}

static pid_t g_main_tid;

/* Sends SIGUSR1 to the template's thread once it spins in its loop. */
static void *
async_sender(void *arg)
{
    while (__atomic_load_n(&g_out.pad, __ATOMIC_ACQUIRE) != 1)
        sched_yield();
    syscall(SYS_tgkill, getpid(), g_main_tid, SIGUSR1);
    return NULL;
}

static int
child_main(child_arg_t *a)
{
    const tmpl_t *t = &tmpls[a->t];
    install_handlers(t->flags);
    g_run = -1;
    if (a->dr == 1)
        a64p_start_dr("");
    else if (a->dr == 2)
        start_dr_warm();
    /* Run the planned handler (recording into the spare slot) once outside
     * streaming mode, so that under DR its blocks exist before the first
     * signal that arrives while streaming.
     */
    g_run = MAXRUNS - 1;
    if (t->flags & SIG_TRAP)
        sme_warm_brk();
    if (t->flags & SIG_ILL)
        sme_warm_udf();
    if (t->flags & SIG_USR1) {
        pthread_t th;
        memset(&g_out, 0, sizeof(g_out));
        g_main_tid = (pid_t)syscall(SYS_gettid);
        if (pthread_create(&th, NULL, async_sender, NULL) != 0)
            return 1;
        sme_warm_spin(&g_out);
        pthread_join(th, NULL);
    }
    g_res->nh[MAXRUNS - 1] = 0;
    for (int r = 0; r < a->runs; r++) {
        memset(&g_out, 0, sizeof(g_out));
        g_run = r;
        pthread_t th;
        if (t->flags & SIG_USR1) {
            g_main_tid = (pid_t)syscall(SYS_gettid);
            if (pthread_create(&th, NULL, async_sender, NULL) != 0)
                return 1;
        }
        t->fn(&g_out, &g_in);
        if (t->flags & SIG_USR1)
            pthread_join(th, NULL);
        g_run = -1;
        g_out.svl = (uint64_t)g_svl;
        memcpy(&g_res->out[r], &g_out, sizeof(g_out));
        g_res->runs_done = r + 1;
    }
    if (a->dr)
        a64p_stop_dr();
    return 0;
}

enum {
    OUT_EQUIV,
    OUT_UNSUPPORTED,
    OUT_STATE,
    OUT_APP_SIGNAL,
    OUT_DR_CRASH,
    OUT_HANG,
    OUT_INCONCLUSIVE,
};
static const char *const out_names[] = {
    "equivalent",
    "unsupported",
    "divergence (state)",
    "divergence (unexpected app signal)",
    "divergence (DR crash)",
    "divergence (hang)",
    "inconclusive",
};

/* Runs a template in a forked child with stderr captured; returns the exit
 * classification and fills *res (a copy of the shared page) and errtext.
 */
static int
run_child(int t, int dr, int runs, shres_t *res, char *errtext, size_t errlen,
          int *status_out)
{
    memset(g_res, 0, sizeof(*g_res));
    char path[] = "/tmp/a64_prop_sme.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        exit(2);
    }
    unlink(path);
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fd, 2);
        close(fd);
        child_arg_t a = { t, dr, runs };
        int rc = child_main(&a);
        fflush(stderr);
        _exit(rc);
    }
    int st = 0, hang = 0;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid)
            break;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - t0.tv_sec > 15) {
            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
            hang = 1;
            break;
        }
        struct timespec ts = { 0, 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    *status_out = st;
    ssize_t n = pread(fd, errtext, errlen - 1, 0);
    errtext[n > 0 ? n : 0] = '\0';
    close(fd);
    memcpy(res, g_res, sizeof(*res));
    if (hang)
        return OUT_HANG;
    if (strstr(errtext, "SME") != NULL &&
        (strstr(errtext, "not supported") != NULL ||
         strstr(errtext, "unsupported") != NULL))
        return OUT_UNSUPPORTED;
    /* A fault in DR (or client) code that a release DR reports and then
     * passes to the application's handler is still a DR crash.
     */
    if (strstr(errtext, "Internal Error") != NULL || strstr(errtext, "ASSERT") != NULL ||
        strstr(errtext, "CURIOSITY") != NULL || strstr(errtext, "crash") != NULL ||
        strstr(errtext, "Unrecoverable") != NULL)
        return OUT_DR_CRASH;
    if (WIFEXITED(st) && WEXITSTATUS(st) == 42 && res->unexpected_sig != 0)
        return OUT_APP_SIGNAL;
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || res->runs_done != runs)
        return OUT_DR_CRASH;
    return OUT_EQUIV;
}

/* Names the template (and offset) containing pc, or prints it. */
static const char *
describe_pc(uint64_t pc, char *buf, size_t len)
{
    const tmpl_t *best = NULL;
    for (int i = 0; i < NTMPL; i++) {
        uint64_t a = (uint64_t)(uintptr_t)tmpls[i].fn;
        if (a <= pc && pc < (uint64_t)(uintptr_t)sme_tmpl_hi &&
            (best == NULL || a > (uint64_t)(uintptr_t)best->fn))
            best = &tmpls[i];
    }
    if (best != NULL) {
        snprintf(buf, len, "%s+0x%llx", best->name,
                 (unsigned long long)(pc - (uint64_t)(uintptr_t)best->fn));
    } else
        snprintf(buf, len, "pc 0x%llx (not in a template)", (unsigned long long)pc);
    return buf;
}

static const char *
first_err_line(const char *errtext, char *buf, size_t len)
{
    const char *keys[] = { "SIGILL", "Internal Error", "ASSERT", "CURIOSITY",
                           "crash",  "Unrecoverable",  "SME",    NULL };
    for (int k = 0; keys[k] != NULL; k++) {
        const char *p = strstr(errtext, keys[k]);
        if (p == NULL)
            continue;
        while (p > errtext && p[-1] != '\n')
            p--;
        /* Drop DR's "<Application PATH (PID).  " prefix. */
        const char *q = strstr(p, ").  ");
        if (q != NULL && q < p + strcspn(p, "\n"))
            p = q + 4;
        size_t n = strcspn(p, "\n");
        if (n >= len)
            n = len - 1;
        memcpy(buf, p, n);
        buf[n] = '\0';
        return buf;
    }
    snprintf(buf, len, "(no DR message)");
    return buf;
}

/* Describes the first difference between two outputs into buf; returns 0 if
 * they are equal.
 */
static int
diff_out(const out_t *n, const out_t *d, int flags, char *buf, size_t len)
{
    for (int i = 0; i < 32; i++) {
        if (n->x[i] != d->x[i]) {
            char name[8];
            snprintf(name, sizeof(name), i == 31 ? "svcr" : "x%d", i);
            snprintf(buf, len, "%s native 0x%llx dr 0x%llx", name,
                     (unsigned long long)n->x[i], (unsigned long long)d->x[i]);
            return 1;
        }
    }
    if (n->fpsr != d->fpsr || n->fpcr != d->fpcr) {
        snprintf(buf, len, "fpsr/fpcr native 0x%llx/0x%llx dr 0x%llx/0x%llx",
                 (unsigned long long)n->fpsr, (unsigned long long)n->fpcr,
                 (unsigned long long)d->fpsr, (unsigned long long)d->fpcr);
        return 1;
    }
    for (int i = 0; i < 32; i++) {
        if (n->q[i] != d->q[i]) {
            snprintf(buf, len, "q%d (after smstop) differs", i);
            return 1;
        }
    }
    int svl = g_svl;
    if (flags & USES_Z) {
        /* Report each Z register that differs, and how. */
        int nz = 0, lo_bytes = svl, hi_bytes = -1;
        char regs[96] = "";
        size_t rl = 0;
        for (int i = 0; i < 32; i++) {
            const uint8_t *a = n->z + i * svl, *b = d->z + i * svl;
            if (memcmp(a, b, svl) == 0)
                continue;
            nz++;
            for (int k = 0; k < svl; k++) {
                if (a[k] != b[k]) {
                    lo_bytes = k < lo_bytes ? k : lo_bytes;
                    hi_bytes = k > hi_bytes ? k : hi_bytes;
                }
            }
            if (rl < sizeof(regs) - 6)
                rl += snprintf(regs + rl, sizeof(regs) - rl, "%sz%d", rl ? "," : "", i);
        }
        if (nz > 0) {
            snprintf(buf, len, "%d Z registers differ (%s) in bytes %d-%d%s", nz, regs,
                     lo_bytes, hi_bytes,
                     lo_bytes >= 16 ? " (bits 0-127, the V registers, equal)" : "");
            return 1;
        }
        for (int i = 0; i < 16; i++) {
            if (memcmp(n->p + i * svl / 8, d->p + i * svl / 8, svl / 8) != 0) {
                snprintf(buf, len, "p%d differs", i);
                return 1;
            }
        }
    }
    if (flags & USES_ZA) {
        for (int i = 0; i < ZA_ROWS; i++) {
            if (memcmp(n->za + i * svl, d->za + i * svl, svl) != 0) {
                snprintf(buf, len, "ZA row %d differs", i);
                return 1;
            }
        }
    }
    if (memcmp(n->mem, d->mem, sizeof(n->mem)) != 0) {
        snprintf(buf, len, "memory written differs");
        return 1;
    }
    if (n->svl != d->svl) {
        snprintf(buf, len, "svl");
        return 1;
    }
    return 0;
}

static int
diff_h(const hrec_t *n, const hrec_t *d, char *buf, size_t len)
{
#define HCMP(f)                                                           \
    do {                                                                  \
        if (n->f != d->f) {                                               \
            snprintf(buf, len, "handler " #f " native 0x%llx dr 0x%llx",  \
                     (unsigned long long)n->f, (unsigned long long)d->f); \
            return 1;                                                     \
        }                                                                 \
    } while (0)
    HCMP(signo);
    HCMP(code);
    HCMP(pc_off);
    HCMP(insn);
    HCMP(svcr_in);
    HCMP(frame_ok);
    HCMP(sve_present);
    HCMP(sve_vl);
    HCMP(sve_flags);
    HCMP(sve_data);
    HCMP(za_present);
    HCMP(za_vl);
    HCMP(za_data);
    HCMP(pstate);
    HCMP(fpsr);
    HCMP(fpcr);
    HCMP(xhash);
    HCMP(vhash);
    HCMP(zhash);
    HCMP(phash);
    HCMP(zahash);
    HCMP(extra_present);
    HCMP(extra_delta);
    HCMP(stage);
#undef HCMP
    return 0;
}

/* What the planned handler under DR saw, for a divergence report. */
static void
describe_handler(const shres_t *r, char *buf, size_t len)
{
    for (int i = 0; i < MAXRUNS; i++) {
        if (r->nh[i] == 0)
            continue;
        const hrec_t *h = &r->h[i][0];
        size_t dl = strlen(buf);
        if (h->stage < 1) {
            snprintf(buf + dl, len - dl,
                     "%shandler entered in run %d with svcr 0x%llx and died before "
                     "recording anything",
                     dl ? "; " : "", i,
                     (unsigned long long)(r->entry_svcr[i] & ~(1ULL << 63)));
            return;
        }
        snprintf(
            buf + dl, len - dl,
            "%shandler ran in run %d (reached stage %d of 4): svcr 0x%llx, frame %s, "
            "SVE record %s vl %d "
            "flags 0x%x data %d, ZA record %s vl %d data %d, EXTRA %s delta %lld",
            dl ? "; " : "", i, h->stage, (unsigned long long)h->svcr_in,
            h->frame_ok ? "valid" : "INVALID", h->sve_present ? "yes" : "no", h->sve_vl,
            h->sve_flags, h->sve_data, h->za_present ? "yes" : "no", h->za_vl, h->za_data,
            h->extra_present ? "yes" : "no", (long long)h->extra_delta);
        if (!h->frame_ok) {
            dl = strlen(buf);
            snprintf(buf + dl, len - dl, " (%s)", r->frame_err);
        }
        return;
    }
}

/* Returns the known issue that explains outcome cls of template/mode name. */
static const char *
known_id(const char *name, int cls)
{
    for (size_t i = 0; i < sizeof(known_issues) / sizeof(known_issues[0]); i++) {
        if (known_issues[i].tmpl != NULL && strcmp(known_issues[i].tmpl, name) == 0)
            return known_issues[i].state_only && cls > OUT_STATE ? NULL
                                                                 : known_issues[i].id;
    }
    return NULL;
}

int
main(int argc, const char *argv[])
{
    const char *only = NULL;
    int runs = 3, opt_known = 0, only_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-only") == 0 && i + 1 < argc)
            only = argv[++i];
        else if (strcmp(argv[i], "-runs") == 0 && i + 1 < argc)
            runs = atoi(argv[++i]);
        else if (strcmp(argv[i], "-mode") == 0 && i + 1 < argc) {
            i++;
            only_mode = strcmp(argv[i], "cold") == 0 ? 1
                : strcmp(argv[i], "warm") == 0       ? 2
                                                     : -1;
            if (only_mode < 0) {
                fprintf(stderr, "unknown mode %s\n", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "-known") == 0)
            opt_known = 1;
        else if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if (runs < 2 || runs > MAXRUNS - 1)
        runs = 3;
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!(getauxval(AT_HWCAP2) & HWCAP2_SME)) {
        printf("sme: skipped: no HWCAP2_SME\n");
        printf("sme: all properties hold\n");
        return 0;
    }
    long vl = prctl(PR_SME_GET_VL);
    if (vl < 0 || prctl(PR_SME_SET_VL, vl & SME_VL_LEN_MASK) < 0) {
        printf("sme: skipped: PR_SME_SET_VL failed (errno %d)\n", errno);
        printf("sme: all properties hold\n");
        return 0;
    }
    g_svl = (int)(prctl(PR_SME_GET_VL) & SME_VL_LEN_MASK);
    if (g_svl < 16 || g_svl > MAX_SVL || g_svl % 16 != 0) {
        printf("sme: skipped: streaming vector length %d not handled\n", g_svl);
        printf("sme: all properties hold\n");
        return 0;
    }
    int fa64 = (getauxval(AT_HWCAP2) & HWCAP2_SME_FA64) != 0;
    a64p_init_features();
    a64p_progress_init("a64_prop_sme");
    g_res = mmap(NULL, sizeof(*g_res), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                 -1, 0);
    if (g_res == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    g_tmpl_lo = (uint64_t)(uintptr_t)sme_tmpl_lo;
    init_input(&g_in);
    printf("sme: SVL %d bytes, FA64 %s, %d runs per child\n", g_svl, fa64 ? "yes" : "no",
           runs);

    static shres_t nat, nat2, dres;
    static char errtext[16384];
    int fails = 0, n_equiv = 0, n_unsup = 0, n_known = 0, n_unexp = 0, n_inconcl = 0;
    int nrun = 0;
    for (int t = 0; t < NTMPL; t++) {
        const tmpl_t *tp = &tmpls[t];
        if (only != NULL && strcmp(only, tp->name) != 0)
            continue;
        if ((tp->flags & SIG_ILL) && fa64) {
            printf("sme %s: skipped: FEAT_SME_FA64 makes AdvSIMD legal when streaming\n",
                   tp->name);
            continue;
        }
        nrun++;
        char detail[1024] = "", line[200];
        int st;
        /* The native oracle: every run equal, a second child equal too. */
        int c = run_child(t, 0, runs, &nat, errtext, sizeof(errtext), &st);
        int c2 = c == OUT_EQUIV
            ? run_child(t, 0, runs, &nat2, errtext, sizeof(errtext), &st)
            : c;
        int native_ok = c == OUT_EQUIV && c2 == OUT_EQUIV;
        for (int r = 0; native_ok && r < runs; r++) {
            if (diff_out(&nat.out[0], &nat.out[r], tp->flags, detail, sizeof(detail)) ||
                diff_out(&nat.out[0], &nat2.out[r], tp->flags, detail, sizeof(detail)) ||
                nat.nh[r] != nat.nh[0] || nat2.nh[r] != nat.nh[0])
                native_ok = 0;
            for (int k = 0; native_ok && k < nat.nh[r]; k++) {
                if (diff_h(&nat.h[0][k], &nat.h[r][k], detail, sizeof(detail)) ||
                    diff_h(&nat.h[0][k], &nat2.h[r][k], detail, sizeof(detail)))
                    native_ok = 0;
            }
        }
        int want_sigs = (tp->flags & (SIG_TRAP | SIG_USR1 | SIG_ILL)) ? 1 : 0;
        if (native_ok && nat.nh[0] != want_sigs) {
            snprintf(detail, sizeof(detail), "%d planned signals natively, want %d",
                     nat.nh[0], want_sigs);
            native_ok = 0;
        }
        if (native_ok && want_sigs && !nat.h[0][0].frame_ok) {
            snprintf(detail, sizeof(detail), "native frame invalid: %s", nat.frame_err);
            native_ok = 0;
        }
        if (!native_ok) {
            fprintf(stderr,
                    "FAIL [sme %s] the native oracle is unusable (class %s): %s %s\n",
                    tp->name, out_names[c], detail,
                    c == OUT_APP_SIGNAL ? "(unexpected native signal)" : "");
            if (c == OUT_APP_SIGNAL) {
                fprintf(stderr, "  signal %d at pc 0x%llx (insn 0x%08x) svcr 0x%llx\n",
                        nat.unexpected_sig, (unsigned long long)nat.unexpected_pc,
                        nat.unexpected_insn, (unsigned long long)nat.unexpected_svcr);
            }
            fails++;
            n_inconcl++;
            continue;
        }
        if (verbose && nat.nh[0] > 0) {
            char nb[512] = "";
            describe_handler(&nat, nb, sizeof(nb));
            fprintf(stderr, "native %s: %s\n", tp->name, nb);
        }
        for (int mode = 1; mode <= 2; mode++) {
            if (only_mode != 0 && mode != only_mode)
                continue;
            const char *mname = mode == 1 ? "cold" : "warm";
            char tname[64];
            snprintf(tname, sizeof(tname), "%s/%s", tp->name, mname);
            detail[0] = '\0';
            /* Under DR. */
            int cls = run_child(t, mode, runs, &dres, errtext, sizeof(errtext), &st);
            if (cls == OUT_EQUIV) {
                for (int r = 0; r < runs && cls == OUT_EQUIV; r++) {
                    /* Report what differs in the final state and in what the
                     * handler saw, not just the first.
                     */
                    char part[512];
                    size_t dl = 0;
                    if (diff_out(&nat.out[r], &dres.out[r], tp->flags, part,
                                 sizeof(part))) {
                        dl += snprintf(detail + dl, sizeof(detail) - dl, "run %d: %s", r,
                                       part);
                    }
                    if (dres.nh[r] != nat.nh[r] && dl < sizeof(detail)) {
                        dl += snprintf(detail + dl, sizeof(detail) - dl,
                                       "%srun %d: %d planned signals, native %d",
                                       dl ? "; " : "", r, dres.nh[r], nat.nh[r]);
                    }
                    for (int k = 0;
                         k < nat.nh[r] && k < dres.nh[r] && dl < sizeof(detail); k++) {
                        if (diff_h(&nat.h[r][k], &dres.h[r][k], line, sizeof(line))) {
                            dl += snprintf(detail + dl, sizeof(detail) - dl,
                                           "%srun %d: %s%s%s", dl ? "; " : "", r, line,
                                           dres.h[r][k].frame_ok ? "" : "; DR frame: ",
                                           dres.h[r][k].frame_ok ? "" : dres.frame_err);
                        }
                    }
                    if (dl > 0) {
                        cls = OUT_STATE;
                        break;
                    }
                }
                if (cls == OUT_EQUIV && (tp->flags & CC) && dres.cc_count != runs) {
                    cls = OUT_INCONCLUSIVE;
                    snprintf(detail, sizeof(detail), "clean call ran %ld times, want %d",
                             dres.cc_count, runs);
                }
            } else if (cls == OUT_APP_SIGNAL || cls == OUT_DR_CRASH ||
                       cls == OUT_UNSUPPORTED) {
                char eb[160], where[96];
                size_t dl = 0;
                if (cls != OUT_APP_SIGNAL) {
                    dl +=
                        snprintf(detail, sizeof(detail), "%s %d after %d runs: %s",
                                 WIFSIGNALED(st) ? "signal" : "exit status",
                                 WIFSIGNALED(st) ? WTERMSIG(st) : WEXITSTATUS(st),
                                 dres.runs_done, first_err_line(errtext, eb, sizeof(eb)));
                }
                if (dres.unexpected_sig != 0 && dl < sizeof(detail)) {
                    dl = strlen(detail);
                    snprintf(
                        detail + dl, sizeof(detail) - dl,
                        "%sapp handler got signal %d at %s (insn 0x%08x) svcr 0x%llx "
                        "in run %d",
                        dl ? "; " : "", dres.unexpected_sig,
                        describe_pc(dres.unexpected_pc, where, sizeof(where)),
                        dres.unexpected_insn, (unsigned long long)dres.unexpected_svcr,
                        dres.runs_done);
                }
            } else if (cls == OUT_HANG) {
                snprintf(detail, sizeof(detail), "no exit after 15 s, %d runs done",
                         dres.runs_done);
            }
            if (cls != OUT_EQUIV && cls != OUT_INCONCLUSIVE)
                describe_handler(&dres, detail, sizeof(detail));
            if (dres.pre_count > 0) {
                size_t dl = strlen(detail);
                snprintf(detail + dl, sizeof(detail) - dl,
                         "%spre-syscall event saw svcr 0x%llx", dl ? "; " : "",
                         (unsigned long long)dres.pre_svcr);
            }
            if ((tp->flags & CC) && cls != OUT_INCONCLUSIVE && dres.cc_count > 0) {
                size_t dl = strlen(detail);
                snprintf(detail + dl, sizeof(detail) - dl, "%sclean call saw svcr 0x%llx",
                         dl ? "; " : "", (unsigned long long)dres.cc_svcr);
            }
            if (verbose && errtext[0] != '\0')
                fprintf(stderr, "--- %s: DR child stderr ---\n%s---\n", tname, errtext);
            const char *kid = known_id(tname, cls);
            if (cls == OUT_EQUIV) {
                n_equiv++;
                printf("sme %s: equivalent%s%s%s%s\n", tname, detail[0] ? " (" : "",
                       detail, detail[0] ? ")" : "",
                       kid != NULL ? " [known issue did not reproduce]" : "");
            } else if (cls == OUT_UNSUPPORTED) {
                n_unsup++;
                printf("sme %s: unsupported (refused by DR): %s\n", tname, detail);
            } else if (cls == OUT_INCONCLUSIVE) {
                n_inconcl++;
                fails++;
                fprintf(stderr, "FAIL [sme %s] inconclusive: %s\n", tname, detail);
            } else if (kid != NULL && !opt_known) {
                n_known++;
                printf("sme %s: known issue %s: %s: %s\n", tname, kid, out_names[cls],
                       detail);
            } else {
                n_unexp++;
                fails++;
                fprintf(stderr, "FAIL [sme %s] %s%s: %s\n", tname, out_names[cls],
                        kid != NULL ? " (known issue)" : "", detail);
                fprintf(stderr, "  repro: a64_prop_sme -only %s -mode %s -v\n", tp->name,
                        mname);
            }
        }
    }
    printf("sme: templates %d: equivalent %d, unsupported %d, known divergences %d, "
           "unexpected divergences %d, inconclusive %d\n",
           nrun, n_equiv, n_unsup, n_known, n_unexp, n_inconcl);
    if (only == NULL)
        fails += a64p_floor("sme", "templates run", nrun, NTMPL - 1);
    printf("sme: %s\n", fails == 0 ? "all properties hold" : "FAILURES");
    return fails == 0 ? 0 : 1;
}

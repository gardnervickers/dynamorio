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

/* Properties of code publication and self-modification under DR on AArch64,
 * with the architecture's cache maintenance rules as the oracle.  Each option
 * variant runs in a forked child (static DR started with
 * dr_app_setup_and_start(), or no DR for the "native" control, which must
 * pass too: it shows that every protocol the test uses is valid).
 *
 *   publish: a writer thread publishes generation k of generated code into
 *     one of several buffers with a valid protocol and then release-stores k;
 *     1-4 executor threads acquire k, execute ISB and call k's entry points
 *     (indirectly) several times.  Every call must return generation k's
 *     entry tag at its start and end and k's checksum: never an older
 *     generation, a mixed instruction sequence or a fault.  A buffer is
 *     rewritten only after every executor acknowledged a newer generation.
 *     Protocols: "full" (DC CVAU per line, DSB ISH, IC IVAU per line, DSB
 *     ISH), "ctr" (the subset CTR_EL0.IDC/DIC permit, read with MRS at each
 *     publication so -fake_ctr_dic applies), "membar" (full maintenance, then
 *     membarrier(PRIVATE_EXPEDITED_SYNC_CORE) instead of the executors' ISB).
 *     Installs: RWX buffers packed so that they share pages (the buffer being
 *     written shares a page with code other threads are running), RWX
 *     page-aligned buffers, mprotect RW -> write -> RX, a MAP_FIXED mapping
 *     over the old one, and munmap followed by a mapping at the same address.
 *     Generated code has straight-line checksum steps, loops (trace heads),
 *     an indirect jump inside the code, an indirect call to a never-modified
 *     helper and back (so returns into rewritten code go through the IBL),
 *     long NOP runs (code crossing cache lines and pages, several blocks) and
 *     several entry points per generation at offsets that change.
 *     The "cmodx" class: an executor spins in a generated loop while the
 *     writer patches a NOP in it into a branch out of the loop (a pair the
 *     architecture permits to be modified concurrently with execution) and
 *     completes full maintenance; the executor must leave the loop through
 *     the patched branch before its iteration counter (2^32) runs out.
 *   selfmod: 1-4 threads each run their own generated function that stores a
 *     new encoding of a later instruction of its own code (computed from the
 *     call's argument), does the required maintenance (DC CVAU, DSB ISH, IC
 *     IVAU, DSB ISH, ISB; or the CTR_EL0-based subset, read with MRS in the
 *     generated code), then executes it.  The result must be the new
 *     instruction's.  Kinds: the target in the same block, in the next block,
 *     on the next page, patched in a loop before execution, patched in a loop
 *     for the next iteration, a two-word patch straddling a cache line or
 *     page, and a branch whose target is patched; and "stale-fault": the
 *     function rewrites an instruction it has already executed (MOVZ, ADR, a
 *     literal load or a branch to the next instruction) and then faults on a
 *     load in the same block before the maintenance, and the fault frame (pc
 *     and registers) must be the old code's: a thread can be in a block built
 *     from code the app has since rewritten.  Threads' functions are either
 *     packed into shared pages or on their own pages.  The "_window" and
 *     "_progress" variants run selfmod with an in-process drreg client (see
 *     jc_client_mode()), whose state restoration at the stale-fault faults
 *     must see the code the block was built from.
 *   patch: a call or branch retargeted (or a callee entry NOP replaced by a
 *     branch) by a writer thread while an executor still runs the code DR
 *     built from the old target, and the old target faults before the
 *     writer's cache maintenance: the fault must be reported at the
 *     instruction that faulted (see "patch mode" below).  Fixed rounds per
 *     class rather than a time budget; its own variant list.
 *
 * Each mode prints generated/accepted/executed/checked/suppressed/inconclusive
 * counts per variant and enforces per-class floors, running extra rounds (a
 * bounded number) for classes below their floor; "all properties hold" is only
 * printed when every check and every floor passed.  Combinations that are not
 * valid protocols under a variant are skipped and counted as inconclusive
 * (e.g. the "ctr" protocol when the app sees CTR_EL0.DIC set under
 * -no_hw_cache_consistency without -fake_ctr_dic: DR then has no IC IVAU to
 * observe, i#5771).
 *
 * Configurations hit by a known, not yet fixed DR issue (known_issues[]) are
 * skipped and reported by name unless -known is given.
 *
 * Usage: a64_prop_jit <publish|selfmod|patch> [-seed S] [-n ROUNDS] [-secs T]
 *        [-regress_secs R] [-variants a,b,...] [-known] [-v]
 * Without -n each variant runs rounds for about T seconds (default 5 with a
 * debug DR, 10 with a release DR, 2 for native); round r of a variant uses round seed S +
 * r, which also selects its class, so "-seed RS -n 1" replays one round.  Each
 * selfmod regression round runs for R seconds (default 3).
 */

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#ifndef A64P_EXTERNAL_DR
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#endif

#include <elf.h>
#include <errno.h>
#include <linux/membarrier.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include "a64_prop_support.h"

static int verbose;
/* -known: also run the configurations of the known DR issues below. */
static int opt_known;
static int is_debug_build;
static const char *g_mode;

/***************************************************************************
 * Variants.  dr_ops NULL means native (no DR).
 */
static const variant_t jit_variants[] = {
    { "native", NULL, 0, 0, 0, 0 },
    { "default", "", 0, 0, 0, 0 },
    { "notraces", "-disable_traces", 0, 0, 0, 0 },
    { "sandbox", "-sandbox_writable", 0, 0, 0, 0 },
    { "nohwcc", "-no_hw_cache_consistency", 0, 0, 1, 0 },
    { "fakectr", "-fake_ctr_dic", 0, 0, 1, 1 },
    { "nohwcc_fakectr", "-no_hw_cache_consistency -fake_ctr_dic", 0, 0, 1, 1 },
    /* With an in-process drreg client (selfmod mode only): see jc_client_mode(). */
    { "default_window", "", 0, 0, 0, 0 },
    { "sandbox_window", "-sandbox_writable", 0, 0, 0, 0 },
    { "nohwcc_window", "-no_hw_cache_consistency", 0, 0, 0, 0 },
    { "nohwcc_progress", "-no_hw_cache_consistency", 0, 0, 0, 0 },
};
/* patch mode under a static DR: native, both cache consistency schemes.  A
 * static DR always turns direct-cti elision off (-code_api), so the elision
 * cases run under drrun instead (-external).
 */
static const variant_t patch_variants[] = {
    { "native", NULL, 0, 0, 0, 0 },
    { "default", "", 0, 0, 0, 0 },
    { "nohwcc_fakectr", "-no_hw_cache_consistency -fake_ctr_dic", 0, 0, 0, 1 },
};
/* The mode's variants. */
static const variant_t *vtab = jit_variants;
static int NVARIANTS = (int)(sizeof(jit_variants) / sizeof(jit_variants[0]));

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

static const char *
unknown_variant(const char *vlist)
{
    static char buf[64];
    for (const char *p = vlist; p != NULL;) {
        const char *e = strchr(p, ',');
        size_t n = e == NULL ? strlen(p) : (size_t)(e - p);
        int found = 0;
        for (int i = 0; i < NVARIANTS && !found; i++) {
            found = strlen(vtab[i].name) == n && strncmp(p, vtab[i].name, n) == 0;
        }
        if (!found) {
            snprintf(buf, sizeof(buf), "%.*s", (int)(n < 60 ? n : 60), p);
            return buf;
        }
        p = e == NULL ? NULL : e + 1;
    }
    return NULL;
}

#ifndef A64P_EXTERNAL_DR
/***************************************************************************
 * The in-process client of the "_window" and "_progress" variants, which
 * instruments every app instr of the round's generated code with drreg:
 *   window: a register drreg picks holds a tool value across two app instrs
 *     (drreg's state restoration must give the app its value at a fault there);
 *   progress: the pattern of an instruction-counting tool (Seedbox's progress
 *     client): a reserved register decrements a budget in raw TLS, a TBZ skips a
 *     READS_APP_CONTEXT | MULTIPATH clean call that refills it, and
 *     drreg_get_app_value() reloads the register before the unreserve.
 */
static int g_client_mode; /* 0 none, 1 window, 2 progress */
static volatile uint64_t g_code_lo, g_code_hi;
static reg_id_t g_budget_seg;
static uint g_budget_offs;
static volatile long g_refills;
#define JC_BUDGET 7
#define JC_TOOL_VAL 0x70017001ULL

static int
jc_client_mode(const variant_t *v)
{
    if (v->dr_ops == NULL)
        return 0;
    if (strstr(v->name, "_window") != NULL)
        return 1;
    if (strstr(v->name, "_progress") != NULL)
        return 2;
    return 0;
}

static void
jc_set_budget(ptr_int_t val)
{
    *(ptr_int_t *)((byte *)dr_get_dr_segment_base(g_budget_seg) + g_budget_offs) = val;
}

static void
jc_refill(void)
{
    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    dr_get_mcontext(dr_get_current_drcontext(), &mc);
    jc_set_budget(JC_BUDGET);
    __atomic_add_fetch(&g_refills, 1, __ATOMIC_RELAXED);
}

static void
jc_thread_init(void *dc)
{
    jc_set_budget(JC_BUDGET);
}

static int
jc_in_code(instr_t *inst)
{
    uint64_t pc = (uint64_t)(uintptr_t)instr_get_app_pc(inst);
    return instr_is_app(inst) && pc >= g_code_lo && pc < g_code_hi;
}

typedef struct {
    int open; /* app instrs the window has spanned, 0 if none */
    reg_id_t reg;
    int idx; /* app instrs seen */
} jc_window_t;

static dr_emit_flags_t
jc_analysis(void *dc, void *tag, instrlist_t *bb, bool for_trace, bool translating,
            void **user)
{
    jc_window_t *w = dr_thread_alloc(dc, sizeof(*w));
    memset(w, 0, sizeof(*w));
    *user = w;
    return DR_EMIT_DEFAULT;
}

static void
jc_progress(void *dc, instrlist_t *bb, instr_t *inst)
{
    reg_id_t reg;
    instr_t *skip = INSTR_CREATE_label(dc);
    if (drreg_reserve_register(dc, bb, inst, NULL, &reg) != DRREG_SUCCESS)
        DR_ASSERT(false);
    dr_insert_read_raw_tls(dc, bb, inst, g_budget_seg, g_budget_offs, reg);
    instrlist_meta_preinsert(bb, inst,
                             INSTR_CREATE_sub(dc, opnd_create_reg(reg),
                                              opnd_create_reg(reg), OPND_CREATE_INT(1)));
    dr_insert_write_raw_tls(dc, bb, inst, g_budget_seg, g_budget_offs, reg);
    instrlist_meta_preinsert(bb, inst,
                             INSTR_CREATE_tbz(dc, opnd_create_instr(skip),
                                              opnd_create_reg(reg), OPND_CREATE_INT(63)));
    dr_insert_clean_call_ex(dc, bb, inst, (void *)jc_refill,
                            DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_MULTIPATH, 0);
    instrlist_meta_preinsert(bb, inst, skip);
    if (drreg_get_app_value(dc, bb, inst, reg, reg) != DRREG_SUCCESS ||
        drreg_unreserve_register(dc, bb, inst, reg) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

static dr_emit_flags_t
jc_insert(void *dc, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace,
          bool translating, void *user)
{
    jc_window_t *w = (jc_window_t *)user;
    bool last = drmgr_is_last_instr(dc, inst);
    if (g_client_mode == 2) {
        /* Like Seedbox's client, a few charge points per block: the first app instr
         * and every 8th (a clean call per instr would exceed the cache's limits).
         */
        if (jc_in_code(inst) && w->idx++ % 8 == 0)
            jc_progress(dc, bb, inst);
    } else if (jc_in_code(inst) || w->open > 0) {
        if (w->open == 2 || (w->open > 0 && last)) {
            if (drreg_unreserve_register(dc, bb, inst, w->reg) != DRREG_SUCCESS)
                DR_ASSERT(false);
            w->open = 0;
        }
        if (w->open > 0)
            w->open++;
        else if (!last && jc_in_code(inst)) {
            if (drreg_reserve_register(dc, bb, inst, NULL, &w->reg) != DRREG_SUCCESS)
                DR_ASSERT(false);
            instrlist_insert_mov_immed_ptrsz(dc, (ptr_int_t)JC_TOOL_VAL,
                                             opnd_create_reg(w->reg), bb, inst, NULL,
                                             NULL);
            w->open = 1;
        }
    }
    if (last)
        dr_thread_free(dc, w, sizeof(*w));
    return DR_EMIT_DEFAULT;
}

static void
jc_exit(void)
{
    if (g_client_mode != 0)
        drreg_exit();
    drmgr_exit();
}

/* patch mode's entry-lazymod: whether DR loaded a module starting at g_watch_mod. */
static void *volatile g_watch_mod;
static volatile int g_watch_seen;

static void
jc_module_load(void *dc, const module_data_t *info, bool loaded)
{
    if (info->start == (app_pc)g_watch_mod)
        g_watch_seen = 1;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    if (!drmgr_init() || !drmgr_register_module_load_event(jc_module_load))
        DR_ASSERT(false);
    dr_register_exit_event(jc_exit);
    if (g_client_mode == 0)
        return;
    /* Conservative: the app may rely on a dead register's value at a fault. */
    drreg_options_t ops = { sizeof(ops), 4, true };
    if (drreg_init(&ops) != DRREG_SUCCESS ||
        !dr_raw_tls_calloc(&g_budget_seg, &g_budget_offs, 1, 0))
        DR_ASSERT(false);
    drmgr_register_thread_init_event(jc_thread_init);
    drmgr_register_bb_instrumentation_event(jc_analysis, jc_insert, NULL);
}
#else
static int g_client_mode;
static volatile uint64_t g_code_lo, g_code_hi;
static int
jc_client_mode(const variant_t *v)
{
    return 0;
}
#endif

/* -external hwcc|nohwcc: the process already runs under drrun (a build
 * without DR, A64P_EXTERNAL_DR), with or without -no_hw_cache_consistency; the
 * one variant, "external", does not start DR.  This is how the patch mode
 * runs with DR's command-line options: a static DR always disables elision.
 */
static const char *g_external;
static const variant_t external_variants[] = {
    { "external", NULL, 0, 0, 0, 0 },
};

static int
variant_hwcc(const variant_t *v)
{
    if (g_external != NULL && strcmp(v->name, "external") == 0)
        return strcmp(g_external, "nohwcc") != 0;
    return v->dr_ops == NULL || strstr(v->dr_ops, "-no_hw_cache_consistency") == NULL;
}

/***************************************************************************
 * Known DR issues: configurations skipped (and counted) unless -known.
 */
typedef struct {
    /* option: the issue's under variants with this option, or, with a leading '!',
     * under those without it.
     */
    const char *id, *option, *cls, *what;
    /* If non-NULL, the issue is the whole variant's, which then runs only if
     * listed in -variants or with -known.
     */
    const char *variant;
} known_t;
/* Ends with a NULL id.  (Fixed: sandbox-copy-race, cmodx under -sandbox_writable;
 * elided-cti-retarget, the patch classes other than entry, by not eliding ctis
 * on or into writable pages without -hw_cache_consistency; stale-block-translation,
 * patch's entry class under -no_hw_cache_consistency, by translating blocks from
 * writable pages from a copy of their code, -xl8_code_copy; and its entry-mprot and
 * entry-wx classes, code made writable only for the patch, and entry-alias, code
 * written through a second mapping, by keeping the copy for code outside modules
 * too; entry-lazymod, code in a module DR finds only when it runs, by counting
 * such a module's code as outside modules; and entry-gap, code between a module's
 * segments, by classifying a whole executable area.)
 */
static const known_t known_issues[] = {
    { "hwcc-drreg-selfmod", NULL, NULL,
      "with -hw_cache_consistency, a drreg client's tool values reach the app across "
      "self-modification (e.g., the fault of a write to the code's read-only page, or "
      "a stale-fault round's write: a register holds the tool value at the app's next "
      "instruction), and the child dies (seen on master too, 2026-10-14)",
      "default_window" },
    { "hwcc-alias", "!-no_hw_cache_consistency", "entry-alias,entry-gap",
      "with -hw_cache_consistency, DR does not see a write to code through a second, "
      "writable mapping of it, and runs the old code even after the app's cache "
      "maintenance (and translates a fault in it from the new code)",
      NULL },
    { NULL, NULL, NULL, NULL },
};
static long known_skipped[sizeof(known_issues) / sizeof(known_issues[0])];

static const known_t *
known_variant(const variant_t *v)
{
    for (size_t i = 0; known_issues[i].id != NULL; i++) {
        if (known_issues[i].variant != NULL &&
            strcmp(known_issues[i].variant, v->name) == 0)
            return &known_issues[i];
    }
    return NULL;
}

/* Returns the known issue that makes class cls invalid under v, or NULL. */
static const known_t *
known_issue(const variant_t *v, const char *cls)
{
    /* Under -external, the options that matter are known only as hwcc/nohwcc. */
    const char *ops = v->dr_ops;
    if (ops == NULL && strcmp(v->name, "external") == 0)
        ops = variant_hwcc(v) ? "" : "-no_hw_cache_consistency";
    if (opt_known || ops == NULL)
        return NULL;
    for (size_t i = 0; known_issues[i].id != NULL; i++) {
        if (known_issues[i].option == NULL)
            continue;
        const char *opt = known_issues[i].option;
        int has = opt[0] == '!' ? strstr(ops, opt + 1) == NULL : strstr(ops, opt) != NULL;
        if (has && list_has(known_issues[i].cls, cls)) {
            known_skipped[i]++;
            return &known_issues[i];
        }
    }
    return NULL;
}

/***************************************************************************
 * Encodings.
 */
#define E_RET 0xd65f03c0u
#define E_NOP 0xd503201fu
#define E_ISB 0xd5033fdfu
#define E_DSB_ISH 0xd5033b9fu
#define E_UDF 0x00000000u
#define E_STP_FP_LR 0xa9bf7bfdu /* stp x29, x30, [sp, #-16]! */
#define E_LDP_FP_LR 0xa8c17bfdu /* ldp x29, x30, [sp], #16 */
#define COND_NE 1

static uint32_t
e_movz(int sf, int rd, uint32_t imm16, int hw)
{
    return (sf ? 0xd2800000u : 0x52800000u) | ((uint32_t)hw << 21) | (imm16 << 5) |
        (uint32_t)rd;
}
static uint32_t
e_movk(int sf, int rd, uint32_t imm16, int hw)
{
    return (sf ? 0xf2800000u : 0x72800000u) | ((uint32_t)hw << 21) | (imm16 << 5) |
        (uint32_t)rd;
}
static uint32_t
e_addi(int rd, int rn, uint32_t imm12)
{
    return 0x91000000u | (imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
static uint32_t
e_subsi(int rd, int rn, uint32_t imm12)
{
    return 0xf1000000u | (imm12 << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
static uint32_t
e_add(int rd, int rn, int rm)
{
    return 0x8b000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
/* eor rd, rn, rm, ror #sh */
static uint32_t
e_eor_ror(int rd, int rn, int rm, int sh)
{
    return 0xcac00000u | ((uint32_t)rm << 16) | ((uint32_t)sh << 10) |
        ((uint32_t)rn << 5) | (uint32_t)rd;
}
/* ror rd, rn, #sh (extr rd, rn, rn, #sh) */
static uint32_t
e_ror(int rd, int rn, int sh)
{
    return 0x93c00000u | ((uint32_t)rn << 16) | ((uint32_t)sh << 10) |
        ((uint32_t)rn << 5) | (uint32_t)rd;
}
/* and rd, rn, #0xffff */
static uint32_t
e_and_ffff(int rd, int rn)
{
    return 0x92403c00u | ((uint32_t)rn << 5) | (uint32_t)rd;
}
/* lsl rd, rn, #5 (ubfm rd, rn, #59, #58) */
static uint32_t
e_lsl5(int rd, int rn)
{
    return 0xd3400000u | (59u << 16) | (58u << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
/* ubfx rd, rn, #16, #16 */
static uint32_t
e_ubfx16(int rd, int rn)
{
    return 0xd3400000u | (16u << 16) | (31u << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
/* orr wd, wn, wm */
static uint32_t
e_orr_w(int rd, int rn, int rm)
{
    return 0x2a000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
/* tst xn, #1 */
static uint32_t
e_tst1(int rn)
{
    return 0xf240001fu | ((uint32_t)rn << 5);
}
static uint32_t
e_csel_w(int rd, int rn, int rm, int cond)
{
    return 0x1a800000u | ((uint32_t)rm << 16) | ((uint32_t)cond << 12) |
        ((uint32_t)rn << 5) | (uint32_t)rd;
}
static uint32_t
e_str_w(int rt, int rn, int off)
{
    return 0xb9000000u | ((uint32_t)(off / 4) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
static uint32_t
e_b(int off)
{
    return 0x14000000u | ((uint32_t)(off / 4) & 0x3ffffffu);
}
static uint32_t
e_bcond(int off, int cond)
{
    return 0x54000000u | (((uint32_t)(off / 4) & 0x7ffffu) << 5) | (uint32_t)cond;
}
static uint32_t
e_tbnz(int rt, int bit, int off)
{
    return 0x37000000u | ((uint32_t)(bit >> 5) << 31) | ((uint32_t)(bit & 31) << 19) |
        (((uint32_t)(off / 4) & 0x3fffu) << 5) | (uint32_t)rt;
}
static uint32_t
e_adr(int rd, int off)
{
    return 0x10000000u | ((uint32_t)(off & 3) << 29) |
        (((uint32_t)(off >> 2) & 0x7ffffu) << 5) | (uint32_t)rd;
}
static uint32_t
e_br(int rn)
{
    return 0xd61f0000u | ((uint32_t)rn << 5);
}
static uint32_t
e_blr(int rn)
{
    return 0xd63f0000u | ((uint32_t)rn << 5);
}
static uint32_t
e_dc_cvau(int rt)
{
    return 0xd50b7b20u | (uint32_t)rt;
}
static uint32_t
e_ic_ivau(int rt)
{
    return 0xd50b7520u | (uint32_t)rt;
}
static uint32_t
e_mrs_ctr(int rt)
{
    return 0xd53b0020u | (uint32_t)rt;
}

static uint64_t
ror64(uint64_t x, int r)
{
    return (x >> r) | (x << (64 - r));
}

/***************************************************************************
 * A tiny assembler with labels.
 */
#define MAXL 32
#define MAXFIX 64
enum { JFX_B, JFX_BCOND, JFX_TBNZ, JFX_ADR };
typedef struct {
    uint32_t *w;
    int n, cap, overflow;
    int lab[MAXL];
    struct {
        int at, lab, kind;
    } fix[MAXFIX];
    int nfix;
} as_t;

static void
as_init(as_t *a, uint32_t *w, int cap)
{
    memset(a, 0, sizeof(*a));
    a->w = w;
    a->cap = cap;
    for (int i = 0; i < MAXL; i++)
        a->lab[i] = -1;
}
static void
put(as_t *a, uint32_t w)
{
    if (a->n < a->cap)
        a->w[a->n] = w;
    else
        a->overflow = 1;
    a->n++;
}
static void
label(as_t *a, int l)
{
    a->lab[l] = a->n;
}
static void
put_fix(as_t *a, uint32_t w, int l, int kind)
{
    if (a->nfix < MAXFIX) {
        a->fix[a->nfix].at = a->n;
        a->fix[a->nfix].lab = l;
        a->fix[a->nfix].kind = kind;
        a->nfix++;
    } else
        a->overflow = 1;
    put(a, w);
}
static int
as_resolve(as_t *a)
{
    if (a->overflow)
        return 0;
    for (int i = 0; i < a->nfix; i++) {
        int at = a->fix[i].at, to = a->lab[a->fix[i].lab];
        if (to < 0)
            return 0;
        int off = (to - at) * 4;
        uint32_t *p = &a->w[at];
        switch (a->fix[i].kind) {
        case JFX_B: *p = e_b(off); break;
        case JFX_BCOND: *p = e_bcond(off, (int)(*p & 15)); break;
        case JFX_TBNZ: *p = e_tbnz((int)(*p & 31), (int)((*p >> 19) & 31), off); break;
        case JFX_ADR: *p = e_adr((int)(*p & 31), off); break;
        }
    }
    return 1;
}
static void
put_mov64(as_t *a, int rd, uint64_t v)
{
    put(a, e_movz(1, rd, (uint32_t)(v & 0xffff), 0));
    for (int hw = 1; hw < 4; hw++) {
        uint32_t c = (uint32_t)(v >> (16 * hw)) & 0xffff;
        if (c != 0)
            put(a, e_movk(1, rd, c, hw));
    }
}

/***************************************************************************
 * Cache maintenance done by the host (writer) code.
 */
enum { PROTO_FULL, PROTO_CTR, PROTO_MEMBAR, NPROTO };
static const char *const proto_name[] = { "full", "ctr", "membar" };

static inline uint64_t
read_ctr(void)
{
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    return ctr;
}

static void
maintain(uint64_t start, uint64_t len, int proto)
{
    uint64_t ctr = read_ctr();
    uint64_t dline = 4ULL << ((ctr >> 16) & 15), iline = 4ULL << (ctr & 15);
    int skip_dc = proto == PROTO_CTR && ((ctr >> 28) & 1) != 0;
    int skip_ic = proto == PROTO_CTR && ((ctr >> 29) & 1) != 0;
    if (!skip_dc) {
        for (uint64_t a = start & ~(dline - 1); a < start + len; a += dline)
            __asm__ volatile("dc cvau, %0" : : "r"(a) : "memory");
    }
    __asm__ volatile("dsb ish" : : : "memory");
    if (!skip_ic) {
        for (uint64_t a = start & ~(iline - 1); a < start + len; a += iline)
            __asm__ volatile("ic ivau, %0" : : "r"(a) : "memory");
        __asm__ volatile("dsb ish" : : : "memory");
    }
}

static int membarrier_ok;

static void
membarrier_init(void)
{
    long q = syscall(SYS_membarrier, MEMBARRIER_CMD_QUERY, 0, 0);
    membarrier_ok = q > 0 && (q & MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE) != 0 &&
        syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0,
                0) == 0;
}

static void
membarrier_sync_core(void)
{
    if (syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0) != 0) {
        perror("ERROR: membarrier");
        _exit(2);
    }
}

/***************************************************************************
 * Calling generated code: x4 is the argument; x0-x3 and x10 are results.
 * Generated code may use x0-x15 and the stack, and saves x29/x30 itself.
 */
typedef struct {
    uint64_t x0, x1, x2, x3, x10;
} out_t;

static void
call_code(uint64_t fn, uint64_t arg, out_t *o)
{
    register uint64_t x0 __asm__("x0");
    register uint64_t x1 __asm__("x1");
    register uint64_t x2 __asm__("x2");
    register uint64_t x3 __asm__("x3");
    register uint64_t x4 __asm__("x4") = arg;
    register uint64_t x10 __asm__("x10");
    register uint64_t x16 __asm__("x16") = fn;
    __asm__ volatile("blr x16"
                     : "=r"(x0), "=r"(x1), "=r"(x2), "=r"(x3), "+r"(x4), "=r"(x10),
                       "+r"(x16)
                     :
                     : "x5", "x6", "x7", "x8", "x9", "x11", "x12", "x13", "x14", "x15",
                       "x17", "x30", "memory", "cc");
    o->x0 = x0;
    o->x1 = x1;
    o->x2 = x2;
    o->x3 = x3;
    o->x10 = x10;
}

/* Waiting: spin briefly before giving up the CPU (on a loaded machine every
 * sched_yield() can cost a time slice).
 */
static inline void
relax(void)
{
    static __thread unsigned n;
    if (++n % 64 == 0)
        sched_yield();
    else {
        for (int i = 0; i < 32; i++)
            __asm__ volatile("yield" : : : "memory");
    }
}

static inline void
isb(void)
{
    __asm__ volatile("isb" : : : "memory");
}

static uint64_t
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static long page_size;

static void *
xmmap(void *addr, size_t len, int prot, int flags)
{
    void *p = mmap(addr, len, prot, flags | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "ERROR: mmap(%p, 0x%zx) failed: %s\n", addr, len,
                strerror(errno));
        _exit(2);
    }
    return p;
}

static void
xmprotect(void *addr, size_t len, int prot)
{
    if (mprotect(addr, len, prot) != 0) {
        fprintf(stderr, "ERROR: mprotect(%p, 0x%zx, %d) failed: %s\n", addr, len, prot,
                strerror(errno));
        _exit(2);
    }
}

/***************************************************************************
 * Failure log shared by the threads of a round.
 */
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static int log_n;
static char log_buf[8192];

static void
logf_fail(const char *fmt, ...)
{
    va_list ap;
    pthread_mutex_lock(&log_lock);
    if (log_n < 12) {
        size_t len = strlen(log_buf);
        va_start(ap, fmt);
        vsnprintf(log_buf + len, sizeof(log_buf) - len, fmt, ap);
        va_end(ap);
    }
    log_n++;
    pthread_mutex_unlock(&log_lock);
}

static void
log_reset(void)
{
    log_n = 0;
    log_buf[0] = '\0';
}

/* Unexpected faults are failures: report the round and die. */
static volatile uint64_t g_round_seed;
static volatile const char *g_round_desc = "";

static void
fatal_handler(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    char buf[256];
    int len =
        snprintf(buf, sizeof(buf),
                 "FAIL: signal %d (code %d) at pc 0x%llx addr %p in round seed "
                 "%llu (%s)\n",
                 sig, si->si_code, (unsigned long long)uc->uc_mcontext.pc, si->si_addr,
                 (unsigned long long)g_round_seed, (const char *)g_round_desc);
    if (write(2, buf, len) < 0) {
        /* Nothing to do. */
    }
    signal(sig, SIG_DFL);
}

static void
sm_stale_handler(int sig, siginfo_t *si, void *ucv);

static void
install_fatal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fatal_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sa.sa_sigaction = sm_stale_handler;
    sigaction(SIGSEGV, &sa, NULL);
}

/***************************************************************************
 * Per-class statistics, accumulated per variant.
 */
#define MAXCLS 32
typedef struct {
    long rounds, gens, calls, checked, fails, inconclusive;
    uint64_t max_latency_ns;
    long stale; /* patch: faults in the old code before maintenance */
} cls_stat_t;

static cls_stat_t g_cls[MAXCLS];

/***************************************************************************
 * publish mode.
 */
enum { INST_RWX_PACKED, INST_RWX_PAGED, INST_MPROT, INST_REMAP, INST_UNMAP, NINST };
static const char *const inst_name[] = { "rwx-packed", "rwx-paged", "mprotect",
                                         "map-fixed", "unmap-map" };
#define PUB_NCLS (NPROTO * NINST + 1)
#define CLS_CMODX (NPROTO * NINST)

static void
pub_class_name(int c, char *buf, size_t n)
{
    if (c == CLS_CMODX)
        snprintf(buf, n, "cmodx");
    else
        snprintf(buf, n, "%s/%s", proto_name[c / NINST], inst_name[c % NINST]);
}

#define MAXEX 4
#define MAXBUF 4
#define MAXE 3
#define NREC 16
#define PACKED_STRIDE 0x600
#define PAGED_PAGES 3

typedef struct {
    uint64_t gen;
    int nentry;
    uint64_t entry[MAXE];
    uint64_t x1[MAXE];
} pubrec_t;

typedef struct {
    int id;
    pthread_t th;
    struct pub_round *R;
    uint64_t seed;
    volatile uint64_t ack;
    long calls, fails;
    /* cmodx */
    volatile uint64_t entered, returned;
    out_t cm_out;
} exec_t;

typedef struct pub_round {
    uint64_t seed;
    int cls, proto, inst, nexec, nbuf, max_calls;
    const variant_t *v;
    uint8_t *arena;
    size_t arena_len, stride;
    uint64_t buf_base[MAXBUF];
    uint8_t *helper;
    volatile uint64_t pub;
    pubrec_t rec[NREC];
    volatile int stop;
    exec_t ex[MAXEX];
    long gens, va_moved;
    /* cmodx */
    uint64_t cm_fn, cm_patch;
    uint32_t cm_insn; /* the patch: "b OUT" */
    volatile uint64_t cm_arm;
} pub_round_t;

static uint64_t
tag_of(uint64_t gen, int e)
{
    return (gen & 0xffffffffULL) | ((uint64_t)(0xa500 | e) << 32);
}

static void
put_tag(as_t *a, int rd, uint64_t gen, int e)
{
    put(a, e_movz(1, rd, (uint32_t)(gen & 0xffff), 0));
    put(a, e_movk(1, rd, (uint32_t)((gen >> 16) & 0xffff), 1));
    put(a, e_movk(1, rd, (uint32_t)(0xa500 | e), 2));
}

/* The never-modified helper: x1 = ror(x1 + 0x123, 13). */
static uint64_t
helper_sim(uint64_t x1)
{
    return ror64(x1 + 0x123, 13);
}

/* Emits k checksum steps on x1 and returns their effect in ops[] (type in
 * the high bits, operand in the low ones) for simulation.
 */
static int
emit_ops(as_t *a, rng_t *r, int k, uint32_t *ops)
{
    for (int i = 0; i < k; i++) {
        int t = (int)rn(r, 3);
        uint32_t imm = t == 0 ? 1 + rn(r, 4095) : 1 + rn(r, 63);
        ops[i] = ((uint32_t)t << 16) | imm;
        if (t == 0)
            put(a, e_addi(1, 1, imm));
        else if (t == 1)
            put(a, e_eor_ror(1, 1, 1, (int)imm));
        else
            put(a, e_ror(1, 1, (int)imm));
    }
    return k;
}

static uint64_t
sim_ops(uint64_t x1, const uint32_t *ops, int k)
{
    for (int i = 0; i < k; i++) {
        uint32_t t = ops[i] >> 16, imm = ops[i] & 0xffff;
        if (t == 0)
            x1 += imm;
        else if (t == 1)
            x1 ^= ror64(x1, (int)imm);
        else
            x1 = ror64(x1, (int)imm);
    }
    return x1;
}

/* Generates generation gen into words[cap] (to be installed at base): UDF
 * filler, then the entries at random offsets.  Returns 0 if it did not fit.
 */
static int
gen_pub_code(rng_t *r, uint32_t *words, int cap, uint64_t base, uint64_t helper,
             uint64_t gen, int nentry, pubrec_t *rec)
{
    for (int i = 0; i < cap; i++)
        words[i] = E_UDF;
    as_t a;
    as_init(&a, words, cap);
    int start = (int)rn(r, (uint32_t)cap / 3);
    for (int i = 0; i < start; i++)
        put(&a, E_UDF);
    rec->gen = gen;
    rec->nentry = nentry;
    for (int e = 0; e < nentry; e++) {
        for (int i = (int)rn(r, 8); i > 0; i--)
            put(&a, E_UDF);
        rec->entry[e] = base + 4ULL * a.n;
        put_tag(&a, 0, gen, e);
        uint64_t c = rnext(r) & 0xffffffffULL;
        put(&a, e_movz(1, 1, (uint32_t)(c & 0xffff), 0));
        put(&a, e_movk(1, 1, (uint32_t)(c >> 16), 1));
        uint64_t x1 = c;
        int nseg = 1 + (int)rn(r, 6);
        for (int s = 0; s < nseg; s++) {
            uint32_t ops[32];
            int t = (int)rn(r, 100);
            if (t < 35) {
                int k = emit_ops(&a, r, 1 + (int)rn(r, 24), ops);
                x1 = sim_ops(x1, ops, k);
            } else if (t < 50) {
                /* A loop: a trace head. */
                int n = 2 + (int)rn(r, 20);
                int l = 8 * e + s;
                put(&a, e_movz(1, 10, (uint32_t)n, 0));
                label(&a, l);
                int k = emit_ops(&a, r, 1 + (int)rn(r, 8), ops);
                put(&a, e_subsi(10, 10, 1));
                put_fix(&a, e_bcond(0, COND_NE), l, JFX_BCOND);
                for (int i = 0; i < n; i++)
                    x1 = sim_ops(x1, ops, k);
            } else if (t < 62) {
                /* An indirect jump inside the code. */
                int l = 8 * e + s;
                put_fix(&a, e_adr(9, 0), l, JFX_ADR);
                put(&a, e_br(9));
                for (int i = (int)rn(r, 3); i >= 0; i--)
                    put(&a, E_UDF);
                label(&a, l);
            } else if (t < 72) {
                /* A direct jump over junk. */
                int l = 8 * e + s;
                put_fix(&a, e_b(0), l, JFX_B);
                for (int i = (int)rn(r, 3); i >= 0; i--)
                    put(&a, E_UDF);
                label(&a, l);
            } else if (t < 85) {
                /* An indirect call to the helper; it returns into this code. */
                put(&a, E_STP_FP_LR);
                put_mov64(&a, 9, helper);
                put(&a, e_blr(9));
                put(&a, E_LDP_FP_LR);
                x1 = helper_sim(x1);
            } else {
                /* NOPs: several blocks, crossing cache lines and pages. */
                for (int i = 1 + (int)rn(r, (uint32_t)cap / 4); i > 0; i--)
                    put(&a, E_NOP);
            }
        }
        put_tag(&a, 2, gen, e);
        put(&a, E_RET);
        rec->x1[e] = x1;
    }
    return as_resolve(&a);
}

static void
pub_check(pub_round_t *R, exec_t *ex, const pubrec_t *rec, int e, const out_t *o)
{
    uint64_t tag = tag_of(rec->gen, e);
    ex->calls++;
    if (o->x0 == tag && o->x2 == tag && o->x1 == rec->x1[e])
        return;
    ex->fails++;
    /* Classify: an older generation's complete result, or a mixture. */
    const char *what = "a mixed or unknown instruction sequence";
    uint64_t g0 = o->x0 & 0xffffffffULL;
    int e0 = (int)((o->x0 >> 32) & 0xff);
    if (o->x0 == o->x2 && ((o->x0 >> 40) & 0xff) == 0xa5 && e0 < MAXE) {
        const pubrec_t *old = &R->rec[g0 % NREC];
        if (g0 != (rec->gen & 0xffffffffULL)) {
            if (old->gen == g0 && e0 < old->nentry && o->x1 == old->x1[e0])
                what = "a complete older generation";
            else
                what = "another generation's tags";
        } else if (e0 != e)
            what = "another entry's code";
        else
            what = "this generation's tags with a wrong checksum";
    }
    logf_fail("    executor %d gen %llu entry %d (0x%llx): got x0 0x%llx x1 0x%llx x2 "
              "0x%llx, expected tag 0x%llx x1 0x%llx: %s\n",
              ex->id, (unsigned long long)rec->gen, e, (unsigned long long)rec->entry[e],
              (unsigned long long)o->x0, (unsigned long long)o->x1,
              (unsigned long long)o->x2, (unsigned long long)tag,
              (unsigned long long)rec->x1[e], what);
}

static void *
pub_executor(void *arg)
{
    exec_t *ex = (exec_t *)arg;
    pub_round_t *R = ex->R;
    rng_t r = { ex->seed };
    uint64_t last = 0;
    int same = 0, same_max = 0;
    while (!__atomic_load_n(&R->stop, __ATOMIC_ACQUIRE)) {
        uint64_t g = __atomic_load_n(&R->pub, __ATOMIC_ACQUIRE);
        /* Re-run a generation a bounded number of times (enough to build
         * traces), then wait for the next one: the interesting executions
         * are the first ones after a publication.
         */
        if (g == last && ++same > same_max)
            g = 0;
        if (g == 0) {
            relax();
            continue;
        }
        if (g != last) {
            same = 0;
            same_max = (int)rn(&r, 120);
        }
        if (R->proto != PROTO_MEMBAR)
            isb();
        pubrec_t rec = R->rec[g % NREC];
        if (rec.gen != g || g < last) {
            logf_fail("    executor %d: publication record %llu reads gen %llu (last "
                      "%llu): harness error\n",
                      ex->id, (unsigned long long)g, (unsigned long long)rec.gen,
                      (unsigned long long)last);
            ex->fails++;
            break;
        }
        for (int i = 1 + (int)rn(&r, (uint32_t)R->max_calls); i > 0; i--) {
            int e = (int)rn(&r, (uint32_t)rec.nentry);
            out_t o;
            call_code(rec.entry[e], 0, &o);
            pub_check(R, ex, &rec, e, &o);
        }
        __atomic_store_n(&ex->ack, g, __ATOMIC_RELEASE);
        last = g;
    }
    return NULL;
}

static uint64_t
min_ack(pub_round_t *R)
{
    uint64_t m = ~0ULL;
    for (int i = 0; i < R->nexec; i++) {
        uint64_t a = __atomic_load_n(&R->ex[i].ack, __ATOMIC_ACQUIRE);
        if (a < m)
            m = a;
    }
    return m;
}

/* Installs words at buffer b according to the round's install mode. */
static void
pub_install(pub_round_t *R, int b, const uint32_t *words)
{
    uint8_t *p = (uint8_t *)(uintptr_t)R->buf_base[b];
    size_t len = R->stride;
    switch (R->inst) {
    case INST_RWX_PACKED:
    case INST_RWX_PAGED: memcpy(p, words, len); break;
    case INST_MPROT:
        xmprotect(p, len, PROT_READ | PROT_WRITE);
        memcpy(p, words, len);
        xmprotect(p, len, PROT_READ | PROT_EXEC);
        break;
    case INST_REMAP:
        xmmap(p, len, PROT_READ | PROT_WRITE, MAP_FIXED);
        memcpy(p, words, len);
        xmprotect(p, len, PROT_READ | PROT_EXEC);
        break;
    case INST_UNMAP: {
        if (munmap(p, len) != 0) {
            perror("ERROR: munmap");
            _exit(2);
        }
        void *q = mmap(p, len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (q != (void *)p) {
            /* Something else took the address meanwhile (DR or libc may map
             * memory at any time): use a new one.  Counted.
             */
            if (q != MAP_FAILED)
                munmap(q, len);
            q = xmmap(NULL, len, PROT_READ | PROT_WRITE, 0);
            R->va_moved++;
            R->buf_base[b] = (uint64_t)(uintptr_t)q;
            p = (uint8_t *)q;
        }
        memcpy(p, words, len);
        xmprotect(p, len, PROT_READ | PROT_EXEC);
        break;
    }
    }
}

static void
pub_writer(pub_round_t *R, uint64_t deadline, rng_t *r)
{
    int cap = (int)(R->stride / 4);
    uint32_t *words = malloc(R->stride);
    for (uint64_t g = 1;; g++) {
        int b = (int)(g % (uint64_t)R->nbuf);
        /* Buffer b last held g - nbuf: wait until no executor can run it. */
        if (g > (uint64_t)R->nbuf) {
            uint64_t need = g - (uint64_t)R->nbuf + 1;
            while (min_ack(R) < need && now_ns() < deadline)
                relax();
            if (min_ack(R) < need)
                break;
        }
        if (now_ns() >= deadline)
            break;
        pubrec_t rec;
        int nentry = 1 + (int)rn(r, MAXE);
        int ok = 0;
        for (int tries = 0; tries < 8 && !ok; tries++) {
            ok = gen_pub_code(r, words, cap, R->buf_base[b],
                              (uint64_t)(uintptr_t)R->helper, g, nentry, &rec);
        }
        if (!ok) {
            fprintf(stderr, "ERROR: cannot generate code for gen %llu\n",
                    (unsigned long long)g);
            _exit(2);
        }
        uint64_t old_base = R->buf_base[b];
        pub_install(R, b, words);
        if (R->buf_base[b] != old_base) {
            /* The buffer moved: relocate the code (it has no absolute
             * self-references, only the helper's address) and the entries.
             */
            for (int e = 0; e < rec.nentry; e++)
                rec.entry[e] = rec.entry[e] - old_base + R->buf_base[b];
        }
        maintain(R->buf_base[b], R->stride, R->proto);
        if (R->proto == PROTO_MEMBAR)
            membarrier_sync_core();
        R->rec[g % NREC] = rec;
        __atomic_store_n(&R->pub, g, __ATOMIC_RELEASE);
        R->gens++;
    }
    free(words);
}

/* cmodx: the loop the executor spins in.  x10 counts down from 2^32; the
 * NOP at P becomes "b OUT".  Returns the entry's index.
 */
static int
gen_cmodx(as_t *a, rng_t *r, int *patch_idx, int *out_idx)
{
    for (int i = (int)rn(r, 200); i > 0; i--)
        put(a, E_UDF);
    int entry = a->n;
    put(a, e_movz(1, 1, 0, 0));
    put(a, e_movz(1, 10, 1, 2)); /* 2^32 */
    label(a, 0);
    put(a, e_addi(1, 1, 1));
    for (int i = (int)rn(r, 6); i > 0; i--)
        put(a, E_NOP);
    *patch_idx = a->n;
    put(a, E_NOP);
    put(a, e_subsi(10, 10, 1));
    put_fix(a, e_bcond(0, COND_NE), 0, JFX_BCOND);
    *out_idx = a->n;
    put(a, e_movz(1, 2, 0xc0de, 0));
    put(a, E_RET);
    return entry;
}

static void *
cmodx_executor(void *arg)
{
    exec_t *ex = (exec_t *)arg;
    pub_round_t *R = ex->R;
    uint64_t last = 0;
    while (!__atomic_load_n(&R->stop, __ATOMIC_ACQUIRE)) {
        uint64_t s = __atomic_load_n(&R->cm_arm, __ATOMIC_ACQUIRE);
        if (s == last) {
            relax();
            continue;
        }
        isb();
        __atomic_store_n(&ex->entered, s, __ATOMIC_RELEASE);
        out_t o;
        call_code(R->cm_fn, 0, &o);
        ex->cm_out = o;
        __atomic_store_n(&ex->returned, s, __ATOMIC_RELEASE);
        last = s;
    }
    return NULL;
}

static void
cmodx_writer(pub_round_t *R, uint64_t deadline, rng_t *r, cls_stat_t *cs)
{
    exec_t *ex = &R->ex[0];
    uint32_t *P = (uint32_t *)(uintptr_t)R->cm_patch;
    for (uint64_t s = 1; now_ns() < deadline; s++) {
        __atomic_store_n(&R->cm_arm, s, __ATOMIC_RELEASE);
        while (__atomic_load_n(&ex->entered, __ATOMIC_ACQUIRE) != s) {
            if (now_ns() > deadline + 20000000000ULL) {
                logf_fail("    cmodx: the executor did not start call %llu\n",
                          (unsigned long long)s);
                cs->fails++;
                return;
            }
            relax();
        }
        for (volatile int i = (int)rn(r, 200000); i > 0; i--)
            ;
        *P = R->cm_insn;
        maintain(R->cm_patch, 4, PROTO_FULL);
        uint64_t t0 = now_ns();
        while (__atomic_load_n(&ex->returned, __ATOMIC_ACQUIRE) != s) {
            if (now_ns() - t0 > 120000000000ULL) {
                logf_fail("    cmodx: the executor did not return from call %llu in "
                          "120 s\n",
                          (unsigned long long)s);
                cs->fails++;
                return;
            }
            relax();
        }
        uint64_t lat = now_ns() - t0;
        if (lat > cs->max_latency_ns)
            cs->max_latency_ns = lat;
        out_t o = ex->cm_out;
        cs->calls++;
        cs->gens++;
        if (o.x10 == 0 || o.x2 != 0xc0de) {
            cs->fails++;
            logf_fail("    cmodx call %llu: the patched branch was not taken (x10 %llu, "
                      "x2 0x%llx, %llu iterations, %.3f s after maintenance)\n",
                      (unsigned long long)s, (unsigned long long)o.x10,
                      (unsigned long long)o.x2, (unsigned long long)o.x1, lat / 1e9);
        } else
            cs->checked++;
        /* Restore the NOP while the executor is outside the code. */
        *P = E_NOP;
        maintain(R->cm_patch, 4, PROTO_FULL);
    }
}

static const variant_t *g_variant;
static int g_app_dic;

/* Whether the class's protocol is a valid one to use under the variant. */
static int
pub_class_valid(const variant_t *v, int proto)
{
    if (proto == PROTO_MEMBAR && !membarrier_ok)
        return 0;
    /* With software cache consistency DR only sees IC IVAU: an app that
     * skips it because CTR_EL0.DIC is set is not supported (i#5771).
     */
    if (proto == PROTO_CTR && g_app_dic && !variant_hwcc(v))
        return 0;
    return 1;
}

static int
pub_round(const variant_t *v, uint64_t seed, double secs)
{
    rng_t r = { seed * 0x9e3779b97f4a7c15ULL + 1 };
    pub_round_t *R = calloc(1, sizeof(*R));
    R->seed = seed;
    R->v = v;
    R->cls = (int)(seed % PUB_NCLS);
    cls_stat_t *cs = &g_cls[R->cls];
    char cname[64];
    pub_class_name(R->cls, cname, sizeof(cname));
    if (R->cls != CLS_CMODX) {
        R->proto = R->cls / NINST;
        R->inst = R->cls % NINST;
        if (!pub_class_valid(v, R->proto)) {
            cs->inconclusive++;
            free(R);
            return 0;
        }
    }
    if (known_issue(v, cname) != NULL) {
        cs->inconclusive++;
        free(R);
        return 0;
    }
    cs->rounds++;
    log_reset();
    R->nexec = R->cls == CLS_CMODX ? 1 : 1 + (int)rn(&r, MAXEX);
    R->nbuf = 2 + (int)rn(&r, MAXBUF - 1);
    R->max_calls = 1 + (int)rn(&r, 6);
    char desc[256];
    snprintf(desc, sizeof(desc), "%s %s executors %d buffers %d calls<=%d", g_mode, cname,
             R->nexec, R->nbuf, R->max_calls);
    g_round_seed = seed;
    g_round_desc = desc;
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "%.63s", desc);
    a64p_prog->seed = seed;
    if (verbose)
        fprintf(stderr, "  round %llu: %s\n", (unsigned long long)seed, desc);

    /* The helper (never modified). */
    R->helper = xmmap(NULL, page_size, PROT_READ | PROT_WRITE, 0);
    {
        uint32_t hw[3] = { e_addi(1, 1, 0x123), e_ror(1, 1, 13), E_RET };
        memcpy(R->helper, hw, sizeof(hw));
        xmprotect(R->helper, page_size, PROT_READ | PROT_EXEC);
        maintain((uint64_t)(uintptr_t)R->helper, sizeof(hw), PROTO_FULL);
    }
    int packed = R->cls != CLS_CMODX && R->inst == INST_RWX_PACKED;
    R->stride = packed ? PACKED_STRIDE : (size_t)PAGED_PAGES * page_size;
    if (packed) {
        /* Start the buffers half a page in, so that they straddle pages. */
        R->arena_len = 2 * page_size + MAXBUF * PACKED_STRIDE;
        R->arena = xmmap(NULL, R->arena_len, PROT_READ | PROT_WRITE | PROT_EXEC, 0);
        for (int b = 0; b < R->nbuf; b++)
            R->buf_base[b] = (uint64_t)(uintptr_t)R->arena + page_size / 2 +
                (uint64_t)b * PACKED_STRIDE;
    } else {
        R->arena_len = (size_t)R->nbuf * R->stride;
        int rwx = R->cls == CLS_CMODX || R->inst == INST_RWX_PAGED;
        R->arena =
            xmmap(NULL, R->arena_len, PROT_READ | PROT_WRITE | (rwx ? PROT_EXEC : 0), 0);
        if (!rwx)
            xmprotect(R->arena, R->arena_len, PROT_READ | PROT_EXEC);
        for (int b = 0; b < R->nbuf; b++)
            R->buf_base[b] = (uint64_t)(uintptr_t)R->arena + (uint64_t)b * R->stride;
    }
    if (R->cls == CLS_CMODX) {
        as_t a;
        uint32_t *w = (uint32_t *)R->arena;
        as_init(&a, w, (int)(R->stride / 4));
        int pidx, oidx;
        int entry = gen_cmodx(&a, &r, &pidx, &oidx);
        if (!as_resolve(&a)) {
            fprintf(stderr, "ERROR: cmodx generation\n");
            _exit(2);
        }
        R->cm_fn = (uint64_t)(uintptr_t)(w + entry);
        R->cm_patch = (uint64_t)(uintptr_t)(w + pidx);
        R->cm_insn = e_b((oidx - pidx) * 4);
        maintain((uint64_t)(uintptr_t)w, 4ULL * a.n, PROTO_FULL);
    }

    uint64_t deadline = now_ns() + (uint64_t)(secs * 1e9);
    for (int i = 0; i < R->nexec; i++) {
        exec_t *ex = &R->ex[i];
        ex->id = i;
        ex->R = R;
        ex->seed = rnext(&r);
        if (pthread_create(&ex->th, NULL,
                           R->cls == CLS_CMODX ? cmodx_executor : pub_executor,
                           ex) != 0) {
            fprintf(stderr, "ERROR: pthread_create\n");
            _exit(2);
        }
    }
    if (R->cls == CLS_CMODX)
        cmodx_writer(R, deadline, &r, cs);
    else
        pub_writer(R, deadline, &r);
    __atomic_store_n(&R->stop, 1, __ATOMIC_RELEASE);
    for (int i = 0; i < R->nexec; i++)
        pthread_join(R->ex[i].th, NULL);
    long fails = 0;
    if (R->cls != CLS_CMODX) {
        cs->gens += R->gens;
        for (int i = 0; i < R->nexec; i++) {
            cs->calls += R->ex[i].calls;
            cs->checked += R->ex[i].calls - R->ex[i].fails;
            fails += R->ex[i].fails;
        }
        cs->fails += fails;
    } else
        fails = log_n;
    if (fails > 0 || log_n > 0) {
        fprintf(stderr,
                "FAIL [%s] variant=%s: round seed %llu (%s): %ld failed calls, %ld "
                "generations\n%s",
                g_mode, v->name, (unsigned long long)seed, desc, fails, R->gens, log_buf);
        fprintf(stderr,
                "A64P-REPLAY v1 prog=a64_prop_jit mode=%s variant=%s seed=%llu "
                "dr_ops=\"%s\" page=%ld ctr=0x%llx\n  repro: a64_prop_jit %s -seed %llu "
                "-n 1 -variants %s -v\n",
                g_mode, v->name, (unsigned long long)seed,
                v->dr_ops == NULL ? "" : v->dr_ops, page_size,
                (unsigned long long)read_ctr(), g_mode, (unsigned long long)seed,
                v->name);
    }
    if (R->cls == CLS_CMODX || R->inst != INST_UNMAP || R->va_moved == 0) {
        munmap(R->arena, R->arena_len);
    } else {
        for (int b = 0; b < R->nbuf; b++)
            munmap((void *)(uintptr_t)R->buf_base[b], R->stride);
    }
    munmap(R->helper, page_size);
    int ret = fails > 0 || log_n > 0;
    free(R);
    return ret;
}

/***************************************************************************
 * selfmod mode.
 */
enum {
    SM_SAME,     /* the target later in the same block */
    SM_NEXTBB,   /* the target in the next block */
    SM_PAGE,     /* the target on the next page */
    SM_LOOP,     /* patched and then executed in each loop iteration */
    SM_LOOPBACK, /* patched for the next loop iteration */
    SM_PAIR,     /* two words straddling a cache line or page */
    SM_BRANCH,   /* a branch whose target is patched */
    SM_STALE,    /* an executed instr is patched, then a fault before maintenance */
    NSM
};
static const char *const sm_name[] = { "same-block", "next-block", "next-page",
                                       "loop",       "loop-next",  "pair",
                                       "branch",     "stale-fault" };
#define SM_NCLS (NSM * 2)

#define SM_MAXT 4

/* Emits the maintenance for the line(s) at x7 (and x8 if two). */
static void
sm_maint(as_t *a, int proto, int two, int lbase)
{
    if (proto == PROTO_CTR) {
        put(a, e_mrs_ctr(9));
        put_fix(a, e_tbnz(9, 28, 0), lbase, JFX_TBNZ);
    }
    put(a, e_dc_cvau(7));
    if (two)
        put(a, e_dc_cvau(8));
    if (proto == PROTO_CTR)
        label(a, lbase);
    put(a, E_DSB_ISH);
    if (proto == PROTO_CTR)
        put_fix(a, e_tbnz(9, 29, 0), lbase + 1, JFX_TBNZ);
    put(a, e_ic_ivau(7));
    if (two)
        put(a, e_ic_ivau(8));
    put(a, E_DSB_ISH);
    if (proto == PROTO_CTR)
        label(a, lbase + 1);
    put(a, E_ISB);
}

/* x6 = encoding of "movz x3, #(x4 & 0xffff)"; x7 = &label tl. */
static void
sm_patch_movz(as_t *a, int proto, int tl, int lbase)
{
    put(a, e_and_ffff(5, 4));
    put(a, e_lsl5(5, 5));
    put(a, e_movz(0, 6, 0x0003, 0));
    put(a, e_movk(0, 6, 0xd280, 1));
    put(a, e_orr_w(6, 6, 5));
    put_fix(a, e_adr(7, 0), tl, JFX_ADR);
    put(a, e_str_w(6, 7, 0));
    sm_maint(a, proto, 0, lbase);
}

/* Pads with NOPs until the next instruction's address mod align is want. */
static void
pad_to(as_t *a, uint64_t base, uint64_t align, uint64_t want)
{
    while (((base + 4ULL * a->n) & (align - 1)) != want && !a->overflow)
        put(a, E_NOP);
}

typedef struct {
    int kind, proto, nloop;
    uint64_t fn, t_addr, end;
    uint64_t fault_pc, lit_addr; /* SM_STALE */
} smfn_t;

#define SM_STALE_FAULT_ADDR 16
#define SM_STALE_LIT 0x1122334455667788ULL

static int
gen_selfmod(as_t *a, rng_t *r, uint64_t base, int kind, int proto, smfn_t *f)
{
    f->kind = kind;
    f->proto = proto;
    f->nloop = 2 + (int)rn(r, 12);
    for (int i = (int)rn(r, 16); i > 0; i--)
        put(a, E_UDF);
    f->fn = base + 4ULL * a->n;
    enum { L_T = 0, L_T2, L_LOOP, L_OLD, L_NEW, L_JOIN, L_M = 10 };
    put(a, e_movz(1, 1, 0, 0));
    switch (kind) {
    case SM_SAME:
    case SM_NEXTBB:
    case SM_PAGE:
        sm_patch_movz(a, proto, L_T, L_M);
        if (kind == SM_SAME) {
            for (int i = (int)rn(r, 20); i > 0; i--)
                put(a, E_NOP);
        } else if (kind == SM_NEXTBB) {
            put_fix(a, e_b(0), L_T, JFX_B);
            for (int i = (int)rn(r, 3); i >= 0; i--)
                put(a, E_UDF);
        } else {
            pad_to(a, base, (uint64_t)page_size, 4ULL * rn(r, 4));
        }
        label(a, L_T);
        put(a, e_movz(1, 3, 0x5a5a, 0));
        put(a, e_add(1, 1, 3));
        break;
    case SM_LOOP:
        put(a, e_movz(1, 10, (uint32_t)f->nloop, 0));
        label(a, L_LOOP);
        sm_patch_movz(a, proto, L_T, L_M);
        for (int i = (int)rn(r, 4); i > 0; i--)
            put(a, E_NOP);
        label(a, L_T);
        put(a, e_movz(1, 3, 0x5a5a, 0));
        put(a, e_add(1, 1, 3));
        put(a, e_addi(4, 4, 1));
        put(a, e_subsi(10, 10, 1));
        put_fix(a, e_bcond(0, COND_NE), L_LOOP, JFX_BCOND);
        break;
    case SM_LOOPBACK:
        put(a, e_movz(1, 10, (uint32_t)f->nloop, 0));
        sm_patch_movz(a, proto, L_T, L_M);
        label(a, L_LOOP);
        label(a, L_T);
        put(a, e_movz(1, 3, 0x5a5a, 0));
        put(a, e_add(1, 1, 3));
        put(a, e_addi(4, 4, 1));
        sm_patch_movz(a, proto, L_T, L_M + 2);
        put(a, e_subsi(10, 10, 1));
        put_fix(a, e_bcond(0, COND_NE), L_LOOP, JFX_BCOND);
        break;
    case SM_PAIR:
        put(a, e_and_ffff(5, 4));
        put(a, e_lsl5(5, 5));
        put(a, e_movz(0, 6, 0x0003, 0));
        put(a, e_movk(0, 6, 0xd280, 1));
        put(a, e_orr_w(6, 6, 5));
        put(a, e_ubfx16(11, 4));
        put(a, e_lsl5(11, 11));
        put(a, e_movz(0, 12, 0x0003, 0));
        put(a, e_movk(0, 12, 0xf2a0, 1));
        put(a, e_orr_w(12, 12, 11));
        put_fix(a, e_adr(7, 0), L_T, JFX_ADR);
        put(a, e_str_w(6, 7, 0));
        put(a, e_str_w(12, 7, 4));
        put(a, e_addi(8, 7, 4));
        sm_maint(a, proto, 1, L_M);
        /* T at the end of a cache line or of a page. */
        pad_to(a, base, rn(r, 2) ? (uint64_t)page_size : 64, rn(r, 2) ? 60 : 56);
        label(a, L_T);
        put(a, e_movz(1, 3, 0x5a5a, 0));
        put(a, e_movk(1, 3, 0xa5a5, 1));
        put(a, e_add(1, 1, 3));
        break;
    case SM_BRANCH: {
        /* T: "b OLD" or "b NEW"; OLD is T + 4 and NEW is T + 12. */
        int npad = (int)rn(r, 8);
        uint32_t bold = e_b(4), bnew = e_b(12);
        put(a, e_tst1(4));
        put(a, e_movz(0, 5, bold & 0xffff, 0));
        put(a, e_movk(0, 5, bold >> 16, 1));
        put(a, e_movz(0, 6, bnew & 0xffff, 0));
        put(a, e_movk(0, 6, bnew >> 16, 1));
        put(a, e_csel_w(6, 6, 5, COND_NE));
        put_fix(a, e_adr(7, 0), L_T, JFX_ADR);
        put(a, e_str_w(6, 7, 0));
        sm_maint(a, proto, 0, L_M);
        for (int i = 0; i < npad; i++)
            put(a, E_NOP);
        label(a, L_T);
        put(a, bold);               /* T: b OLD */
        put(a, e_movz(1, 3, 1, 0)); /* OLD */
        put_fix(a, e_b(0), L_JOIN, JFX_B);
        put(a, e_movz(1, 3, 2, 0)); /* NEW (T + 12) */
        label(a, L_JOIN);
        put(a, e_add(1, 1, 3));
        break;
    }
    case SM_STALE: {
        /* T, which this call has already executed, is rewritten with x4's encoding
         * (sm_stale_pick()), and a load later in the same block faults before the
         * maintenance: the fault frame must be the old code's, whatever the new
         * code at T would make of the block (a branch ends it; ADR and a literal load
         * are replaced with longer sequences under DR).  The handler resumes after the
         * load; the maintenance then makes the next call execute the new T.
         */
        put(a, e_movz(1, 3, 0, 0));
        label(a, L_T);
        put(a, e_movz(1, 3, 0x5a5a, 0));
        put(a, e_add(1, 1, 3));
        put_fix(a, e_adr(7, 0), L_T, JFX_ADR);
        put(a, e_str_w(4, 7, 0));
        for (int i = (int)rn(r, 4); i > 0; i--)
            put(a, E_NOP);
        put(a, e_movz(1, 9, SM_STALE_FAULT_ADDR, 0));
        label(a, L_OLD);
        put(a, 0xf940012au); /* ldr x10, [x9]: faults */
        put(a, e_addi(1, 1, 1));
        put_fix(a, e_adr(7, 0), L_T, JFX_ADR);
        sm_maint(a, proto, 0, L_M);
        put(a, E_RET);
        label(a, L_NEW);
        put(a, (uint32_t)SM_STALE_LIT);
        put(a, (uint32_t)(SM_STALE_LIT >> 32));
        f->fault_pc = base + 4ULL * (uint64_t)a->lab[L_OLD];
        f->lit_addr = base + 4ULL * (uint64_t)a->lab[L_NEW];
        f->t_addr = base + 4ULL * (uint64_t)a->lab[L_T];
        f->end = base + 4ULL * (uint64_t)a->n;
        return as_resolve(a);
    }
    }
    put(a, E_RET);
    f->t_addr = base + 4ULL * (uint64_t)a->lab[L_T];
    f->end = base + 4ULL * (uint64_t)a->n;
    return as_resolve(a);
}

static uint64_t
sm_expect(const smfn_t *f, uint64_t v)
{
    switch (f->kind) {
    case SM_LOOP:
    case SM_LOOPBACK: {
        uint64_t s = 0;
        for (int i = 0; i < f->nloop; i++)
            s += (v + (uint64_t)i) & 0xffff;
        return s;
    }
    case SM_PAIR: return v & 0xffffffffULL;
    case SM_BRANCH: return (v & 1) ? 2 : 1;
    default: return v & 0xffff;
    }
}

typedef struct {
    int id;
    pthread_t th;
    smfn_t f;
    uint64_t seed, deadline;
    long calls, fails;
    volatile int *go;
    /* SM_STALE: the fault frame, recorded by sm_stale_handler(). */
    volatile int expect_fault, fault_seen;
    uint64_t fpc, fx[11];
} smth_t;

static __thread smth_t *tl_sm;

/* Picks the next encoding for an SM_STALE function's T and the value it leaves in
 * x3: one of MOVZ (the control: the block's layout does not change), ADR, a literal
 * load and a branch to the next instruction (which leaves x3 zero).
 */
static uint32_t
sm_stale_pick(rng_t *r, const smfn_t *f, uint64_t *val)
{
    switch (rn(r, 4)) {
    case 0: {
        uint32_t imm = (uint32_t)rn(r, 0x10000);
        *val = imm;
        return e_movz(1, 3, imm, 0);
    }
    case 1: {
        int off = 4 * (int)rn(r, 256);
        *val = f->t_addr + (uint64_t)off;
        return e_adr(3, off);
    }
    case 2: *val = 0; return e_b(4);
    default: {
        int64_t off = (int64_t)(f->lit_addr - f->t_addr);
        *val = SM_STALE_LIT;
        return 0x58000003u | (((uint32_t)(off / 4) & 0x7ffffu) << 5);
    }
    }
}

/* SIGSEGV: the expected fault of an SM_STALE function, or a failure. */
static void
sm_stale_handler(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    smth_t *t = tl_sm;
    if (t == NULL || !t->expect_fault ||
        si->si_addr != (void *)(uintptr_t)SM_STALE_FAULT_ADDR) {
        fatal_handler(sig, si, ucv);
        return;
    }
    t->expect_fault = 0;
    t->fault_seen = 1;
    t->fpc = uc->uc_mcontext.pc;
    for (int i = 0; i < 11; i++)
        t->fx[i] = uc->uc_mcontext.regs[i];
    /* After the load, even if the frame's pc is wrong. */
    uc->uc_mcontext.pc = t->f.fault_pc + 4;
}

/* One call of an SM_STALE function whose T now leaves *cur in x3. */
static void
sm_stale_call(smth_t *t, rng_t *r, uint64_t *cur)
{
    uint64_t next;
    uint32_t enc = sm_stale_pick(r, &t->f, &next);
    out_t o;
    t->fault_seen = 0;
    t->expect_fault = 1;
    call_code(t->f.fn, enc, &o);
    t->expect_fault = 0;
    t->calls++;
    uint64_t want = *cur + 1;
    if (o.x1 != want || !t->fault_seen || t->fpc != t->f.fault_pc || t->fx[1] != *cur ||
        t->fx[3] != *cur || t->fx[4] != enc || t->fx[7] != t->f.t_addr ||
        t->fx[9] != SM_STALE_FAULT_ADDR) {
        t->fails++;
        logf_fail("    thread %d %s/%s call %ld: T 0x%llx now 0x%08x: result 0x%llx "
                  "expected 0x%llx; fault %s at pc 0x%llx (expected 0x%llx), x1 0x%llx "
                  "x3 0x%llx (expected 0x%llx) x4 0x%llx x7 0x%llx x9 0x%llx\n",
                  t->id, sm_name[t->f.kind], proto_name[t->f.proto], t->calls,
                  (unsigned long long)t->f.t_addr, enc, (unsigned long long)o.x1,
                  (unsigned long long)want, t->fault_seen ? "seen" : "missing",
                  (unsigned long long)t->fpc, (unsigned long long)t->f.fault_pc,
                  (unsigned long long)t->fx[1], (unsigned long long)t->fx[3],
                  (unsigned long long)*cur, (unsigned long long)t->fx[4],
                  (unsigned long long)t->fx[7], (unsigned long long)t->fx[9]);
    }
    *cur = next;
}

static void *
sm_thread(void *arg)
{
    smth_t *t = (smth_t *)arg;
    rng_t r = { t->seed };
    while (!__atomic_load_n(t->go, __ATOMIC_ACQUIRE))
        relax();
    isb();
    tl_sm = t;
    if (t->f.kind == SM_STALE) {
        uint64_t cur = 0x5a5a;
        while (now_ns() < t->deadline)
            sm_stale_call(t, &r, &cur);
        tl_sm = NULL;
        return NULL;
    }
    uint64_t prev = ~0ULL;
    while (now_ns() < t->deadline) {
        uint64_t v = rnext(&r);
        /* A value whose result equals the previous call's would hide a stale
         * target.
         */
        if (sm_expect(&t->f, v) == prev)
            v += 1;
        out_t o;
        call_code(t->f.fn, v, &o);
        uint64_t want = sm_expect(&t->f, v);
        t->calls++;
        if (o.x1 != want) {
            t->fails++;
            uint32_t *tw = (uint32_t *)(uintptr_t)t->f.t_addr;
            logf_fail("    thread %d %s/%s call %ld: arg 0x%llx: result 0x%llx (x3 "
                      "0x%llx), expected 0x%llx (previous call's 0x%llx); fn 0x%llx T "
                      "0x%llx now %08x %08x end 0x%llx\n",
                      t->id, sm_name[t->f.kind], proto_name[t->f.proto], t->calls,
                      (unsigned long long)v, (unsigned long long)o.x1,
                      (unsigned long long)o.x3, (unsigned long long)want,
                      (unsigned long long)prev, (unsigned long long)t->f.fn,
                      (unsigned long long)t->f.t_addr, tw[0], tw[1],
                      (unsigned long long)t->f.end);
        }
        prev = want;
    }
    return NULL;
}

/* force: NULL, or {threads, class, packed} to fix the round's shape (every
 * thread gets the class), or {threads, -1, packed, class of each thread...}.
 */
static int
sm_round(const variant_t *v, uint64_t seed, double secs, const int *force)
{
    rng_t r = { seed * 0x9e3779b97f4a7c15ULL + 7 };
    int cls0 = (int)(seed % SM_NCLS);
    int nth = 1 + (int)rn(&r, SM_MAXT);
    int packed = (int)rn(&r, 2);
    /* For reducing a failure: A64_PROP_JIT_SM="threads,class,packed". */
    int force_cls = -1;
    const char *fenv = getenv("A64_PROP_JIT_SM");
    if (force != NULL) {
        nth = force[0];
        force_cls = force[1];
        packed = force[2];
    } else if (fenv != NULL && sscanf(fenv, "%d,%d,%d", &nth, &force_cls, &packed) != 3) {
        fprintf(stderr, "ERROR: A64_PROP_JIT_SM=threads,class,packed\n");
        _exit(2);
    }
    size_t stride = packed ? 0x400 : 2 * (size_t)page_size;
    size_t arena_len = 2 * (size_t)page_size + SM_MAXT * stride;
    uint8_t *arena = xmmap(NULL, arena_len, PROT_READ | PROT_WRITE | PROT_EXEC, 0);
    uint8_t *start = packed ? arena + page_size - 0x200 : arena;
    g_code_lo = (uint64_t)(uintptr_t)arena;
    g_code_hi = (uint64_t)(uintptr_t)arena + arena_len;
    smth_t th[SM_MAXT];
    volatile int go = 0;
    log_reset();
    char desc[256];
    int dl = snprintf(desc, sizeof(desc), "%s %s threads %d:", g_mode,
                      packed ? "packed" : "paged", nth);
    uint64_t deadline;
    for (int i = 0; i < nth; i++) {
        int c = force_cls >= 0 ? force_cls : i == 0 ? cls0 : (int)rn(&r, SM_NCLS);
        if (force != NULL && force[1] < 0)
            c = force[3 + i];
        int kind = c % NSM, proto = c / NSM;
        if (proto == PROTO_CTR && g_app_dic && !variant_hwcc(v)) {
            g_cls[c].inconclusive++;
            proto = PROTO_FULL;
            c = kind;
        }
        if (packed && kind == SM_PAGE)
            kind = SM_SAME, c = proto * NSM + kind;
        char cn[64];
        snprintf(cn, sizeof(cn), "%s/%s", sm_name[kind], proto_name[proto]);
        if (known_issue(v, cn) != NULL) {
            g_cls[c].inconclusive++;
            kind = SM_SAME;
            c = proto * NSM + kind;
        }
        uint64_t base = (uint64_t)(uintptr_t)start + (uint64_t)i * stride;
        as_t a;
        as_init(&a, (uint32_t *)(uintptr_t)base, (int)(stride / 4));
        memset(&th[i], 0, sizeof(th[i]));
        if (!gen_selfmod(&a, &r, base, kind, proto, &th[i].f)) {
            /* Packed functions can overflow their slot: use a short kind. */
            as_init(&a, (uint32_t *)(uintptr_t)base, (int)(stride / 4));
            kind = SM_SAME;
            c = proto * NSM + kind;
            if (!gen_selfmod(&a, &r, base, kind, proto, &th[i].f)) {
                fprintf(stderr, "ERROR: selfmod generation\n");
                _exit(2);
            }
        }
        th[i].id = i;
        th[i].seed = rnext(&r);
        th[i].go = &go;
        g_cls[c].rounds++;
        dl += snprintf(desc + dl, sizeof(desc) - dl, " %s/%s", sm_name[kind],
                       proto_name[proto]);
    }
    maintain((uint64_t)(uintptr_t)arena, arena_len, PROTO_FULL);
    g_round_seed = seed;
    g_round_desc = desc;
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "%.63s", desc);
    a64p_prog->seed = seed;
    if (verbose)
        fprintf(stderr, "  round %llu: %s\n", (unsigned long long)seed, desc);
    deadline = now_ns() + (uint64_t)(secs * 1e9);
    for (int i = 0; i < nth; i++) {
        th[i].deadline = deadline;
        if (pthread_create(&th[i].th, NULL, sm_thread, &th[i]) != 0) {
            fprintf(stderr, "ERROR: pthread_create\n");
            _exit(2);
        }
    }
    __atomic_store_n(&go, 1, __ATOMIC_RELEASE);
    long fails = 0;
    for (int i = 0; i < nth; i++) {
        pthread_join(th[i].th, NULL);
        int c = th[i].f.proto * NSM + th[i].f.kind;
        g_cls[c].calls += th[i].calls;
        g_cls[c].checked += th[i].calls - th[i].fails;
        g_cls[c].fails += th[i].fails;
        g_cls[c].gens++;
        fails += th[i].fails;
    }
    if (fails > 0) {
        fprintf(stderr,
                "FAIL [%s] variant=%s: round seed %llu (%s): %ld failed calls\n%s",
                g_mode, v->name, (unsigned long long)seed, desc, fails, log_buf);
        fprintf(stderr,
                "A64P-REPLAY v1 prog=a64_prop_jit mode=%s variant=%s seed=%llu "
                "dr_ops=\"%s\" page=%ld ctr=0x%llx\n  repro: a64_prop_jit %s -seed %llu "
                "-n 1 -variants %s -v\n",
                g_mode, v->name, (unsigned long long)seed,
                v->dr_ops == NULL ? "" : v->dr_ops, page_size,
                (unsigned long long)read_ctr(), g_mode, (unsigned long long)seed,
                v->name);
    }
    munmap(arena, arena_len);
    return fails > 0;
}

/***************************************************************************
 * patch mode: a fault in code built from a call target that the app has
 * since retargeted, before the app's cache maintenance.
 *
 * HotSpot retargets calls constantly (inline cache transitions, relinking) and
 * patches entries, writing the instruction first and doing IC IVAU after.
 * Until then a thread may run the old instructions (B, BL and NOP may be
 * modified concurrently with their execution), so a thread can still run, and
 * fault in, a block DR built from the old code.  DR then translates the fault
 * by decoding the code again: if it had followed (elided) the old target into
 * the caller's block, the new decode follows the new target and the fault is
 * reported at the new target's instruction (a HotSpot crash in
 * ~BufferBlob::InlineCacheBuffer under -no_hw_cache_consistency, fixed by not
 * eliding a cti whose page or target page is writable then).
 *
 * Each round: a caller C reaches site X through a cti; X, Y and Z are sites of
 * the same shape "movz x6, #tag; ldr x7, [x1, #off]; movz x0, #tag; ret" with
 * distinct tags and offsets.  An executor thread primes C (it builds and runs
 * C's code with a valid x1); the writer then retargets the cti from X to Y
 * with one aligned store (or, for "entry", replaces X's leading NOP with
 * "b Z") and does no maintenance yet; the executor calls C with x1 = NULL.
 * Either stream is legal: the old one faults at X's load with si_addr = X's
 * offset and x6 = X's tag, the new one at Y's (Z's) with Y's (Z's).  The
 * handler requires the reported pc, si_addr and x6 to belong to one site, and
 * x1, x5 (set by C) and, for BL, x30 to be C's.  The writer then completes
 * the maintenance and the executor must see only the new stream.
 *
 * Classes: BL or B retargeted in a caller on an RWX page with the sites on the
 * same page ("packed") or their own RWX pages ("paged"); BL in a caller on an
 * RWX page with the sites read-only ("bl-target-ro"); "entry", a caller on a
 * read-only page calling X on an RWX page whose entry NOP becomes "b Z"; and
 * "entry" with X's page read-only (RX) until the writer makes it writable for
 * the patch: RWX ("entry-mprot"), or RW and back to RX before the executor's
 * fault ("entry-wx", a W^X JIT); and "entry" with X's page an RX mapping of a
 * memfd that is never writable, written (and patched) through a second, RW
 * mapping of it ("entry-alias", a double-mapped JIT); and "entry-wx" with X on
 * the second page of a mapping whose first page holds an ELF header written
 * after the mapping was made ("entry-lazymod", as a custom loader that copies an
 * image into memory might): DR finds that module only when X first runs; and
 * "entry-alias" with X in the middle page of an RX mapping of an ELF image (DR
 * adds the module at the mmap) whose two segments are its first and last pages
 * ("entry-gap"): X is in the gap between a module's segments, outside it.
 * Under -no_hw_cache_consistency DR only learns of the write from the IC
 * IVAU, so the old stream ("stale") is what DR runs: each class must observe
 * it at least once there, or the round did not test anything (a floor).
 */
enum {
    PT_BL_PACKED,
    PT_BL_PAGED,
    PT_BL_TGT_RO,
    PT_B_PACKED,
    PT_B_PAGED,
    PT_ENTRY,
    PT_ENTRY_MPROT,
    PT_ENTRY_WX,
    PT_ENTRY_ALIAS,
    PT_ENTRY_LAZYMOD,
    PT_ENTRY_GAP,
    NPT
};
static const char *const pt_name[] = { "bl-packed",     "bl-paged", "bl-target-ro",
                                       "b-packed",      "b-paged",  "entry",
                                       "entry-mprot",   "entry-wx", "entry-alias",
                                       "entry-lazymod", "entry-gap" };
#define PT_NSITE 3 /* X (old), Y (new for a retarget), Z (new for "entry") */
static const uint32_t pt_tag[PT_NSITE] = { 0x0a1, 0x0b2, 0x0c3 };
static const uint32_t pt_off[PT_NSITE] = { 8, 16, 24 };
#define PT_C_TAG 0x5c
#define PT_FAULT_MARK 0xfa17
#define PT_ROUNDS_PER_CLASS 8

static uint32_t
e_bl(int off)
{
    return 0x94000000u | ((uint32_t)(off / 4) & 0x3ffffffu);
}
/* ldr xt, [xn, #off] */
static uint32_t
e_ldr_x(int rt, int rn, int off)
{
    return 0xf9400000u | ((uint32_t)(off / 8) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}

typedef struct {
    int cls, bl, nprime;
    uint8_t *map[3];
    size_t map_len[3];
    uint8_t *alias; /* entry-alias: the RW mapping of map[1], which is RX */
    uint8_t *res;   /* the reservation the maps are in */
    size_t res_len;
    uint64_t c_fn, ret_after; /* ret_after: x30 at the fault for BL, else 0 */
    uint64_t site[PT_NSITE], ldr[PT_NSITE];
    uint64_t patch_at;
    uint32_t patch_insn;
    int new_site;
    uint64_t data[4];
} pt_layout_t;

/* What the SIGSEGV handler saw. */
typedef struct {
    volatile int armed, hits;
    int signo, code;
    uint64_t pc, addr, x1, x5, x6, x30;
} pt_fault_t;
static pt_fault_t g_ptf;
static __thread int pt_is_executor;

static void
pt_handler(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    if (!pt_is_executor || !g_ptf.armed) {
        fatal_handler(sig, si, ucv);
        return;
    }
    g_ptf.armed = 0;
    g_ptf.hits++;
    g_ptf.signo = sig;
    g_ptf.code = si->si_code;
    g_ptf.pc = uc->uc_mcontext.pc;
    g_ptf.addr = (uint64_t)(uintptr_t)si->si_addr;
    g_ptf.x1 = uc->uc_mcontext.regs[1];
    g_ptf.x5 = uc->uc_mcontext.regs[5];
    g_ptf.x6 = uc->uc_mcontext.regs[6];
    g_ptf.x30 = uc->uc_mcontext.regs[30];
    /* Return from the site (to C after its BL, or to pt_call for B). */
    uc->uc_mcontext.pc = uc->uc_mcontext.regs[30];
    uc->uc_mcontext.regs[0] = PT_FAULT_MARK;
}

/* Calls fn with x1 = arg; returns x0 and the loaded x7. */
static uint64_t
pt_call(uint64_t fn, uint64_t arg, uint64_t *x7_out)
{
    register uint64_t x0 __asm__("x0");
    register uint64_t x1 __asm__("x1") = arg;
    register uint64_t x7 __asm__("x7") = 0;
    register uint64_t x16 __asm__("x16") = fn;
    __asm__ volatile("blr x16"
                     : "=r"(x0), "+r"(x1), "+r"(x7), "+r"(x16)
                     :
                     : "x2", "x3", "x4", "x5", "x6", "x8", "x9", "x10", "x11", "x12",
                       "x13", "x14", "x15", "x17", "x30", "memory", "cc");
    *x7_out = x7;
    return x0;
}

static void
pt_put_site(uint32_t *w, int s, int entry_nop)
{
    int i = 0;
    if (entry_nop)
        w[i++] = E_NOP;
    w[i++] = e_movz(1, 6, pt_tag[s], 0);
    w[i++] = e_ldr_x(7, 1, (int)pt_off[s]);
    w[i++] = e_movz(1, 0, pt_tag[s], 0);
    w[i++] = E_RET;
}

/* Returns where to write the code at at: through the alias for map 1 if it has one. */
static uint32_t *
pt_writable(const pt_layout_t *L, uint64_t at)
{
    uint64_t m1 = (uint64_t)(uintptr_t)L->map[1];
    if (L->alias != NULL && at >= m1 && at < m1 + L->map_len[1])
        return (uint32_t *)(uintptr_t)(L->alias + (at - m1));
    return (uint32_t *)(uintptr_t)at;
}

/* Maps len bytes of a new memfd twice: RX at at, returned in *exec_out, and RW at the
 * returned address.
 */
static uint8_t *
pt_map_alias(size_t len, uint8_t *at, uint8_t **exec_out)
{
    int fd = memfd_create("a64p_alias", MFD_CLOEXEC);
    if (fd < 0 || ftruncate(fd, (off_t)len) != 0) {
        fprintf(stderr, "ERROR: memfd: %s\n", strerror(errno));
        _exit(2);
    }
    void *rw = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    void *rx = mmap(at, len, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, fd, 0);
    if (rw == MAP_FAILED || rx == MAP_FAILED) {
        fprintf(stderr, "ERROR: mmap of a memfd: %s\n", strerror(errno));
        _exit(2);
    }
    close(fd);
    *exec_out = (uint8_t *)rx;
    return (uint8_t *)rw;
}

static void
pt_put_elf_header(uint8_t *p, size_t len);

/* Maps a memfd of len bytes at at, RW (so DR sees no ELF header at the mmap), and
 * writes an ELF header in its first page describing the whole mapping as one RX
 * segment.  The caller leaves an inaccessible page on each side: DR merges adjacent
 * executable areas, and a thread that has run code next to it would not look its pages
 * up again (and find the module) when it first runs code in it.
 */
static uint8_t *
pt_map_lazymod(size_t len, uint8_t *at)
{
    int fd = memfd_create("a64p_lazymod", MFD_CLOEXEC);
    if (fd < 0 || ftruncate(fd, (off_t)len) != 0) {
        fprintf(stderr, "ERROR: memfd: %s\n", strerror(errno));
        _exit(2);
    }
    uint8_t *p = mmap(at, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "ERROR: mmap of a memfd: %s\n", strerror(errno));
        _exit(2);
    }
    close(fd);
    pt_put_elf_header(p, len);
    return p;
}

/* Maps a memfd of len (3 pages) bytes twice: RX at at, returned in *exec_out, and RW
 * at the returned address, with an ELF header written before the RX mapping, so DR
 * adds the module at that mmap, whose two RX segments are the first and last pages.
 */
static uint8_t *
pt_map_gapmod(size_t len, uint8_t *at, uint8_t **exec_out)
{
    int fd = memfd_create("a64p_gapmod", MFD_CLOEXEC);
    if (fd < 0 || ftruncate(fd, (off_t)len) != 0) {
        fprintf(stderr, "ERROR: memfd: %s\n", strerror(errno));
        _exit(2);
    }
    uint8_t *rw = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (rw == MAP_FAILED) {
        fprintf(stderr, "ERROR: mmap of a memfd: %s\n", strerror(errno));
        _exit(2);
    }
    pt_put_elf_header(rw, (size_t)page_size);
    Elf64_Ehdr *eh = (Elf64_Ehdr *)rw;
    Elf64_Phdr *ph = (Elf64_Phdr *)(rw + sizeof(*eh));
    ph[1] = ph[0];
    ph[1].p_offset = ph[1].p_vaddr = ph[1].p_paddr = len - (size_t)page_size;
    eh->e_phnum = 2;
    void *rx = mmap(at, len, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, fd, 0);
    if (rx == MAP_FAILED) {
        fprintf(stderr, "ERROR: mmap of a memfd: %s\n", strerror(errno));
        _exit(2);
    }
    close(fd);
    *exec_out = (uint8_t *)rx;
    return rw;
}

/* Writes at p an ELF header describing [p, p + len) as one RX segment. */
static void
pt_put_elf_header(uint8_t *p, size_t len)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)p;
    Elf64_Phdr *ph = (Elf64_Phdr *)(p + sizeof(*eh));
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_ident[EI_DATA] = ELFDATA2LSB;
    eh->e_ident[EI_VERSION] = EV_CURRENT;
    eh->e_ident[EI_OSABI] = ELFOSABI_SYSV;
    eh->e_type = ET_DYN;
    eh->e_machine = EM_AARCH64;
    eh->e_version = EV_CURRENT;
    eh->e_phoff = sizeof(*eh);
    eh->e_ehsize = sizeof(*eh);
    eh->e_phentsize = sizeof(*ph);
    eh->e_phnum = 1;
    eh->e_shentsize = sizeof(Elf64_Shdr);
    ph->p_type = PT_LOAD;
    ph->p_flags = PF_R | PF_X;
    ph->p_filesz = ph->p_memsz = len;
    ph->p_align = (uint64_t)page_size;
}

/* Builds the round's code.  Slots are 64-byte aligned offsets in their pages. */
static void
pt_build(pt_layout_t *L, rng_t *r)
{
    int cls = L->cls;
    int packed = cls == PT_BL_PACKED || cls == PT_B_PACKED;
    L->bl = cls != PT_B_PACKED && cls != PT_B_PAGED;
    int nmap = packed ? 1 : 3;
    /* map 0: C (and the sites if packed); map 1: X (and Y); map 2: Y or Z.
     * entry-lazymod's map 1 is the header page, then the sites' page.
     */
    L->res_len = (size_t)page_size;
    for (int m = 0; m < nmap; m++) {
        size_t pages = 1;
        if (m == 1 && cls == PT_ENTRY_LAZYMOD)
            pages = 2;
        else if (m == 1 && cls == PT_ENTRY_GAP)
            pages = 3;
        L->map_len[m] = pages * (size_t)page_size;
        L->res_len += L->map_len[m] + (size_t)page_size;
    }
    /* The mappings come from one reservation, an inaccessible page apart: so that C's
     * BL reaches them (mappings of their own can land gigabytes apart under DR), and DR
     * does not merge them into one area.
     */
    L->res = xmmap(NULL, L->res_len, PROT_NONE, 0);
    uint8_t *at = L->res + page_size;
    for (int m = 0; m < nmap; m++) {
        if (m == 1 && cls == PT_ENTRY_ALIAS)
            L->alias = pt_map_alias(L->map_len[m], at, &L->map[m]);
        else if (m == 1 && cls == PT_ENTRY_LAZYMOD)
            L->map[m] = pt_map_lazymod(L->map_len[m], at);
        else if (m == 1 && cls == PT_ENTRY_GAP)
            L->alias = pt_map_gapmod(L->map_len[m], at, &L->map[m]);
        else {
            L->map[m] =
                xmmap(at, L->map_len[m], PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED);
        }
        at += L->map_len[m] + page_size;
    }
    int nslot = (int)(page_size / 64);
    uint64_t c_at, site_at[PT_NSITE];
    if (packed) {
        /* Four distinct slots on one page. */
        int slot[4];
        for (int i = 0; i < 4; i++) {
            int ok;
            do {
                slot[i] = (int)rn(r, (uint32_t)nslot);
                ok = 1;
                for (int j = 0; j < i; j++)
                    ok = ok && slot[j] != slot[i];
            } while (!ok);
        }
        c_at = (uint64_t)(uintptr_t)L->map[0] + 64ULL * slot[0];
        for (int s = 0; s < PT_NSITE; s++)
            site_at[s] = (uint64_t)(uintptr_t)L->map[0] + 64ULL * slot[1 + s];
    } else {
        int sx = (int)rn(r, (uint32_t)nslot), sy;
        do
            sy = (int)rn(r, (uint32_t)nslot);
        while (sy == sx);
        c_at = (uint64_t)(uintptr_t)L->map[0] + 64ULL * rn(r, (uint32_t)nslot);
        /* X's page: the second of map 1 if it has more than one. */
        uint64_t sites1 = (uint64_t)(uintptr_t)L->map[1] +
            (L->map_len[1] > (size_t)page_size ? (uint64_t)page_size : 0);
        site_at[0] = sites1 + 64ULL * sx;
        if (cls == PT_BL_TGT_RO) {
            /* X and Y on one page that becomes read-only. */
            site_at[1] = sites1 + 64ULL * sy;
        } else
            site_at[1] = (uint64_t)(uintptr_t)L->map[2] + 64ULL * sy;
        site_at[2] = (uint64_t)(uintptr_t)L->map[2] + 64ULL * ((sy + 1) % nslot);
    }
    int entry = cls == PT_ENTRY || cls == PT_ENTRY_MPROT || cls == PT_ENTRY_WX ||
        cls == PT_ENTRY_ALIAS || cls == PT_ENTRY_LAZYMOD || cls == PT_ENTRY_GAP;
    for (int s = 0; s < PT_NSITE; s++) {
        pt_put_site(pt_writable(L, site_at[s]), s, entry && s == 0);
        L->site[s] = site_at[s];
        L->ldr[s] = site_at[s] + (entry && s == 0 ? 8 : 4);
    }
    L->new_site = entry ? 2 : 1;
    /* The caller: [stp] nops; movz x5, #tag; bl|b X; [ldp; ret]. */
    as_t a;
    uint32_t *cw = (uint32_t *)(uintptr_t)c_at;
    as_init(&a, cw, 16);
    if (L->bl)
        put(&a, E_STP_FP_LR);
    for (int i = (int)rn(r, 4); i > 0; i--)
        put(&a, E_NOP);
    put(&a, e_movz(1, 5, PT_C_TAG, 0));
    uint64_t cti = c_at + 4ULL * a.n;
    int off_x = (int)(int64_t)(site_at[0] - cti);
    put(&a, L->bl ? e_bl(off_x) : e_b(off_x));
    if (L->bl) {
        put(&a, E_LDP_FP_LR);
        put(&a, E_RET);
    }
    L->c_fn = c_at;
    L->ret_after = L->bl ? cti + 4 : 0;
    if (entry) {
        L->patch_at = site_at[0];
        L->patch_insn = e_b((int)(int64_t)(site_at[2] - site_at[0]));
    } else {
        L->patch_at = cti;
        int off_y = (int)(int64_t)(site_at[1] - cti);
        L->patch_insn = L->bl ? e_bl(off_y) : e_b(off_y);
    }
    for (int m = 0; m < nmap; m++)
        maintain((uint64_t)(uintptr_t)L->map[m], L->map_len[m], PROTO_FULL);
    /* Read-only parts: the sites for bl-target-ro; C and Z for entry; X too (until
     * the patch) for entry-mprot, entry-wx and entry-lazymod.  entry-alias's X is
     * never writable where it runs.
     */
    if (cls == PT_BL_TGT_RO || cls == PT_ENTRY_MPROT || cls == PT_ENTRY_WX ||
        cls == PT_ENTRY_LAZYMOD)
        xmprotect(L->map[1], L->map_len[1], PROT_READ | PROT_EXEC);
    if (entry) {
        xmprotect(L->map[0], L->map_len[0], PROT_READ | PROT_EXEC);
        xmprotect(L->map[2], L->map_len[2], PROT_READ | PROT_EXEC);
    }
    for (int i = 0; i < 4; i++)
        L->data[i] = rnext(r) | 1;
}

/* Executor/writer hand-off. */
static volatile int pt_step;
static pt_layout_t *pt_L;
/* The executor's findings for the round. */
static int pt_stale, pt_fresh, pt_fails;

static void
pt_wait(int step)
{
    while (__atomic_load_n(&pt_step, __ATOMIC_ACQUIRE) != step)
        relax();
}

static void
pt_go(int step)
{
    __atomic_store_n(&pt_step, step, __ATOMIC_RELEASE);
}

/* Returns the site whose fault g_ptf describes, or -1 with the problem logged. */
static int
pt_check_fault(const pt_layout_t *L, const char *when, int want_site)
{
    if (g_ptf.hits != 1) {
        logf_fail("    %s: %d faults recorded, expected 1\n", when, g_ptf.hits);
        return -1;
    }
    int by_addr = -1, by_pc = -1, by_tag = -1;
    for (int s = 0; s < PT_NSITE; s++) {
        if (g_ptf.addr == pt_off[s])
            by_addr = s;
        if (g_ptf.pc == L->ldr[s])
            by_pc = s;
        if (g_ptf.x6 == pt_tag[s])
            by_tag = s;
    }
    int ok = g_ptf.signo == SIGSEGV && by_addr >= 0 && by_addr == by_pc &&
        by_addr == by_tag && g_ptf.x1 == 0 && g_ptf.x5 == PT_C_TAG &&
        (L->ret_after == 0 || g_ptf.x30 == L->ret_after) &&
        (by_addr == 0 || by_addr == L->new_site) &&
        (want_site < 0 || by_addr == want_site);
    if (ok)
        return by_addr;
    char pcw[48] = "an unknown pc";
    for (int s = 0; s < PT_NSITE; s++) {
        if (g_ptf.pc >= L->site[s] && g_ptf.pc < L->site[s] + 20)
            snprintf(pcw, sizeof(pcw), "site %c+%llu", "XYZ"[s],
                     (unsigned long long)(g_ptf.pc - L->site[s]));
    }
    logf_fail("    %s: signal %d at pc 0x%llx (%s) si_addr 0x%llx x6 0x%llx x1 0x%llx x5 "
              "0x%llx x30 0x%llx; sites X 0x%llx Y 0x%llx Z 0x%llx (load at +%d), "
              "expected x30 0x%llx: the access is site %c's (si_addr), the tag site "
              "%c's, the pc site %c's%s\n",
              when, g_ptf.signo, (unsigned long long)g_ptf.pc, pcw,
              (unsigned long long)g_ptf.addr, (unsigned long long)g_ptf.x6,
              (unsigned long long)g_ptf.x1, (unsigned long long)g_ptf.x5,
              (unsigned long long)g_ptf.x30, (unsigned long long)L->site[0],
              (unsigned long long)L->site[1], (unsigned long long)L->site[2],
              (int)(L->ldr[0] - L->site[0]), (unsigned long long)L->ret_after,
              by_addr < 0 ? '?' : "XYZ"[by_addr], by_tag < 0 ? '?' : "XYZ"[by_tag],
              by_pc < 0 ? '?' : "XYZ"[by_pc],
              by_addr == 0 && by_pc > 0
                  ? ": the old code faulted and was reported at the new code"
                  : "");
    return -1;
}

/* One call of C with x1 = NULL that must fault in a site. */
static int
pt_fault_call(const pt_layout_t *L, const char *when, int want_site)
{
    uint64_t x7;
    memset(&g_ptf, 0, sizeof(g_ptf));
    __atomic_store_n(&g_ptf.armed, 1, __ATOMIC_RELEASE);
    uint64_t x0 = pt_call(L->c_fn, 0, &x7);
    g_ptf.armed = 0;
    if (x0 != PT_FAULT_MARK) {
        logf_fail("    %s: C with x1 = NULL returned x0 0x%llx without faulting\n", when,
                  (unsigned long long)x0);
        return -1;
    }
    return pt_check_fault(L, when, want_site);
}

/* One call of C with a valid x1 that must run site s. */
static int
pt_good_call(const pt_layout_t *L, const char *when, int s)
{
    uint64_t x7, x0 = pt_call(L->c_fn, (uint64_t)(uintptr_t)L->data, &x7);
    if (x0 == pt_tag[s] && x7 == L->data[pt_off[s] / 8])
        return 0;
    logf_fail("    %s: C returned x0 0x%llx x7 0x%llx, expected site %c's 0x%x 0x%llx\n",
              when, (unsigned long long)x0, (unsigned long long)x7, "XYZ"[s], pt_tag[s],
              (unsigned long long)L->data[pt_off[s] / 8]);
    return -1;
}

static void *
pt_executor(void *arg)
{
    pt_layout_t *L = pt_L;
    pt_is_executor = 1;
    pt_wait(1);
    isb();
    for (int i = 0; i < L->nprime; i++) {
        if (pt_good_call(L, "priming", 0) < 0)
            pt_fails++;
    }
    pt_go(2);
    pt_wait(3);
    /* Retargeted, maintenance withheld: either stream. */
    int s = pt_fault_call(L, "before maintenance", -1);
    if (s < 0)
        pt_fails++;
    else if (s == 0)
        pt_stale++;
    else
        pt_fresh++;
    pt_go(4);
    pt_wait(5);
    /* Maintenance done: only the new stream. */
    isb();
    if (pt_good_call(L, "after maintenance", L->new_site) < 0)
        pt_fails++;
    if (pt_fault_call(L, "after maintenance", L->new_site) < 0)
        pt_fails++;
    pt_go(6);
    return NULL;
}

static int
pt_round(const variant_t *v, uint64_t seed)
{
    rng_t r = { seed * 0x9e3779b97f4a7c15ULL + 11 };
    pt_layout_t L;
    memset(&L, 0, sizeof(L));
    L.cls = (int)(seed % NPT);
    cls_stat_t *cs = &g_cls[L.cls];
    if (known_issue(v, pt_name[L.cls]) != NULL) {
        cs->inconclusive++;
        return 0;
    }
    cs->rounds++;
    log_reset();
    L.nprime = 1 + (int)rn(&r, 3);
    pt_build(&L, &r);
    char desc[160];
    snprintf(desc, sizeof(desc), "%s %s prime %d C 0x%llx X 0x%llx Y 0x%llx Z 0x%llx",
             g_mode, pt_name[L.cls], L.nprime, (unsigned long long)L.c_fn,
             (unsigned long long)L.site[0], (unsigned long long)L.site[1],
             (unsigned long long)L.site[2]);
    g_round_seed = seed;
    g_round_desc = desc;
    snprintf(a64p_prog->phase, sizeof(a64p_prog->phase), "%.63s", desc);
    a64p_prog->seed = seed;
    if (verbose)
        fprintf(stderr, "  round %llu: %s\n", (unsigned long long)seed, desc);
    pt_L = &L;
    pt_stale = pt_fresh = pt_fails = 0;
    pt_step = 0;
    pthread_t th;
    if (pthread_create(&th, NULL, pt_executor, NULL) != 0) {
        fprintf(stderr, "ERROR: pthread_create\n");
        _exit(2);
    }
#ifndef A64P_EXTERNAL_DR
    g_watch_seen = 0;
    g_watch_mod = L.cls == PT_ENTRY_LAZYMOD ? L.map[1] : NULL;
#endif
    pt_go(1);
    pt_wait(2);
#ifndef A64P_EXTERNAL_DR
    if (L.cls == PT_ENTRY_LAZYMOD && v->dr_ops != NULL && !g_watch_seen) {
        /* X has run: DR must have found its module then (its load event is on its
         * first execution), or the class is just another anonymous one.
         */
        logf_fail("    after priming: DR found no module for X\n");
        pt_fails++;
    }
#endif
    /* Retarget with one aligned store and no maintenance. */
    int wx = L.cls == PT_ENTRY_WX || L.cls == PT_ENTRY_LAZYMOD;
    if (L.cls == PT_ENTRY_MPROT || wx) {
        xmprotect(L.map[1], L.map_len[1],
                  PROT_READ | PROT_WRITE | (L.cls == PT_ENTRY_MPROT ? PROT_EXEC : 0));
    }
    __atomic_store_n(pt_writable(&L, L.patch_at), L.patch_insn, __ATOMIC_RELAXED);
    if (wx)
        xmprotect(L.map[1], L.map_len[1], PROT_READ | PROT_EXEC);
    pt_go(3);
    pt_wait(4);
    maintain(L.patch_at, 4, PROTO_FULL);
    pt_go(5);
    pthread_join(th, NULL);
    for (int m = 0; m < 3; m++) {
        /* Each map by itself (an unmap of entry-lazymod's module is one of all of
         * it), then the rest of the reservation.
         */
        if (L.map[m] != NULL)
            munmap(L.map[m], L.map_len[m]);
    }
    if (L.alias != NULL)
        munmap(L.alias, L.map_len[1]);
    munmap(L.res, L.res_len);
    cs->gens++;
    cs->calls += L.nprime + 3;
    cs->stale += pt_stale;
    if (pt_fails == 0)
        cs->checked++;
    cs->fails += pt_fails;
    if (pt_fails > 0) {
        fprintf(stderr,
                "FAIL [%s] variant=%s: round seed %llu (%s): %d failed checks\n%s",
                g_mode, v->name, (unsigned long long)seed, desc, pt_fails, log_buf);
        fprintf(stderr,
                "A64P-REPLAY v1 prog=a64_prop_jit mode=%s variant=%s seed=%llu "
                "dr_ops=\"%s\" page=%ld ctr=0x%llx\n  repro: a64_prop_jit %s -seed %llu "
                "-n 1 -variants %s -v\n",
                g_mode, v->name, (unsigned long long)seed,
                v->dr_ops == NULL ? "" : v->dr_ops, page_size,
                (unsigned long long)read_ctr(), g_mode, (unsigned long long)seed,
                v->name);
    }
    return pt_fails > 0;
}

/* Under -external (drrun with elision): a module of an R header page and an RX text
 * page, mapped as a loader does (the whole file, then the text segment over it), so DR
 * adds it at its mapping.  Its text has a function with a forward branch, which DR
 * elides into the function's block, over a word to a load.  After the function has run,
 * the app unmaps the header page alone, which drops the module from DR's list while
 * the text and its block stay.  Calling the function with x1 = NULL must report the
 * fault at the load: DR translates it by recreating the block, which must still elide
 * the branch (whether code is outside modules may not change for a block that lives).
 */
static int
pt_header_unmap(void)
{
    int fails = 0;
    size_t len = 2 * (size_t)page_size;
    int fd = memfd_create("a64p_hdrunmap", MFD_CLOEXEC);
    if (fd < 0 || ftruncate(fd, (off_t)len) != 0) {
        fprintf(stderr, "ERROR: memfd: %s\n", strerror(errno));
        _exit(2);
    }
    /* Write the file through a mapping made while it holds no ELF header. */
    uint8_t *w = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (w == MAP_FAILED) {
        fprintf(stderr, "ERROR: mmap of a memfd: %s\n", strerror(errno));
        _exit(2);
    }
    pt_put_elf_header(w, len);
    uint32_t *t = (uint32_t *)(w + page_size);
    int n = 0;
    t[n++] = e_movz(1, 6, 0xd1, 0);
    t[n++] = e_b(8); /* over the next word */
    t[n++] = E_UDF;
    int ldr = n;
    t[n++] = e_ldr_x(7, 1, 8);
    t[n++] = e_movz(1, 0, 0xd1, 0);
    t[n++] = E_RET;
    munmap(w, len);
    /* An inaccessible page each side keeps DR from merging the module's areas with
     * others.
     */
    uint8_t *guard = xmmap(NULL, len + 2 * (size_t)page_size, PROT_NONE, 0);
    uint8_t *base = guard + page_size;
    if (mmap(base, len, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) == MAP_FAILED ||
        mmap(base + page_size, (size_t)page_size, PROT_READ | PROT_EXEC,
             MAP_SHARED | MAP_FIXED, fd, page_size) == MAP_FAILED) {
        fprintf(stderr, "ERROR: mmap of a memfd: %s\n", strerror(errno));
        _exit(2);
    }
    close(fd);
    uint64_t fn = (uint64_t)(uintptr_t)(base + page_size);
    maintain(fn, (uint64_t)page_size, PROTO_FULL);
    isb();
    uint64_t data[2] = { 0, 0x5eed }, x7;
    for (int i = 0; i < 2; i++) {
        if (pt_call(fn, (uint64_t)(uintptr_t)data, &x7) != 0xd1 || x7 != data[1]) {
            fprintf(stderr, "FAIL [patch] header-unmap: priming call %d\n", i);
            fails++;
        }
    }
    munmap(base, (size_t)page_size);
    pt_is_executor = 1;
    memset(&g_ptf, 0, sizeof(g_ptf));
    __atomic_store_n(&g_ptf.armed, 1, __ATOMIC_RELEASE);
    uint64_t x0 = pt_call(fn, 0, &x7);
    g_ptf.armed = 0;
    pt_is_executor = 0;
    uint64_t want = fn + 4 * (uint64_t)ldr;
    if (x0 != PT_FAULT_MARK || g_ptf.hits != 1 || g_ptf.pc != want || g_ptf.addr != 8 ||
        g_ptf.x6 != 0xd1) {
        fprintf(stderr,
                "FAIL [patch] header-unmap: after unmapping the module's header, the "
                "fault at 0x%llx was reported at pc 0x%llx (si_addr 0x%llx, x6 0x%llx, "
                "%d faults, x0 0x%llx)\n",
                (unsigned long long)want, (unsigned long long)g_ptf.pc,
                (unsigned long long)g_ptf.addr, (unsigned long long)g_ptf.x6, g_ptf.hits,
                (unsigned long long)x0);
        fails++;
    } else
        printf("patch external header-unmap: fault reported at the load\n");
    munmap(base + page_size, (size_t)page_size);
    munmap(guard, (size_t)page_size);
    munmap(base + len, (size_t)page_size);
    return fails;
}

static void
pt_install_handler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = pt_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
}

/***************************************************************************
 * Hand-written regression cases, run first in every publish child.
 */
/* Writes "movz x1, #val; ret" at p and completes full maintenance. */
static void
put_ret_val(uint8_t *p, uint32_t val)
{
    uint32_t w[2] = { e_movz(1, 1, val, 0), E_RET };
    memcpy(p, w, sizeof(w));
    maintain((uint64_t)(uintptr_t)p, sizeof(w), PROTO_FULL);
}

/* munmap() with a length that is not a page multiple unmaps every page it
 * touches: code on the partial last page must not survive in DR's cache (it
 * used to: DR removed only [addr, addr + len) from its executable areas, ran
 * the old code once new code was mapped at the same address, and asserted at
 * detach when it restored the protection of the page it had made
 * read-only).
 */
static int
regress_munmap_tail(long *checked, long *inconclusive)
{
    size_t len = 2 * (size_t)page_size;
    int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    uint8_t *p = xmmap(NULL, len, prot, 0);
    uint8_t *f = p + page_size + page_size / 2;
    out_t o;
    put_ret_val(f, 1);
    isb();
    for (int i = 0; i < 3; i++)
        call_code((uint64_t)(uintptr_t)f, 0, &o);
    if (o.x1 != 1) {
        fprintf(stderr,
                "FAIL [regress munmap-tail] variant=%s: first code returned %llu\n",
                g_variant->name, (unsigned long long)o.x1);
        munmap(p, len);
        return 1;
    }
    if (munmap(p, page_size + page_size / 4) != 0) {
        perror("ERROR: munmap");
        _exit(2);
    }
    uint8_t *q =
        mmap(p, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (q != p) {
        /* Something else took the address: nothing to check. */
        if (q != MAP_FAILED)
            munmap(q, len);
        (*inconclusive)++;
        return 0;
    }
    put_ret_val(f, 2);
    isb();
    call_code((uint64_t)(uintptr_t)f, 0, &o);
    munmap(p, len);
    (*checked)++;
    if (o.x1 != 2) {
        fprintf(stderr,
                "FAIL [regress munmap-tail] variant=%s: code mapped where an unaligned "
                "munmap removed old code returned %llu, not 2 (stale code)\n",
                g_variant->name, (unsigned long long)o.x1);
        return 1;
    }
    return 0;
}

/* Threads whose self-modifying functions share a page: a thread's write
 * fault in a block it built before another thread's write made the page's
 * area selfmod-sandboxed used to be translated with a recreated block that
 * had sandboxing (the area's current state) and so did not match the block
 * that faulted: it resumed at the block start with x0-x4 taken from stale
 * spill slots (its store then wrote a wrong instruction), or failed to
 * translate.  Four threads, same-block patches, CTR-based maintenance.
 */
static int
regress_selfmod_shared_page(long *checked, double secs)
{
    static const int shape[3] = { 4, PROTO_CTR * NSM + SM_SAME, 1 /*packed*/ };
    (*checked)++;
    int f = sm_round(g_variant, 0, secs, shape);
    if (f != 0)
        fprintf(stderr, "FAIL [regress selfmod-shared-page] variant=%s\n",
                g_variant->name);
    return f;
}

/* Self-modifying threads on their own pages whose blocks cross the
 * sandbox2ro threshold: a thread deleting its own block after a self-write
 * raced with another thread's flush unlinking that block, and both deleted
 * it (asserts in link.c, corrupted link lists).  Round seed 12's shape:
 * three threads, two-word patches and a same-block patch, CTR-based
 * maintenance.
 */
static int
regress_selfmod_self_write_race(long *checked, double secs)
{
    /* The shape round seed 12 had before the stale-fault kind was added. */
    static const int shape[3 + 3] = { 3,
                                      -1,
                                      0 /*paged*/,
                                      PROTO_CTR * NSM + SM_PAIR,
                                      PROTO_CTR * NSM + SM_PAIR,
                                      PROTO_CTR * NSM + SM_SAME };
    (*checked)++;
    int f = sm_round(g_variant, 12, secs, shape);
    if (f != 0) {
        fprintf(stderr, "FAIL [regress selfmod-self-write-race] variant=%s\n",
                g_variant->name);
    }
    return f;
}

/* Four threads patching an instruction on the next page: a write fault from a
 * block whose vm list still holds a wider area than the target's (since split
 * by another thread's selfmod marking) tripped a debug assertion in
 * handle_modified_code() that assumed the writer's block then overlaps the
 * target region.
 */
static int
regress_selfmod_next_page(long *checked, double secs)
{
    static const int shape[3] = { 4, PROTO_FULL * NSM + SM_PAGE, 0 /*paged*/ };
    (*checked)++;
    int f = sm_round(g_variant, 0, secs, shape);
    if (f != 0)
        fprintf(stderr, "FAIL [regress selfmod-next-page] variant=%s\n", g_variant->name);
    return f;
}

/* -regress_secs: the length of each selfmod regression round. */
static double g_regress_secs = 3.0;

static int
run_regressions(const variant_t *v)
{
    long checked = 0, inconclusive = 0;
    int fails = 0;
    if (strcmp(g_mode, "selfmod") == 0) {
        /* The page-protection path only (the bug's). */
        if (variant_hwcc(v)) {
            fails += regress_selfmod_shared_page(&checked, g_regress_secs);
            fails += regress_selfmod_next_page(&checked, g_regress_secs);
        }
        fails += regress_selfmod_self_write_race(&checked, g_regress_secs);
    } else
        fails += regress_munmap_tail(&checked, &inconclusive);
    printf("%s %s: regressions checked %ld, inconclusive %ld\n", g_mode, v->name, checked,
           inconclusive);
    return fails;
}

/***************************************************************************
 * Per-variant children.
 */
typedef struct {
    const variant_t *v;
    uint64_t seed;
    int n;
    double secs;
} child_args_t;

static int
ncls(void)
{
    if (strcmp(g_mode, "patch") == 0)
        return NPT;
    return strcmp(g_mode, "publish") == 0 ? PUB_NCLS : SM_NCLS;
}

static void
cls_name(int c, char *buf, size_t n)
{
    if (strcmp(g_mode, "publish") == 0)
        pub_class_name(c, buf, n);
    else if (strcmp(g_mode, "patch") == 0)
        snprintf(buf, n, "%s", pt_name[c]);
    else
        snprintf(buf, n, "%s/%s", sm_name[c % NSM], proto_name[c / NSM]);
}

/* Floors: per class, checked calls and generations (publications or
 * functions).
 */
static long
floor_checked(int c)
{
    if (strcmp(g_mode, "publish") == 0)
        return c == CLS_CMODX ? 3 : 20;
    if (strcmp(g_mode, "patch") == 0)
        return 1;
    /* Each stale-fault call takes a signal; without -hw_cache_consistency each
     * call's maintenance flushes; instrumented code is slower.  (Under load the
     * nohwcc variants fell short of 50 in some classes once a class was added.)
     */
    long f = c % NSM == SM_STALE ? 20 : 50;
    if (!variant_hwcc(g_variant))
        f /= 2;
    return g_client_mode != 0 ? f / 2 : f;
}
static long
floor_gens(int c)
{
    if (strcmp(g_mode, "publish") == 0)
        return c == CLS_CMODX ? 3 : 5;
    if (strcmp(g_mode, "patch") == 0)
        return 1;
    return 1;
}

static int g_fixed_rounds; /* -n: floors only for the classes that ran */

static int
class_below_floor(int c)
{
    if (g_cls[c].rounds == 0 && (g_cls[c].inconclusive > 0 || g_fixed_rounds))
        return 0; /* not valid under this variant: reported as inconclusive */
    return g_cls[c].checked < floor_checked(c) || g_cls[c].gens < floor_gens(c);
}

static int
run_round(const variant_t *v, uint64_t seed, double secs)
{
    if (strcmp(g_mode, "publish") == 0)
        return pub_round(v, seed, secs);
    if (strcmp(g_mode, "patch") == 0)
        return pt_round(v, seed);
    return sm_round(v, seed, secs, NULL);
}

static int
variant_child(void *arg)
{
    child_args_t *c = (child_args_t *)arg;
    const variant_t *v = c->v;
    g_variant = v;
    g_client_mode = jc_client_mode(v);
    memset(g_cls, 0, sizeof(g_cls));
    install_fatal_handlers();
    /* A watchdog: a hang (e.g. an executor stuck in stale code) kills the
     * child with SIGALRM, which the parent reports with the round.
     */
    alarm((unsigned)(120 + 10 * c->secs));
    if (v->dr_ops != NULL)
        a64p_start_dr(v->dr_ops);
    membarrier_init();
    /* What the app sees (-fake_ctr_dic changes it). */
    g_app_dic = (read_ctr() >> 29) & 1;
    int fails = 0, nc = ncls();
    g_fixed_rounds = c->n > 0;
    if (strcmp(g_mode, "patch") == 0) {
        pt_install_handler();
        if (g_external != NULL)
            fails += pt_header_unmap();
        /* Rounds take milliseconds: a fixed number per class. */
        int n = c->n > 0 ? c->n : PT_ROUNDS_PER_CLASS * nc;
        for (int i = 0; i < n; i++)
            fails += run_round(v, c->seed + (uint64_t)i, 0);
    } else
        fails += run_regressions(v);
    if (strcmp(g_mode, "patch") == 0) {
        /* Done above. */
    } else if (c->n > 0) {
        for (int i = 0; i < c->n; i++)
            fails += run_round(v, c->seed + (uint64_t)i, c->secs / nc);
    } else {
        /* One round per class, then extra rounds for classes below their
         * floors, within a bounded total.
         */
        double per = c->secs / nc;
        if (per < 0.1)
            per = 0.1;
        uint64_t s = c->seed;
        for (int i = 0; i < nc; i++, s++)
            fails += run_round(v, s, per);
        for (int extra = 0; extra < 16 * nc; extra++, s++) {
            int need = 0;
            for (int k = 0; k < nc; k++)
                need += class_below_floor(k);
            if (need == 0)
                break;
            if (class_below_floor((int)(s % (uint64_t)nc)))
                fails += run_round(v, s, per);
        }
    }
    if (v->dr_ops != NULL)
        a64p_stop_dr();
    /* Report. */
    a64p_counts_t cnt = { 0 };
    char label[128];
    for (int k = 0; k < nc; k++) {
        cls_stat_t *cs = &g_cls[k];
        cnt.generated += cs->gens;
        cnt.accepted += cs->gens;
        cnt.executed += cs->calls;
        cnt.checked += cs->checked;
        cnt.inconclusive += cs->inconclusive;
        char cn[64];
        cls_name(k, cn, sizeof(cn));
        if (verbose) {
            fprintf(stderr,
                    "  %s %s: rounds %ld gens %ld calls %ld checked %ld fails %ld "
                    "inconclusive %ld max-latency %.3f ms\n",
                    v->name, cn, cs->rounds, cs->gens, cs->calls, cs->checked, cs->fails,
                    cs->inconclusive, cs->max_latency_ns / 1e6);
        }
        if (class_below_floor(k)) {
            snprintf(label, sizeof(label), "%s variant=%s class=%s", g_mode, v->name, cn);
            fails += a64p_floor(label, "checked calls", cs->checked, floor_checked(k));
            fails += a64p_floor(label, "generations", cs->gens, floor_gens(k));
        }
        /* Without hardware cache consistency DR runs the old code until the
         * maintenance: a class that never faulted there tested nothing.
         */
        if (strcmp(g_mode, "patch") == 0 && !variant_hwcc(v) && cs->rounds > 0) {
            snprintf(label, sizeof(label), "%s variant=%s class=%s", g_mode, v->name, cn);
            fails += a64p_floor(label, "faults in the old code", cs->stale, 1);
        }
        if (strcmp(g_mode, "patch") == 0 && cs->rounds > 0) {
            printf("%s %s %s: rounds %ld checked %ld old-code faults %ld\n", g_mode,
                   v->name, cn, cs->rounds, cs->checked, cs->stale);
        }
    }
    for (size_t i = 0; known_issues[i].id != NULL; i++) {
        if (known_skipped[i] > 0) {
            printf("%s %s: known issue %s skipped %ld rounds of class %s: %s\n", g_mode,
                   v->name, known_issues[i].id, known_skipped[i], known_issues[i].cls,
                   known_issues[i].what);
        }
    }
    snprintf(label, sizeof(label), "%s %s", g_mode, v->name);
    a64p_counts_print(stdout, label, &cnt);
    if (strcmp(g_mode, "publish") == 0 && g_cls[CLS_CMODX].rounds > 0) {
        printf("%s %s: cmodx max latency from maintenance to the patched branch %.3f "
               "ms\n",
               g_mode, v->name, g_cls[CLS_CMODX].max_latency_ns / 1e6);
    }
    return fails;
}

int
main(int argc, const char *argv[])
{
    const char *mode = argc > 1 ? argv[1] : "publish";
    uint64_t seed = 1;
    int n = 0;
    double secs = -1;
    const char *vlist = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc)
            seed = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            n = atoi(argv[++i]);
        else if (strcmp(argv[i], "-secs") == 0 && i + 1 < argc)
            secs = atof(argv[++i]);
        else if (strcmp(argv[i], "-regress_secs") == 0 && i + 1 < argc)
            g_regress_secs = atof(argv[++i]);
        else if (strcmp(argv[i], "-variants") == 0 && i + 1 < argc)
            vlist = argv[++i];
        else if (strcmp(argv[i], "-external") == 0 && i + 1 < argc)
            g_external = argv[++i];
        else if (strcmp(argv[i], "-known") == 0)
            opt_known = 1;
        else if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return 2;
        }
    }
    if (strcmp(mode, "publish") != 0 && strcmp(mode, "selfmod") != 0 &&
        strcmp(mode, "patch") != 0) {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    g_mode = mode;
    if (strcmp(mode, "patch") == 0) {
        vtab = patch_variants;
        NVARIANTS = (int)(sizeof(patch_variants) / sizeof(patch_variants[0]));
    }
    if (g_external != NULL) {
        if (strcmp(g_external, "hwcc") != 0 && strcmp(g_external, "nohwcc") != 0) {
            fprintf(stderr, "-external takes hwcc or nohwcc\n");
            return 2;
        }
        vtab = external_variants;
        NVARIANTS = 1;
    }
#ifdef A64P_EXTERNAL_DR
    if (g_external == NULL) {
        fprintf(stderr, "this build runs under drrun: pass -external hwcc|nohwcc\n");
        return 2;
    }
#endif
    if (vlist != NULL && unknown_variant(vlist) != NULL) {
        fprintf(stderr, "unknown variant '%s'; variants are:", unknown_variant(vlist));
        for (int i = 0; i < NVARIANTS; i++)
            fprintf(stderr, " %s", vtab[i].name);
        fprintf(stderr, "\n");
        return 2;
    }
#ifdef A64_DR_PROP_DEBUG_DR
    is_debug_build = 1;
#endif
    {
        const char *e = getenv("A64_DR_PROP_DEBUG_DR");
        if (e != NULL)
            is_debug_build = atoi(e);
    }
    page_size = sysconf(_SC_PAGESIZE);
    a64p_progress_init("a64_prop_jit");
    setvbuf(stdout, NULL, _IOLBF, 0);
    int fails = 0, nrun = 0;
    for (int i = 0; i < NVARIANTS; i++) {
        const variant_t *v = &vtab[i];
        if (vlist != NULL ? !list_has(vlist, v->name)
                          : (v->debug_only && !is_debug_build))
            continue;
        /* The client instruments only selfmod's generated code. */
        if (jc_client_mode(v) != 0 && strcmp(mode, "selfmod") != 0)
            continue;
        const known_t *kv = known_variant(v);
        if (kv != NULL && vlist == NULL && !opt_known) {
            printf("%s %s: known issue %s: variant skipped: %s\n", mode, v->name, kv->id,
                   kv->what);
            continue;
        }
        /* A release DR runs fewer variants, each faster: give each more time. */
        double dsecs = v->dr_ops == NULL ? 2.0 : is_debug_build ? 5.0 : 10.0;
        /* Instrumented code runs slower. */
        if (jc_client_mode(v) != 0)
            dsecs *= 2;
        child_args_t a = { v, seed, n, secs >= 0 ? secs : dsecs };
        int f = a64p_in_child(mode, v, variant_child, &a);
        if (f != 0)
            fprintf(stderr, "FAIL [%s] variant=%s: %d failures\n", mode, v->name, f);
        fails += f;
        nrun++;
    }
    fails += a64p_floor(mode, "variants run", nrun, 1);
    printf("%s: %s\n", mode, fails == 0 ? "all properties hold" : "FAILURES");
    return fails == 0 ? 0 : 1;
}

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
 * An instruction-budget client in the shape of a deterministic-replay
 * "progress" client, for the AArch64 real-workload smoke tests
 * (suite/tests/a64_smoke/README.md).  It must not change what the application
 * computes, so the smoke tests compare the application's output under it with
 * a native run.
 *
 * Every block is charged its application instruction count at one or more
 * charge points.  A point loads the thread's budget from raw TLS into a
 * drreg-reserved register, subtracts the charge with non-flag-setting SUBs,
 * stores it back and tests the sign with TBZ.  When the budget runs out, a
 * READS_APP_CONTEXT | MULTIPATH clean call refills it and leaves through
 * dr_redirect_execution() back to the charged instruction (giving that
 * charge back, as the point runs again).  Before the instruction, the
 * scratch register gets its application value back with
 * drreg_get_app_value() and is unreserved.
 *
 * This mixes most of what a real client puts in a block: raw-TLS tool
 * stores of a reserved register, drreg spills whose restore has to be found
 * by state translation when a signal or fault arrives mid-block, a clean
 * call whose callee redirects, and a register handed back in place.
 *
 * Like Seedbox's client it also rewrites WFE/WFI/WFET/WFIT to NOP (keeping
 * their translation), since on one CPU a wait only changes how many times a
 * spin loop is charged.
 *
 * Client options (the same names as Seedbox's progress client):
 *   --instructions-per-progress-call N   the budget between refills (default
 *                                        1000; Seedbox runs with 50000)
 *   --progress-points-per-block N        charge points per block (default 1)
 * The two values may also be given positionally: [BUDGET [POINTS]].  With
 * A64_PROGRESS_VERBOSE set in the environment, prints the number of refills
 * at exit.
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include <limits.h>
#include <string.h>

static ptr_int_t budget_per_refill;
static uint points_per_block;
static reg_id_t tls_seg;
static uint tls_offs;
static uint64 refills;
/* Opt-in, bounded evidence for the dedicated budget-1 context probe only. */
static bool diagnose_redirect_roundtrip;
static int diagnostic_tls_idx = -1;
static uint64 diagnostic_redirects;
static uint64 diagnostic_matches;
static uint diagnostic_mismatch_reported;

typedef struct {
    dr_mcontext_t expected;
    app_pc resume;
    uint64 ordinal;
    bool pending;
} redirect_diagnostic_t;

/* Instructions left in this thread's window; negative once a charge crosses
 * the budget, and the refill carries the overshoot.
 */
static ptr_int_t *
budget_slot(void)
{
    return (ptr_int_t *)((byte *)dr_get_dr_segment_base(tls_seg) + tls_offs);
}

static void
report_roundtrip_mismatch(redirect_diagnostic_t *diagnostic, const char *field,
                          uint64 expected, uint64 actual)
{
    if (__atomic_exchange_n(&diagnostic_mismatch_reported, 1, __ATOMIC_RELAXED) != 0)
        return;
    module_data_t *module = dr_lookup_module(diagnostic->resume);
    dr_fprintf(STDERR,
               "a64_progress_like: redirect roundtrip mismatch ordinal=%llu module=%s "
               "offset=%#llx field=%s expected=%#llx actual=%#llx\n",
               (unsigned long long)diagnostic->ordinal,
               module == NULL || module->full_path == NULL ? "<untracked>"
                                                           : module->full_path,
               module == NULL
                   ? 0ULL
                   : (unsigned long long)((ptr_uint_t)diagnostic->resume -
                                          (ptr_uint_t)module->start),
               field, (unsigned long long)expected, (unsigned long long)actual);
    if (module != NULL)
        dr_free_module_data(module);
}

static void
verify_redirect_roundtrip(void)
{
    void *drcontext = dr_get_current_drcontext();
    redirect_diagnostic_t *diagnostic =
        drmgr_get_tls_field(drcontext, diagnostic_tls_idx);
    if (diagnostic == NULL || !diagnostic->pending)
        return;
    diagnostic->pending = false;

    /* Only integer and control fields are documented as valid here. The original
     * application oracle separately checks SIMD registers, FPCR and FPSR.
     */
    dr_mcontext_t actual = { sizeof(actual), DR_MC_INTEGER | DR_MC_CONTROL };
    DR_ASSERT(dr_get_mcontext(drcontext, &actual));
#define COMPARE_CONTEXT_FIELD(member, label)                                            \
    do {                                                                                \
        if (diagnostic->expected.member != actual.member) {                             \
            report_roundtrip_mismatch(diagnostic, label,                               \
                                      (uint64)diagnostic->expected.member,              \
                                      (uint64)actual.member);                           \
            return;                                                                     \
        }                                                                               \
    } while (0)
    COMPARE_CONTEXT_FIELD(r0, "x0");
    COMPARE_CONTEXT_FIELD(r1, "x1");
    COMPARE_CONTEXT_FIELD(r2, "x2");
    COMPARE_CONTEXT_FIELD(r3, "x3");
    COMPARE_CONTEXT_FIELD(r4, "x4");
    COMPARE_CONTEXT_FIELD(r5, "x5");
    COMPARE_CONTEXT_FIELD(r6, "x6");
    COMPARE_CONTEXT_FIELD(r7, "x7");
    COMPARE_CONTEXT_FIELD(r8, "x8");
    COMPARE_CONTEXT_FIELD(r9, "x9");
    COMPARE_CONTEXT_FIELD(r10, "x10");
    COMPARE_CONTEXT_FIELD(r11, "x11");
    COMPARE_CONTEXT_FIELD(r12, "x12");
    COMPARE_CONTEXT_FIELD(r13, "x13");
    COMPARE_CONTEXT_FIELD(r14, "x14");
    COMPARE_CONTEXT_FIELD(r15, "x15");
    COMPARE_CONTEXT_FIELD(r16, "x16");
    COMPARE_CONTEXT_FIELD(r17, "x17");
    COMPARE_CONTEXT_FIELD(r18, "x18");
    COMPARE_CONTEXT_FIELD(r19, "x19");
    COMPARE_CONTEXT_FIELD(r20, "x20");
    COMPARE_CONTEXT_FIELD(r21, "x21");
    COMPARE_CONTEXT_FIELD(r22, "x22");
    COMPARE_CONTEXT_FIELD(r23, "x23");
    COMPARE_CONTEXT_FIELD(r24, "x24");
    COMPARE_CONTEXT_FIELD(r25, "x25");
    COMPARE_CONTEXT_FIELD(r26, "x26");
    COMPARE_CONTEXT_FIELD(r27, "x27");
    COMPARE_CONTEXT_FIELD(r28, "x28");
    COMPARE_CONTEXT_FIELD(r29, "x29");
    COMPARE_CONTEXT_FIELD(r30, "x30");
    COMPARE_CONTEXT_FIELD(sp, "sp");
    COMPARE_CONTEXT_FIELD(nzcv, "nzcv");
#undef COMPARE_CONTEXT_FIELD
    __atomic_fetch_add(&diagnostic_matches, 1, __ATOMIC_RELAXED);
}

static void
refill_and_resume(app_pc resume, ptr_int_t charged)
{
    ptr_int_t *left = budget_slot();
    do {
        *left += budget_per_refill;
        __atomic_fetch_add(&refills, 1, __ATOMIC_RELAXED);
    } while (*left < 0);
    /* The point runs again at resume: give its charge back. */
    *left += charged;
    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    DR_ASSERT(dr_get_mcontext(dr_get_current_drcontext(), &mc));
    mc.pc = resume;
    if (diagnose_redirect_roundtrip) {
        redirect_diagnostic_t *diagnostic =
            drmgr_get_tls_field(dr_get_current_drcontext(), diagnostic_tls_idx);
        DR_ASSERT(diagnostic != NULL);
        diagnostic->expected = mc;
        diagnostic->resume = resume;
        diagnostic->ordinal =
            __atomic_add_fetch(&diagnostic_redirects, 1, __ATOMIC_RELAXED);
        diagnostic->pending = true;
    }
    dr_redirect_execution(&mc);
    DR_ASSERT_MSG(false, "dr_redirect_execution returned");
}

static void
event_thread_init(void *drcontext)
{
    *budget_slot() = budget_per_refill;
    if (diagnose_redirect_roundtrip) {
        redirect_diagnostic_t *diagnostic =
            dr_thread_alloc(drcontext, sizeof(*diagnostic));
        memset(diagnostic, 0, sizeof(*diagnostic));
        drmgr_set_tls_field(drcontext, diagnostic_tls_idx, diagnostic);
    }
}

static void
event_thread_exit(void *drcontext)
{
    if (diagnose_redirect_roundtrip) {
        redirect_diagnostic_t *diagnostic =
            drmgr_get_tls_field(drcontext, diagnostic_tls_idx);
        if (diagnostic != NULL)
            dr_thread_free(drcontext, diagnostic, sizeof(*diagnostic));
    }
}

static void
insert_charge(void *drcontext, instrlist_t *bb, instr_t *where, uint count)
{
    instr_t *skip = INSTR_CREATE_label(drcontext);
    reg_id_t scratch;
    if (drreg_reserve_register(drcontext, bb, where, NULL, &scratch) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drreg_reserve_register failed");
    dr_insert_read_raw_tls(drcontext, bb, where, tls_seg, tls_offs, scratch);
    /* SUB (immediate) takes 12 bits; it leaves NZCV alone. */
    for (uint left = count; left > 0;) {
        uint step = left < 4095 ? left : 4095;
        instrlist_meta_preinsert(bb, where,
                                 INSTR_CREATE_sub(drcontext, opnd_create_reg(scratch),
                                                  opnd_create_reg(scratch),
                                                  OPND_CREATE_INT(step)));
        left -= step;
    }
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
    /* Hand the application value back before where rather than lazily: an
     * instruction that faults before the next read of the register would
     * otherwise expose the budget to the application's handler.
     */
    if (drreg_get_app_value(drcontext, bb, where, scratch, scratch) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drreg_get_app_value failed");
    if (drreg_unreserve_register(drcontext, bb, where, scratch) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drreg_unreserve_register failed");
    if (diagnose_redirect_roundtrip) {
        /* This call is after drreg has returned the scratch register to the
         * application. It observes the resumed boundary before the app instruction.
         */
        dr_insert_clean_call_ex(drcontext, bb, where, (void *)verify_redirect_roundtrip,
                                DR_CLEANCALL_READS_APP_CONTEXT, 0);
    }
}

static dr_emit_flags_t
event_app2app(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
              bool translating)
{
    for (instr_t *in = instrlist_first_app(bb); in != NULL; in = instr_get_next_app(in)) {
        int opc = instr_get_opcode(in);
        if (opc != OP_wfe && opc != OP_wfi && opc != OP_wfet && opc != OP_wfit)
            continue;
        instr_t *nop = INSTR_CREATE_nop(drcontext);
        instr_set_translation(nop, instr_get_app_pc(in));
        instrlist_replace(bb, in, nop);
        instr_destroy(drcontext, in);
        in = nop;
    }
    return DR_EMIT_DEFAULT;
}

/* Charge point p of a block of n app instrs starts at instr p * n / points. */
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
    plan->points = plan->length < points_per_block ? plan->length : points_per_block;
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
        if (plan->next < plan->points && plan->index == point_start(plan, plan->next)) {
            plan->next++;
            insert_charge(drcontext, bb, inst,
                          point_start(plan, plan->next) - plan->index);
        }
        plan->index++;
    }
    if (drmgr_is_last_instr(drcontext, inst)) {
        DR_ASSERT(plan->index == plan->length && plan->next == plan->points);
        dr_thread_free(drcontext, plan, sizeof(*plan));
    }
    return DR_EMIT_DEFAULT;
}

static void
event_exit(void)
{
    if (diagnose_redirect_roundtrip &&
        __atomic_load_n(&diagnostic_mismatch_reported, __ATOMIC_RELAXED) == 0) {
        dr_fprintf(STDERR,
                   "a64_progress_like: redirect roundtrip matched %llu/%llu contexts\n",
                   (unsigned long long)__atomic_load_n(&diagnostic_matches,
                                                       __ATOMIC_RELAXED),
                   (unsigned long long)__atomic_load_n(&diagnostic_redirects,
                                                       __ATOMIC_RELAXED));
    }
    { /* Always report executed refills: empty instrumentation cannot pass. */
        dr_fprintf(STDERR, "a64_progress_like: %llu refills\n",
                   (unsigned long long)refills);
    }
    if (!dr_raw_tls_cfree(tls_offs, 1))
        DR_ASSERT_MSG(false, "dr_raw_tls_cfree failed");
    drreg_exit();
    drmgr_exit();
}

/* Like atol for decimal client arguments, including zero when no digits match.
 * Use the public standalone parser: this client is built without libc.
 */
static long
parse_long(const char *text)
{
    long value = 0;
    dr_sscanf(text, "%ld", &value);
    return value;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    long budget = 1000, points = 1;
    int positional = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--instructions-per-progress-call") == 0 && i + 1 < argc)
            budget = parse_long(argv[++i]);
        else if (strcmp(argv[i], "--progress-points-per-block") == 0 && i + 1 < argc)
            points = parse_long(argv[++i]);
        else if (strcmp(argv[i], "--diagnose-first-redirect") == 0)
            diagnose_redirect_roundtrip = true;
        else if (argv[i][0] != '-' && positional < 2) {
            if (positional++ == 0)
                budget = parse_long(argv[i]);
            else
                points = parse_long(argv[i]);
        } else {
            dr_fprintf(STDERR, "a64_progress_like: unknown option %s\n", argv[i]);
            dr_abort();
        }
    }
    if (budget <= 0 || budget > UINT_MAX || points <= 0 || points > UINT_MAX) {
        dr_fprintf(STDERR, "a64_progress_like: budget and points must be positive\n");
        dr_abort();
    }
    budget_per_refill = (ptr_int_t)budget;
    points_per_block = (uint)points;
    /* Always save the app value: a register dead on the straight-line path
     * can still be read on a fault path.
     */
    drreg_options_t ops = { sizeof(ops), 3, true };
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drmgr/drreg init failed");
    if (diagnose_redirect_roundtrip) {
        diagnostic_tls_idx = drmgr_register_tls_field();
        if (diagnostic_tls_idx == -1)
            DR_ASSERT_MSG(false, "drmgr_register_tls_field failed");
    }
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, 1, 0))
        DR_ASSERT_MSG(false, "dr_raw_tls_calloc failed");
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_app2app_event(event_app2app, NULL) ||
        !drmgr_register_bb_instrumentation_event(event_analysis, event_insertion, NULL))
        DR_ASSERT_MSG(false, "event registration failed");
    dr_register_exit_event(event_exit);
}

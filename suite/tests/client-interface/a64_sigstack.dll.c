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
 * Checks the signal stack that DR translates a fault in the code cache on.
 * DR rebuilds the faulting block there, calling this client's instrumentation
 * again, under frames that hold whole AArch64 contexts.  This client charges
 * each block the way an instruction-budget client does (a drreg scratch
 * register, raw TLS, a TBZ over a clean call with immediate arguments), and
 * when it instruments a block for a translation on the signal stack it
 * measures how much of that stack is left below it.  A failed translation
 * rebuilds the block again from deeper (recreate_app_pc()), and a kernel frame
 * with SVE or SME state is larger than a plain one.  With the 32KB stack we had
 * for clients, 8KB was left here for this app, and in a JVM, where a failed
 * translation of a fault in stale JIT code rebuilt the block again, the stack
 * overflowed.
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include <signal.h>

/* What must be left when instrumenting a block for a translation. */
#define MIN_HEADROOM (16 * 1024)

static reg_id_t tls_seg;
static uint tls_offs;
static void *count_lock;
static uint translations_on_sigstack;
static size_t min_headroom = (size_t)-1;

static void
refill(app_pc resume, ptr_int_t charged)
{
    /* The budget never runs out: the call is only there for its insertion. */
    DR_ASSERT_MSG(false, "budget ran out");
}

static void
event_thread_init(void *drcontext)
{
    *(ptr_int_t *)((byte *)dr_get_dr_segment_base(tls_seg) + tls_offs) = (ptr_int_t)1
        << 62;
}

/* Records the signal stack left below us, if we are on DR's signal stack. */
static void
measure_headroom(void)
{
    stack_t ss;
    byte *sp = (byte *)&ss;
    if (sigaltstack(NULL, &ss) != 0 || ss.ss_sp == NULL || sp < (byte *)ss.ss_sp ||
        sp >= (byte *)ss.ss_sp + ss.ss_size)
        return;
    dr_mutex_lock(count_lock);
    translations_on_sigstack++;
    if ((size_t)(sp - (byte *)ss.ss_sp) < min_headroom)
        min_headroom = (size_t)(sp - (byte *)ss.ss_sp);
    dr_mutex_unlock(count_lock);
}

static void
insert_charge(void *drcontext, instrlist_t *bb, instr_t *where)
{
    instr_t *skip = INSTR_CREATE_label(drcontext);
    reg_id_t scratch;
    if (drreg_reserve_register(drcontext, bb, where, NULL, &scratch) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drreg_reserve_register failed");
    dr_insert_read_raw_tls(drcontext, bb, where, tls_seg, tls_offs, scratch);
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_sub(drcontext, opnd_create_reg(scratch),
                                              opnd_create_reg(scratch),
                                              OPND_CREATE_INT(1)));
    dr_insert_write_raw_tls(drcontext, bb, where, tls_seg, tls_offs, scratch);
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_tbz(drcontext, opnd_create_instr(skip),
                                              opnd_create_reg(scratch),
                                              OPND_CREATE_INT(63)));
    dr_insert_clean_call_ex(drcontext, bb, where, (void *)refill,
                            DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_MULTIPATH, 2,
                            OPND_CREATE_INTPTR((ptr_int_t)instr_get_app_pc(where)),
                            OPND_CREATE_INTPTR(1));
    instrlist_meta_preinsert(bb, where, skip);
    if (drreg_get_app_value(drcontext, bb, where, scratch, scratch) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drreg_get_app_value failed");
    if (drreg_unreserve_register(drcontext, bb, where, scratch) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drreg_unreserve_register failed");
}

static dr_emit_flags_t
event_insertion(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                bool for_trace, bool translating, void *user_data)
{
    if (instr_is_app(inst) && inst == instrlist_first_app(bb)) {
        if (translating)
            measure_headroom();
        insert_charge(drcontext, bb, inst);
    }
    return DR_EMIT_DEFAULT;
}

static void
event_exit(void)
{
    dr_fprintf(STDERR, "translated on the signal stack: %s\n",
               translations_on_sigstack > 0 ? "yes" : "no");
    if (min_headroom >= MIN_HEADROOM)
        dr_fprintf(STDERR, "signal stack headroom: ok\n");
    else {
        dr_fprintf(STDERR, "signal stack headroom: %zu bytes, below %d\n", min_headroom,
                   MIN_HEADROOM);
    }
    dr_mutex_destroy(count_lock);
    if (!dr_raw_tls_cfree(tls_offs, 1))
        DR_ASSERT_MSG(false, "dr_raw_tls_cfree failed");
    drreg_exit();
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t ops = { sizeof(ops), 3, true };
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS)
        DR_ASSERT_MSG(false, "drmgr/drreg init failed");
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, 1, 0))
        DR_ASSERT_MSG(false, "dr_raw_tls_calloc failed");
    count_lock = dr_mutex_create();
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_bb_instrumentation_event(NULL, event_insertion, NULL))
        DR_ASSERT_MSG(false, "event registration failed");
    /* This tree's drmgr has no drmgr_register_exit_event(). */
    dr_register_exit_event(event_exit);
}

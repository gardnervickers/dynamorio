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
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* See syscall_flush_signal.c. */

#include "dr_api.h"
#include "client_tools.h"

/* Must match the app. */
enum { FLUSH_SYNCHALL, FLUSH_UNLINK };

static app_pc pc_flush_marker, pc_blocking_svc;
/* Only the second thread runs the marker, one call at a time. */
static bool flushed;

/* Flushes the block that holds the blocked read, from another thread. */
static void
callee_flush(reg_t kind)
{
    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    if (flushed) {
        flushed = false;
        return;
    }
    /* The block is its first two instructions: the number and the system call. */
    if (kind == FLUSH_SYNCHALL)
        DR_ASSERT(dr_flush_region(pc_blocking_svc, 8));
    else
        DR_ASSERT(dr_unlink_flush_region(pc_blocking_svc, 8));
    /* The flush may have taken this clean call's own fragment with it: run the
     * marker's block again, which then returns from this callee.
     */
    flushed = true;
    DR_ASSERT(dr_get_mcontext(dr_get_current_drcontext(), &mc));
    mc.pc = pc_flush_marker;
    dr_redirect_execution(&mc);
    DR_ASSERT(false);
}

static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    app_pc pc = dr_fragment_app_pc(tag);
    if (pc == pc_flush_marker) {
        dr_insert_clean_call(drcontext, bb, instrlist_first(bb), (void *)callee_flush,
                             false, 1, opnd_create_reg(DR_REG_X0));
    } else if (pc == pc_blocking_svc) {
        /* The test is about a system call that stays in the cache. */
        instr_t *last = instrlist_last_app(bb);
        if (last == NULL || !instr_is_syscall(last))
            dr_fprintf(STDERR, "the read's block does not end in its system call\n");
    }
    return DR_EMIT_DEFAULT;
}

DR_EXPORT void
dr_init(client_id_t id)
{
    module_data_t *app = dr_get_main_module();
    DR_ASSERT(app != NULL);
    pc_flush_marker = (app_pc)dr_get_proc_address(app->handle, "flush_marker");
    pc_blocking_svc = (app_pc)dr_get_proc_address(app->handle, "blocking_svc");
    DR_ASSERT(pc_flush_marker != NULL && pc_blocking_svc != NULL);
    dr_free_module_data(app);
    dr_register_bb_event(bb_event);
}

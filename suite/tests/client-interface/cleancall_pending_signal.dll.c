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

/* See cleancall_pending_signal.c. */

#include "dr_api.h"
#include "client_tools.h"
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* The probes' loops are linked well before this many visits. */
#define TRIGGER_VISIT 4096

static app_pc probe_out_of_line_pc, probe_inline_pc;
static process_id_t app_pid;
static volatile thread_id_t app_tid;
static int out_of_line_visits;
static volatile int inline_visits, inline_spinning, inline_release;
static volatile int in_callee;

static void
send_usr1(void)
{
    DR_ASSERT(syscall(SYS_tgkill, app_pid, app_tid, SIGUSR1) == 0);
}

static void
callee_out_of_line(void)
{
    /* For the client thread too: the inline round runs after this one. */
    app_tid = dr_get_thread_id(dr_get_current_drcontext());
    if (++out_of_line_visits != TRIGGER_VISIT)
        return;
    in_callee = 1;
    send_usr1();
    in_callee = 0;
}

/* A leaf with few registers, so that it is neither inlined (it has a loop) nor given
 * an out-of-line context switch.
 */
static void
callee_inline(void)
{
    if (++inline_visits != TRIGGER_VISIT)
        return;
    in_callee = 1;
    inline_spinning = 1;
    while (inline_release == 0) {
        /* Spin until the client thread has sent the signal. */
    }
    in_callee = 0;
}

/* Whether SIGUSR1 is still pending for the app thread in the kernel, that is,
 * not yet delivered to DR's handler: from the SigPnd line of its status file
 * (under the app's pid: a client thread is not in its thread group).
 */
static bool
usr1_pending_in_kernel(void)
{
    char path[64], buf[2048];
    dr_snprintf(path, BUFFER_SIZE_ELEMENTS(path), "/proc/%d/task/%d/status", (int)app_pid,
                (int)app_tid);
    NULL_TERMINATE_BUFFER(path);
    file_t f = dr_open_file(path, DR_FILE_READ);
    DR_ASSERT(f != INVALID_FILE);
    ssize_t len = dr_read_file(f, buf, sizeof(buf) - 1);
    dr_close_file(f);
    DR_ASSERT(len > 0);
    buf[len] = '\0';
    const char *line = strstr(buf, "SigPnd:");
    DR_ASSERT(line != NULL);
    uint64 mask = 0;
    DR_ASSERT(dr_sscanf(line, "SigPnd: %llx", &mask) == 1);
    return (mask & (1ULL << (SIGUSR1 - 1))) != 0;
}

static void
sender_thread(void *arg)
{
    int i;
    for (i = 0; i < 60000 && inline_spinning == 0; i++)
        dr_sleep(1);
    DR_ASSERT(inline_spinning != 0);
    send_usr1();
    /* Release the callee only once the kernel has delivered the signal, which it
     * then did while the callee spun: otherwise the round would not exercise the
     * check after the callee.
     */
    for (i = 0; i < 60000 && usr1_pending_in_kernel(); i++)
        dr_sleep(1);
    if (usr1_pending_in_kernel())
        dr_fprintf(STDERR, "SIGUSR1 not delivered while the inline callee spun\n");
    inline_release = 1;
}

static dr_signal_action_t
signal_event(void *drcontext, dr_siginfo_t *info)
{
    if (info->sig == SIGUSR1 && in_callee != 0)
        dr_fprintf(STDERR, "SIGUSR1 delivered inside the callee\n");
    return DR_SIGNAL_DELIVER;
}

/* Inserts a clean call to callee before the block's first instruction and, on
 * AArch64, checks that it is the kind of call site the round tests.  An
 * out-of-line context switch has three calls, BL or BLR: clean_call_save, the
 * callee and clean_call_restore, which checks for a pending signal.  An inline
 * one has two: the callee, and its own check's call to clean_call_pending_signal.
 */
static void
insert_call(void *drcontext, instrlist_t *bb, void *callee, bool out_of_line)
{
    instr_t *first = instrlist_first(bb);
    instr_t *mark = INSTR_CREATE_label(drcontext);
    instrlist_meta_preinsert(bb, first, mark);
    dr_insert_clean_call(drcontext, bb, first, callee, false, 0);
#ifdef AARCH64
    int blrs = 0;
    for (instr_t *in = instr_get_next(mark); in != first; in = instr_get_next(in)) {
        if (instr_get_opcode(in) == OP_blr || instr_get_opcode(in) == OP_bl)
            blrs++;
    }
    if (blrs != (out_of_line ? 3 : 2)) {
        dr_fprintf(STDERR, "%s callee: %d calls, not the expected kind of call site\n",
                   out_of_line ? "out-of-line" : "inline", blrs);
    }
#endif
}

static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    app_pc pc = dr_fragment_app_pc(tag);
    if (pc == probe_out_of_line_pc)
        insert_call(drcontext, bb, (void *)callee_out_of_line, true);
    else if (pc == probe_inline_pc)
        insert_call(drcontext, bb, (void *)callee_inline, false);
    return DR_EMIT_DEFAULT;
}

DR_EXPORT void
dr_init(client_id_t id)
{
    module_data_t *app = dr_get_main_module();
    DR_ASSERT(app != NULL);
    probe_out_of_line_pc = (app_pc)dr_get_proc_address(app->handle, "probe_out_of_line");
    probe_inline_pc = (app_pc)dr_get_proc_address(app->handle, "probe_inline");
    DR_ASSERT(probe_out_of_line_pc != NULL && probe_inline_pc != NULL);
    dr_free_module_data(app);
    app_pid = dr_get_process_id();
    dr_register_signal_event(signal_event);
    dr_register_bb_event(bb_event);
    DR_ASSERT(dr_create_client_thread(sender_thread, NULL));
}

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

/* See redirect_entry.c. */

#include "dr_api.h"
#include "client_tools.h"
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Must match the app. */
enum {
    MODE_NONE,
    MODE_STATE,
    MODE_FRAGMENT_STATE,
    MODE_NO_FRAGMENT,
    MODE_PENDING_SIGNAL,
    MODE_KERNEL_XFER,
    MODE_SIGNAL_ROUTINE,
    MODE_SIGNAL_FRAGMENT,
    MODE_SIGNAL_BLOCKING,
    MODE_PENDING_FLUSH,
    MODE_SYNCH,
    MODE_REPORT,
};

/* Bounds each wait for the other thread, which yields. */
#define MAX_YIELDS 100000000

/* Raw TLS words.  A taken-over block spills SCRATCH and tests MODE. */
enum { SPILL, MODE, ENTRY, ROUTINE, TLS_WORDS };
#define SCRATCH DR_REG_X9

static reg_id_t tls_segment;
static uint tls_offset;
static byte *routine;
static process_id_t app_pid;
static app_pc pc_arm, pc_probe_state, pc_probe_from, pc_probe_plain, pc_probe_spin,
    pc_spin, pc_spin_from, pc_probe_read, pc_never_run, pc_flush_target, pc_flush_marker;
static volatile int in_callee;
static volatile int waiting_for_flusher, flusher_started, flush_done;
static int xfer_registered, xfer_redirects, synch_refused;

static uint
slot(uint word)
{
    return tls_offset + word * sizeof(reg_t);
}

static reg_t *
tls_word(uint word)
{
    return (reg_t *)((byte *)dr_get_dr_segment_base(tls_segment) + slot(word));
}

static const char *
mode_name(reg_t mode)
{
    switch (mode) {
    case MODE_STATE: return "state";
    case MODE_FRAGMENT_STATE: return "fragment to fragment";
    case MODE_NO_FRAGMENT: return "no fragment";
    case MODE_PENDING_SIGNAL: return "pending signal";
    case MODE_KERNEL_XFER: return "kernel transfer event";
    case MODE_SIGNAL_ROUTINE: return "signal after the entry, routine";
    case MODE_SIGNAL_FRAGMENT: return "signal after the entry, fragment to fragment";
    case MODE_SIGNAL_BLOCKING: return "signal after the entry, blocking destination";
    case MODE_PENDING_FLUSH: return "pending flush";
    case MODE_SYNCH: return "synchronizing thread";
    default: return "unknown";
    }
}

/* Queues a SIGUSR1 for this thread: it arrives during the call, in code that DR
 * cannot interrupt.
 */
static void
send_usr1(void *drcontext)
{
    in_callee = 1;
    DR_ASSERT(syscall(SYS_tgkill, app_pid, dr_get_thread_id(drcontext), SIGUSR1) == 0);
    in_callee = 0;
}

static dr_signal_action_t
signal_event(void *drcontext, dr_siginfo_t *info)
{
    if (info->sig == SIGUSR1 && in_callee != 0)
        dr_fprintf(STDERR, "SIGUSR1 delivered inside the callee\n");
    return DR_SIGNAL_DELIVER;
}

static void
kernel_xfer_event(void *drcontext, const dr_kernel_xfer_info_t *info)
{
    if (info->type == DR_XFER_CLIENT_REDIRECT)
        xfer_redirects++;
}

static void
redirect_through_dispatcher(void *drcontext, app_pc pc)
{
    dr_mcontext_t mc = { sizeof(mc), DR_MC_ALL };
    DR_ASSERT(dr_get_mcontext(drcontext, &mc));
    mc.pc = pc;
    dr_redirect_execution(&mc);
    DR_ASSERT(false);
}

/* Ends the clean call at pc's block: directly if DR returns an entry, which the
 * call site then jumps to.  after_entry runs once DR has returned one.
 */
static void
resume_at(void *drcontext, reg_t mode, app_pc pc, bool expect_entry,
          void (*after_entry)(void *))
{
    byte *entry = dr_redirect_entry(drcontext, pc);
    if ((entry != NULL) != expect_entry || expect_entry) {
        dr_fprintf(STDERR, "%s: %s\n", mode_name(mode),
                   entry != NULL ? "direct entry" : "refused");
    }
    if (entry == NULL)
        redirect_through_dispatcher(drcontext, pc);
    if (after_entry != NULL)
        (*after_entry)(drcontext);
    *tls_word(ENTRY) = (reg_t)entry;
}

/* Reports that DR refused an entry for pc, and resumes there the long way. */
static void
refused_at(void *drcontext, reg_t mode, app_pc pc)
{
    byte *entry = dr_redirect_entry(drcontext, pc);
    dr_fprintf(STDERR, "%s: %s\n", mode_name(mode),
               entry == NULL ? "refused" : "direct entry");
    redirect_through_dispatcher(drcontext, pc);
}

/* The callee of the routine that taken-over probe blocks branch to. */
static void
callee_routine(void)
{
    void *drcontext = dr_get_current_drcontext();
    reg_t mode = *tls_word(MODE);
    int i;
    *tls_word(MODE) = MODE_NONE;
    switch (mode) {
    case MODE_STATE: resume_at(drcontext, mode, pc_probe_state, true, NULL); break;
    case MODE_NO_FRAGMENT:
        dr_fprintf(STDERR, "%s: %s\n", mode_name(mode),
                   dr_redirect_entry(drcontext, pc_never_run) == NULL ? "refused"
                                                                      : "direct entry");
        redirect_through_dispatcher(drcontext, pc_probe_plain);
        break;
    case MODE_PENDING_SIGNAL:
        send_usr1(drcontext);
        refused_at(drcontext, mode, pc_probe_plain);
        break;
    case MODE_KERNEL_XFER:
        /* A registered event is no reason to refuse (drmgr always registers
         * one), and the direct entry does not raise it.
         */
        dr_register_kernel_xfer_event(kernel_xfer_event);
        xfer_registered = 1;
        resume_at(drcontext, mode, pc_probe_plain, true, NULL);
        break;
    case MODE_PENDING_FLUSH:
        DR_ASSERT(dr_delay_flush_region(pc_flush_target, 4, 0, NULL));
        refused_at(drcontext, mode, pc_probe_plain);
        break;
    case MODE_SYNCH:
        /* The other thread's flush needs this one at a safe spot, which a clean
         * call is not: it can only ask, and until the request arrives DR may
         * still return an entry.
         */
        waiting_for_flusher = 1;
        for (i = 0; flusher_started == 0 && i < MAX_YIELDS; i++)
            dr_thread_yield();
        for (i = 0; i < MAX_YIELDS; i++) {
            if (dr_redirect_entry(drcontext, pc_probe_plain) == NULL) {
                synch_refused = 1;
                break;
            }
            dr_thread_yield();
        }
        dr_fprintf(STDERR, "%s: %s\n", mode_name(mode),
                   synch_refused ? "refused" : "direct entry");
        redirect_through_dispatcher(drcontext, pc_probe_plain);
        break;
    case MODE_SIGNAL_ROUTINE:
        resume_at(drcontext, mode, pc_probe_spin, true, send_usr1);
        break;
    case MODE_SIGNAL_BLOCKING:
        resume_at(drcontext, mode, pc_probe_read, true, send_usr1);
        break;
    default: DR_ASSERT(false);
    }
}

/* The callee of a clean call inside a fragment that resumes at another one. */
static void
callee_fragment(void)
{
    void *drcontext = dr_get_current_drcontext();
    reg_t mode = *tls_word(MODE);
    *tls_word(MODE) = MODE_NONE;
    if (mode == MODE_FRAGMENT_STATE)
        resume_at(drcontext, mode, pc_probe_state, true, NULL);
    else if (mode == MODE_SIGNAL_FRAGMENT)
        resume_at(drcontext, mode, pc_spin, true, send_usr1);
    else
        DR_ASSERT(false);
}

static void
callee_arm(reg_t mode)
{
    if (mode != MODE_REPORT) {
        *tls_word(MODE) = mode;
        return;
    }
    if (xfer_registered) {
        DR_ASSERT(dr_unregister_kernel_xfer_event(kernel_xfer_event));
        xfer_registered = 0;
        dr_fprintf(STDERR, "%s: %s\n", mode_name(MODE_KERNEL_XFER),
                   xfer_redirects == 0 ? "not raised" : "raised");
    } else {
        dr_fprintf(STDERR, "%s: %s\n", mode_name(MODE_SYNCH),
                   flush_done ? "flush completed" : "flush not completed");
    }
}

/* Runs on the second thread. */
static void
callee_flush(void)
{
    void *drcontext = dr_get_current_drcontext();
    int i;
    if (flush_done)
        return;
    for (i = 0; waiting_for_flusher == 0 && i < MAX_YIELDS; i++)
        dr_thread_yield();
    flusher_started = 1;
    DR_ASSERT(dr_flush_region(pc_flush_target, 4));
    flush_done = 1;
    /* The flush may have taken this clean call's own fragment with it: run the
     * marker's block again, which now returns from this callee.
     */
    redirect_through_dispatcher(drcontext, pc_flush_marker);
}

/* Emits the shared routine once, outside the code cache: restore SCRATCH, call
 * callee_routine, and jump to the entry it stored.
 */
static void
emit_routine(void *drcontext)
{
    instrlist_t *ilist = instrlist_create(drcontext);
    instr_t *end = INSTR_CREATE_label(drcontext);
    size_t size = dr_page_size();
    byte *last, *line;
    instrlist_meta_append(ilist, end);
    dr_insert_read_raw_tls(drcontext, ilist, end, tls_segment, slot(SPILL), SCRATCH);
    dr_insert_clean_call_ex(
        drcontext, ilist, end, (void *)callee_routine,
        DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_ALWAYS_OUT_OF_LINE, 0);
    dr_insert_redirect_entry_jump(drcontext, ilist, end,
                                  dr_raw_tls_opnd(drcontext, tls_segment, slot(ENTRY)));
    routine =
        dr_nonheap_alloc(size, DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC);
    DR_ASSERT(routine != NULL);
    last = instrlist_encode(drcontext, ilist, routine, true);
    DR_ASSERT(last != NULL && last <= routine + size);
    instrlist_clear_and_destroy(drcontext, ilist);
    for (line = routine; line < last; line += 4)
        __asm__ __volatile__("dc cvau, %0" : : "r"(line) : "memory");
    __asm__ __volatile__("dsb ish" : : : "memory");
    for (line = routine; line < last; line += 4)
        __asm__ __volatile__("ic ivau, %0" : : "r"(line) : "memory");
    __asm__ __volatile__("dsb ish\n\tisb" : : : "memory");
    DR_ASSERT(dr_memory_protect(routine, size, DR_MEMPROT_READ | DR_MEMPROT_EXEC));
}

static void
thread_init(void *drcontext)
{
    if (routine == NULL)
        emit_routine(drcontext);
    *tls_word(MODE) = MODE_NONE;
    *tls_word(ROUTINE) = (reg_t)routine;
}

/* Takes over the block: when the thread's MODE word is set, it leaves for the
 * routine, or (in_fragment) makes the clean call and the jump itself.
 */
static void
take_over(void *drcontext, instrlist_t *bb, bool in_fragment)
{
    instr_t *first = instrlist_first(bb);
    instr_t *skip = INSTR_CREATE_label(drcontext);
    dr_insert_write_raw_tls(drcontext, bb, first, tls_segment, slot(SPILL), SCRATCH);
    dr_insert_read_raw_tls(drcontext, bb, first, tls_segment, slot(MODE), SCRATCH);
    instrlist_meta_preinsert(
        bb, first,
        INSTR_CREATE_cbz(drcontext, opnd_create_instr(skip), opnd_create_reg(SCRATCH)));
    if (in_fragment) {
        dr_insert_read_raw_tls(drcontext, bb, first, tls_segment, slot(SPILL), SCRATCH);
        dr_insert_clean_call_ex(drcontext, bb, first, (void *)callee_fragment,
                                DR_CLEANCALL_READS_APP_CONTEXT, 0);
        dr_insert_redirect_entry_jump(
            drcontext, bb, first, dr_raw_tls_opnd(drcontext, tls_segment, slot(ENTRY)));
    } else {
        dr_insert_read_raw_tls(drcontext, bb, first, tls_segment, slot(ROUTINE), SCRATCH);
        instrlist_meta_preinsert(bb, first,
                                 INSTR_CREATE_br(drcontext, opnd_create_reg(SCRATCH)));
    }
    instrlist_meta_preinsert(bb, first, skip);
    dr_insert_read_raw_tls(drcontext, bb, first, tls_segment, slot(SPILL), SCRATCH);
}

static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    app_pc pc = dr_fragment_app_pc(tag);
    if (pc == pc_arm) {
        dr_insert_clean_call(drcontext, bb, instrlist_first(bb), (void *)callee_arm,
                             false, 1, opnd_create_reg(DR_REG_X0));
    } else if (pc == pc_flush_marker) {
        dr_insert_clean_call(drcontext, bb, instrlist_first(bb), (void *)callee_flush,
                             false, 0);
    } else if (pc == pc_probe_state || pc == pc_probe_plain || pc == pc_probe_spin ||
               pc == pc_probe_read)
        take_over(drcontext, bb, false);
    else if (pc == pc_probe_from || pc == pc_spin_from)
        take_over(drcontext, bb, true);
    return DR_EMIT_DEFAULT;
}

static void
exit_event(void)
{
    if (routine != NULL)
        dr_nonheap_free(routine, dr_page_size());
    DR_ASSERT(dr_raw_tls_cfree(tls_offset, TLS_WORDS));
}

static app_pc
app_symbol(module_data_t *app, const char *name)
{
    app_pc pc = (app_pc)dr_get_proc_address(app->handle, name);
    DR_ASSERT_MSG(pc != NULL, name);
    return pc;
}

DR_EXPORT void
dr_init(client_id_t id)
{
    module_data_t *app = dr_get_main_module();
    DR_ASSERT(app != NULL);
    pc_arm = app_symbol(app, "arm");
    pc_probe_state = app_symbol(app, "probe_state");
    pc_probe_from = app_symbol(app, "probe_from");
    pc_probe_plain = app_symbol(app, "probe_plain");
    pc_probe_spin = app_symbol(app, "probe_spin");
    pc_spin = app_symbol(app, "spin");
    pc_spin_from = app_symbol(app, "spin_from");
    pc_probe_read = app_symbol(app, "probe_read");
    pc_never_run = app_symbol(app, "never_run");
    pc_flush_target = app_symbol(app, "flush_target");
    pc_flush_marker = app_symbol(app, "flush_marker");
    dr_free_module_data(app);
    app_pid = dr_get_process_id();
    DR_ASSERT(dr_raw_tls_calloc(&tls_segment, &tls_offset, TLS_WORDS, 0));
    dr_register_exit_event(exit_event);
    dr_register_thread_init_event(thread_init);
    dr_register_signal_event(signal_event);
    dr_register_bb_event(bb_event);
}

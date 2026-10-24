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

/* Checks that DR counts a module's code as module code, on AArch64 without
 * -hw_cache_consistency, where code outside any module may change unseen: DR keeps a
 * copy of the code of a block from there and does not elide its ctis.  That is so for
 * the executable and the vdso, which DR finds at init, and for a library the app
 * dlopen()s, whose
 * loader first maps the library's whole extent with its text's protection and then
 * maps its data over part of it, leaving a gap between the two (64K max-page-size
 * segments on a 4K-page kernel) that no segment covers.  Elision is what we can see:
 * with -opt_speed, each function's direct branch is elided into its block exactly when
 * DR counts it as module code (the vdso's __kernel_clock_gettime starts with a bl).
 */

#include "dr_api.h"
#include "client_tools.h"
#include <string.h>

typedef struct {
    const char *name;
    app_pc func;
    bool seen;
} func_t;

static func_t funcs[] = { { "a64_module_class_exe", NULL, false },
                          { "a64_module_class_lib", NULL, false },
                          { "__kernel_clock_gettime", NULL, false } };
#define NUM_FUNCS (sizeof(funcs) / sizeof(funcs[0]))

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    for (uint i = 0; i < NUM_FUNCS; i++) {
        app_pc func = (app_pc)dr_get_proc_address(info->handle, funcs[i].name);
        if (func == NULL)
            continue;
        funcs[i].func = func;
        if (i == 1) {
            dr_fprintf(STDERR, "library segments contiguous: %s\n",
                       info->contiguous ? "yes" : "no");
        }
    }
}

static dr_emit_flags_t
event_bb(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    if (translating)
        return DR_EMIT_DEFAULT;
    for (uint i = 0; i < NUM_FUNCS; i++) {
        if (funcs[i].seen || (app_pc)tag != funcs[i].func)
            continue;
        funcs[i].seen = true;
        /* An elided cti leaves the block's app code discontiguous. */
        bool elided = false;
        app_pc next = NULL;
        for (instr_t *instr = instrlist_first_app(bb); instr != NULL;
             instr = instr_get_next_app(instr)) {
            app_pc pc = instr_get_app_pc(instr);
            if (next != NULL && pc != next)
                elided = true;
            next = pc + instr_length(drcontext, instr);
        }
        dr_fprintf(STDERR, "%s: branch %s\n", funcs[i].name,
                   elided ? "elided" : "not elided");
    }
    return DR_EMIT_DEFAULT;
}

static void
event_exit(void)
{
    for (uint i = 0; i < NUM_FUNCS; i++) {
        if (!funcs[i].seen)
            dr_fprintf(STDERR, "%s: block not seen\n", funcs[i].name);
    }
}

DR_EXPORT void
dr_init(client_id_t id)
{
    dr_register_module_load_event(event_module_load);
    dr_register_bb_event(event_bb);
    dr_register_exit_event(event_exit);
}

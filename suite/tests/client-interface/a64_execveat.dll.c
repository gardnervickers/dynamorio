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
 * Counts the blocks the app's main module executes, with a clean call, in the
 * image client.a64_execveat's app fexecve's (SYS_execveat of a close-on-exec
 * memfd).  An image that DR does not follow runs natively, with no client to
 * count its loop: a guest that spins without syscalls then runs uncontrolled.
 * We get no exit event in the image that execs.
 */

#include "dr_api.h"
#include <string.h>

/* Must match a64_execveat.c. */
#define LOOP_ITERS 1000000

static app_pc main_start, main_end;
static bool main_is_memfd;
static uint64 main_bbs;

static void
count_bb(void)
{
    main_bbs++; /* The app is single-threaded. */
}

static dr_emit_flags_t
event_bb(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    app_pc pc = dr_fragment_app_pc(tag);
    if (pc >= main_start && pc < main_end) {
        dr_insert_clean_call(drcontext, bb, instrlist_first_app(bb), (void *)count_bb,
                             false, 0);
    }
    return DR_EMIT_DEFAULT;
}

static void
event_exit(void)
{
    dr_fprintf(STDERR, "client: main module is %sa memfd\n", main_is_memfd ? "" : "not ");
    if (main_bbs >= LOOP_ITERS)
        dr_fprintf(STDERR, "client: counted the loop\n");
    else {
        dr_fprintf(STDERR, "client: counted only " UINT64_FORMAT_STRING " blocks\n",
                   main_bbs);
    }
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    module_data_t *main_mod = dr_get_main_module();
    DR_ASSERT(main_mod != NULL);
    main_start = main_mod->start;
    main_end = main_mod->end;
    main_is_memfd = strstr(main_mod->full_path, "/memfd:a64_execveat") != NULL;
    dr_free_module_data(main_mod);
    dr_register_bb_event(event_bb);
    dr_register_exit_event(event_exit);
}

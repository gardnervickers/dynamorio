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
 * Checks that DR emits an app instruction as it decoded it when the app code
 * changes before the emit, as a JIT's patch may race with our decode, on a CPU
 * where the decoded instruction cannot be encoded for new code.  Copying the new
 * word would put an instruction we never decoded or mangled into the cache.
 *
 * The app (a64_emit_decoded_app) runs GCSPUSHM X0 once.  We tell DR the CPU has no
 * FEAT_GCS, so encoding it fails.  When DR has decoded its block, we make the app
 * code there BR X28, which unmangled would jump through DR's TLS base, and insert a
 * clean call that puts GCSPUSHM back before it runs, so that the app and any
 * translation see the code we decoded.  The emitted instruction must then be
 * GCSPUSHM, which raises SIGILL (no CPU lets an app run it with GCS off), and the
 * signal event checks the word at its cache pc.
 */

#include "dr_api.h"
#include <signal.h>

#define GCSPUSHM_X0 0xd50b7700
#define BR_X28 0xd61f0380

/* dr_proc.h declares this only for builds with BUILD_TESTS, which the tests are. */
void
proc_set_feature(feature_bit_t f, bool enable);

static app_pc gcs_pc;
static int changed, sigills, emitted_decoded;

/* Writes through /proc/self/mem, which needs no write permission for the code and
 * leaves alone any protection DR keeps on it.
 */
static bool
write_app_word(app_pc pc, uint word)
{
    file_t mem = dr_open_file("/proc/self/mem", DR_FILE_WRITE_ONLY);
    if (mem == INVALID_FILE)
        return false;
    bool ok = dr_file_seek(mem, (int64)(ptr_uint_t)pc, DR_SEEK_SET) &&
        dr_write_file(mem, &word, sizeof(word)) == sizeof(word);
    dr_close_file(mem);
    return ok;
}

static void
restore_word(app_pc pc)
{
    if (!write_app_word(pc, GCSPUSHM_X0))
        dr_fprintf(STDERR, "failed to restore the app word\n");
}

static dr_emit_flags_t
event_bb(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    for (instr_t *instr = instrlist_first_app(bb); instr != NULL;
         instr = instr_get_next_app(instr)) {
        if (instr_get_opcode(instr) != OP_gcspushm)
            continue;
        app_pc pc = instr_get_app_pc(instr);
        /* Every time, translating or not, so that translation sees the same code. */
        dr_insert_clean_call(drcontext, bb, instr, (void *)restore_word, false, 1,
                             OPND_CREATE_INTPTR(pc));
        if (translating || changed > 0 || pc != gcs_pc)
            continue;
        if (!write_app_word(pc, BR_X28)) {
            dr_fprintf(STDERR, "failed to change the app word\n");
            continue;
        }
        changed++;
    }
    return DR_EMIT_DEFAULT;
}

static dr_signal_action_t
event_signal(void *drcontext, dr_siginfo_t *info)
{
    if (info->sig != SIGILL)
        return DR_SIGNAL_DELIVER;
    sigills++;
    if (info->raw_mcontext_valid && info->mcontext->pc == gcs_pc &&
        *(uint *)info->raw_mcontext->pc == GCSPUSHM_X0)
        emitted_decoded++;
    return DR_SIGNAL_DELIVER;
}

static void
event_exit(void)
{
    if (changed == 1 && sigills == 1 && emitted_decoded == 1)
        dr_fprintf(STDERR, "emitted the decoded instr\n");
    else {
        dr_fprintf(STDERR, "changed %d, SIGILLs %d, emitted as decoded %d\n", changed,
                   sigills, emitted_decoded);
    }
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    proc_set_feature(FEATURE_GCS, false);
    /* Find the app's GCSPUSHM. */
    module_data_t *exe = dr_get_main_module();
    for (app_pc pc = exe->start; pc + sizeof(uint) <= exe->end; pc += sizeof(uint)) {
        uint word;
        if (dr_safe_read(pc, sizeof(word), &word, NULL) && word == GCSPUSHM_X0) {
            gcs_pc = pc;
            break;
        }
    }
    dr_free_module_data(exe);
    if (gcs_pc == NULL)
        dr_fprintf(STDERR, "failed to find GCSPUSHM\n");
    dr_register_bb_event(event_bb);
    dr_register_signal_event(event_signal);
    dr_register_exit_event(event_exit);
}

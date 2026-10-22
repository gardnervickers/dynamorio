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
 * Checks that each FEAT_MOPS main and epilogue instruction in the code cache
 * follows its prologue (and main) instruction, where the kernel rewinds the pc
 * to on a mismatched-option exception, although this client puts a nop before
 * every app instruction, and the app (allasm_aarch64_mops) uses the stolen
 * register in one copy.  DR adds copies for that (mangle_mops_sequences()).
 *
 * The test machine need not have FEAT_MOPS: we tell DR it has it, so that DR
 * adds the copies, and the app skips each instruction's SIGILL.  The signal
 * event gets each one's cache pc, from where we check every main and epilogue
 * instruction to the end of the block.  The first block holds all four copies
 * and sets, with our nops in between; after each skip DR builds a block that
 * starts with the next instruction, so a main or epilogue instruction starts a
 * block too.
 */

#include "dr_api.h"
#include <signal.h>
#include <string.h>

/* dr_proc.h declares this only for builds with BUILD_TESTS, which the tests are. */
void
proc_set_feature(feature_bit_t f, bool enable);

#define MAX_SCAN 512

static bool native_mops;
static int sigills, checked, bad;

static dr_emit_flags_t
event_bb(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    for (instr_t *instr = instrlist_first_app(bb); instr != NULL;
         instr = instr_get_next_app(instr))
        instrlist_meta_preinsert(bb, instr, XINST_CREATE_nop(drcontext));
    return DR_EMIT_DEFAULT;
}

/* Returns 0, 1 or 2 for a MOPS prologue, main or epilogue opcode, else -1. */
static int
mops_stage(int opcode)
{
    switch (opcode) {
    case OP_cpyfp:
    case OP_cpyp:
    case OP_setp: return 0;
    case OP_cpyfm:
    case OP_cpym:
    case OP_setm: return 1;
    case OP_cpyfe:
    case OP_cpye:
    case OP_sete: return 2;
    }
    return -1;
}

/* Whether the instr at pc is a MOPS instr of the given stage, of the same kind of
 * copy or set as ref and with the same operands.
 */
static bool
is_stage_of(void *drcontext, byte *pc, int stage, instr_t *ref)
{
    instr_t instr;
    instr_init(drcontext, &instr);
    bool ok = decode(drcontext, pc, &instr) != NULL &&
        mops_stage(instr_get_opcode(&instr)) == stage &&
        instr_num_srcs(&instr) == instr_num_srcs(ref) &&
        instr_num_dsts(&instr) == instr_num_dsts(ref);
    for (int i = 0; ok && i < instr_num_srcs(ref); i++)
        ok = opnd_same(instr_get_src(&instr, i), instr_get_src(ref, i));
    for (int i = 0; ok && i < instr_num_dsts(ref); i++)
        ok = opnd_same(instr_get_dst(&instr, i), instr_get_dst(ref, i));
    /* The kind: SET*, CPY* or CPYF*. */
    if (ok) {
        int opc = instr_get_opcode(&instr), ref_opc = instr_get_opcode(ref);
        bool set = opc == OP_setp || opc == OP_setm || opc == OP_sete;
        bool ref_set = ref_opc == OP_setp || ref_opc == OP_setm || ref_opc == OP_sete;
        bool cpyf = opc == OP_cpyfp || opc == OP_cpyfm || opc == OP_cpyfe;
        bool ref_cpyf = ref_opc == OP_cpyfp || ref_opc == OP_cpyfm || ref_opc == OP_cpyfe;
        ok = set == ref_set && cpyf == ref_cpyf;
    }
    instr_free(drcontext, &instr);
    return ok;
}

/* Checks the code before the main or epilogue instr ref at cache pc. */
static void
check_before(void *drcontext, byte *pc, instr_t *ref)
{
    int stage = mops_stage(instr_get_opcode(ref));
    bool ok = is_stage_of(drcontext, pc - 4, stage - 1, ref) &&
        (stage == 1 || is_stage_of(drcontext, pc - 8, 0, ref));
    checked++;
    if (!ok) {
        bad++;
        dr_fprintf(STDERR, "MOPS stage %d at " PFX " does not follow its prologue\n",
                   stage, pc);
    }
}

static dr_signal_action_t
event_signal(void *drcontext, dr_siginfo_t *info)
{
    if (info->sig != SIGILL || native_mops || !info->raw_mcontext_valid)
        return DR_SIGNAL_DELIVER;
    sigills++;
    /* Check every main and epilogue instr, the app's and DR's copies, from the
     * faulting one to the end of the block, which is the next syscall.
     */
    byte *pc = info->raw_mcontext->pc;
    for (int i = 0; i < MAX_SCAN; i++, pc += 4) {
        instr_t instr;
        instr_init(drcontext, &instr);
        if (decode(drcontext, pc, &instr) == NULL || instr_get_opcode(&instr) == OP_svc) {
            instr_free(drcontext, &instr);
            break;
        }
        if (mops_stage(instr_get_opcode(&instr)) > 0)
            check_before(drcontext, pc, &instr);
        instr_free(drcontext, &instr);
    }
    return DR_SIGNAL_DELIVER;
}

static void
event_exit(void)
{
    /* The app's 12 MOPS instrs each raise SIGILL. */
    if (native_mops)
        dr_fprintf(STDERR, "FEAT_MOPS present: no layout to check\n");
    else if (bad == 0 && sigills == 12 && checked > 0)
        dr_fprintf(STDERR, "MOPS layout ok\n");
    else {
        dr_fprintf(STDERR, "MOPS layout: %d SIGILLs, %d of %d checks failed\n", sigills,
                   bad, checked);
    }
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    native_mops = proc_has_feature(FEATURE_MOPS);
    /* -no_force_mops leaves DR without FEAT_MOPS, so that it adds no copies and
     * the checks fail: a check of the checks.
     */
    if (argc < 2 || strcmp(argv[1], "-no_force_mops") != 0)
        proc_set_feature(FEATURE_MOPS, true);
    dr_register_bb_event(event_bb);
    dr_register_signal_event(event_signal);
    dr_register_exit_event(event_exit);
}

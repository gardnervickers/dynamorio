/* **********************************************************
 * Copyright (c) 2020-2021 Google, Inc. All rights reserved.
 * Copyright (c) 2018 Arm Limited. All rights reserved.
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
 * * Neither the name of ARM Limited nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL ARM LIMITED OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* This file contains tests to ensure we fail to encode invalid IR instructions. */

/* Define DR_FAST_IR to verify that everything compiles when we call the inline
 * versions of these routines.
 */
#ifndef STANDALONE_DECODER
#    define DR_FAST_IR 1
#endif

/* Uses the DR API, using DR as a standalone library, rather than
 * being a client library working with DR on a target program.
 */

#include "configure.h"
#include "dr_api.h"
#include "tools.h"

#ifdef STANDALONE_DECODER
#    define ASSERT(x)                                                                 \
        ((void)((!(x)) ? (fprintf(stderr, "ASSERT FAILURE (standalone): %s:%d: %s\n", \
                                  __FILE__, __LINE__, #x),                            \
                          abort(), 0)                                                 \
                       : 0))
#else
#    define ASSERT(x)                                                                \
        ((void)((!(x)) ? (dr_fprintf(STDERR, "ASSERT FAILURE (client): %s:%d: %s\n", \
                                     __FILE__, __LINE__, #x),                        \
                          dr_abort(), 0)                                             \
                       : 0))
#endif

static void
test_fmov_general(void *dc)
{
    byte *pc;
    instr_t *instr;

    instr = INSTR_CREATE_fmov_general(dc, opnd_create_reg(DR_REG_D10),
                                      opnd_create_reg(DR_REG_W9));
    ASSERT(!instr_is_encoding_possible(instr));
    instr_destroy(dc, instr);

    instr = INSTR_CREATE_fmov_general(dc, opnd_create_reg(DR_REG_S10),
                                      opnd_create_reg(DR_REG_X9));
    ASSERT(!instr_is_encoding_possible(instr));
    instr_destroy(dc, instr);

    instr = INSTR_CREATE_fmov_general(dc, opnd_create_reg(DR_REG_W10),
                                      opnd_create_reg(DR_REG_X9));
    ASSERT(!instr_is_encoding_possible(instr));
    instr_destroy(dc, instr);
}

/* FEAT_MOPS encodings with overlapping registers, or with register number 31 other
 * than as a set's data register, are CONSTRAINED UNPREDICTABLE: they must decode as
 * OP_xx, and the encoder must not produce them.
 */
static void
test_mops_reserved(void *dc)
{
    instr_t *instr;

    enable_all_test_cpu_features();

    static const uint reserved[] = {
        0x19010441, /* cpyfp Rd == Rs (x1) */
        0x19010442, /* cpyfp Rd == Rn (x2) */
        0x19010421, /* cpyfp Rd == Rs == Rn (x1) */
        0x19020443, /* cpyfp Rs == Rn (x2) */
        0x1901045f, /* cpyfp Rd == 31 */
        0x191f0443, /* cpyfp Rs == 31 */
        0x190107e3, /* cpyfp Rn == 31 */
        0x1d410441, /* cpym Rd == Rs (x1) */
        0x19c10441, /* setp Rd == Rs (x1) */
        0x19c20443, /* setp Rn == Rs (x2) */
        0x19c1045f, /* setp Rd == 31 */
        0x19c107e3, /* setp Rn == 31 */
        0x59010443, /* cpyfp with sz == 01 */
    };
    for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
        instr = instr_create(dc);
        decode(dc, (byte *)&reserved[i], instr);
        ASSERT(instr_get_opcode(instr) == OP_xx);
        instr_destroy(dc, instr);
    }

    /* A set's data register may be XZR... */
    static const uint setp_xzr = 0x19df0443; /* setp [x3]!, x2!, xzr */
    instr = instr_create(dc);
    decode(dc, (byte *)&setp_xzr, instr);
    ASSERT(instr_get_opcode(instr) == OP_setp);
    instr_destroy(dc, instr);

    /* ...but no address or size register may be. */
    instr = INSTR_CREATE_cpyfp(dc, opnd_create_reg(DR_REG_X3), opnd_create_reg(DR_REG_X1),
                               opnd_create_reg(DR_REG_XZR));
    ASSERT(!instr_is_encoding_possible(instr));
    instr_destroy(dc, instr);
    instr = INSTR_CREATE_setp(dc, opnd_create_reg(DR_REG_X3), opnd_create_reg(DR_REG_XZR),
                              opnd_create_reg(DR_REG_X1));
    ASSERT(!instr_is_encoding_possible(instr));
    instr_destroy(dc, instr);
}

int
main(int argc, char *argv[])
{
#ifdef STANDALONE_DECODER
    void *dcontext = GLOBAL_DCONTEXT;
#else
    void *dcontext = dr_standalone_init();
#endif

    test_fmov_general(dcontext);
    print("test_fmov_general complete\n");

    test_mops_reserved(dcontext);
    print("test_mops_reserved complete\n");

    print("All tests complete\n");
#ifndef STANDALONE_DECODER
    dr_standalone_exit();
#endif
    return 0;
}

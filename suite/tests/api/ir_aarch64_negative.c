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

/* Reserved SVE/SVE2 encodings must neither be produced by the encoder nor accepted by
 * the decoder.
 */
static void
test_sve_reserved(void *dc)
{
    instr_t *instr;

    /* Otherwise SVE encodings are not possible on hardware without SVE. */
    enable_all_test_cpu_features();

    /* Byte elements with LSL #8 (size:sh == 001) are reserved... */
    instr = INSTR_CREATE_add_sve_shift(
        dc, opnd_create_reg_element_vector(DR_REG_Z0, OPSZ_1),
        opnd_create_immed_uint(1, OPSZ_1), opnd_create_immed_uint(8, OPSZ_1b));
    ASSERT(!instr_is_encoding_possible(instr));
    instr_destroy(dc, instr);
    /* ...but not for larger elements. */
    instr = INSTR_CREATE_add_sve_shift(
        dc, opnd_create_reg_element_vector(DR_REG_Z0, OPSZ_2),
        opnd_create_immed_uint(1, OPSZ_1), opnd_create_immed_uint(8, OPSZ_1b));
    ASSERT(instr_is_encoding_possible(instr));
    instr_destroy(dc, instr);

    /* Scalar+scalar contiguous loads, stores and prefetches reserve Rm == 31 (XZR)... */
    instr = INSTR_CREATE_ld1b_sve_pred(
        dc, opnd_create_reg_element_vector(DR_REG_Z0, OPSZ_1),
        opnd_create_predicate_reg(DR_REG_P0, false),
        opnd_create_base_disp_aarch64(DR_REG_X0, DR_REG_XZR, DR_EXTEND_UXTX, 0, 0, 0,
                                      OPSZ_1));
    ASSERT(!instr_is_encoding_possible(instr));
    instr_destroy(dc, instr);
    /* ...except for the first-fault loads. */
    instr = INSTR_CREATE_ldff1b_sve_pred(
        dc, opnd_create_reg_element_vector(DR_REG_Z0, OPSZ_1),
        opnd_create_predicate_reg(DR_REG_P0, false),
        opnd_create_base_disp_aarch64(DR_REG_X0, DR_REG_XZR, DR_EXTEND_UXTX, 0, 0, 0,
                                      OPSZ_1));
    ASSERT(instr_is_encoding_possible(instr));
    instr_destroy(dc, instr);

    /* SVE ADR (vector) has no negated index or transfer size, and its index is
     * scaled exactly when the shift amount is nonzero.
     */
    const opnd_t adr_ok = opnd_create_vector_base_disp_aarch64(
        DR_REG_Z1, DR_REG_Z2, OPSZ_4, DR_EXTEND_UXTX, true, 0, 0, OPSZ_0, 1);
    const opnd_t adr_bad[] = {
        opnd_create_vector_base_disp_aarch64(DR_REG_Z1, DR_REG_Z2, OPSZ_4, DR_EXTEND_UXTX,
                                             true, 0, DR_OPND_NEGATED, OPSZ_0, 1),
        opnd_create_vector_base_disp_aarch64(DR_REG_Z1, DR_REG_Z2, OPSZ_4, DR_EXTEND_UXTX,
                                             true, 0, 0, OPSZ_4, 1),
        opnd_create_vector_base_disp_aarch64(DR_REG_Z1, DR_REG_Z2, OPSZ_4, DR_EXTEND_UXTX,
                                             true, 0, 0, OPSZ_0, 0),
    };
    instr = INSTR_CREATE_adr_sve(dc, opnd_create_reg_element_vector(DR_REG_Z0, OPSZ_4),
                                 adr_ok);
    ASSERT(instr_is_encoding_possible(instr));
    instr_destroy(dc, instr);
    for (size_t i = 0; i < sizeof(adr_bad) / sizeof(adr_bad[0]); i++) {
        instr = INSTR_CREATE_adr_sve(
            dc, opnd_create_reg_element_vector(DR_REG_Z0, OPSZ_4), adr_bad[i]);
        ASSERT(!instr_is_encoding_possible(instr));
        instr_destroy(dc, instr);
    }

    static const uint reserved[] = {
        0x2520e72c, /* add z12.b, z12.b, #57, lsl #8 */
        0x05102209, /* cpy z9.b, p0/z, #16, lsl #8 */
        0x2538e136, /* dup z22.b, #9, lsl #8 */
        0xa41f4000, /* ld1b {z0.b}, p0/z, [x0, xzr] */
        0xe41f4000, /* st1b {z0.b}, p0, [x0, xzr] */
        0x841fc000, /* prfb pldl1keep, p0, [x0, xzr] */
        0xa43f0000, /* ld1rob {z0.b}, p0/z, [x0, xzr] */
        0x45384000, /* sqxtnb with tsize == 111 */
        0x45806800, /* pmullb with size == 10 */
    };
    for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
        instr = instr_create(dc);
        decode(dc, (byte *)&reserved[i], instr);
        ASSERT(instr_get_opcode(instr) == OP_xx);
        instr_destroy(dc, instr);
    }

    /* A zero Rm still decodes for ldff1b. */
    static const uint ldff1b_xzr = 0xa41f6000; /* ldff1b {z0.b}, p0/z, [x0, xzr] */
    instr = instr_create(dc);
    decode(dc, (byte *)&ldff1b_xzr, instr);
    ASSERT(instr_get_opcode(instr) == OP_ldff1b);
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

    test_sve_reserved(dcontext);
    print("test_sve_reserved complete\n");

    test_mops_reserved(dcontext);
    print("test_mops_reserved complete\n");

    print("All tests complete\n");
#ifndef STANDALONE_DECODER
    dr_standalone_exit();
#endif
    return 0;
}

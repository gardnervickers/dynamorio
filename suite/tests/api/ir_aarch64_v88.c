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

#include "ir_aarch64.h"

/* The FEAT_MOPS registers must all differ, and only a set's data register may be
 * XZR.
 */
static const reg_id_t mops_d[6] = { DR_REG_X0,  DR_REG_X5,  DR_REG_X10,
                                    DR_REG_X15, DR_REG_X20, DR_REG_X30 };
static const reg_id_t mops_s[6] = { DR_REG_X1,  DR_REG_X6,  DR_REG_X11,
                                    DR_REG_X16, DR_REG_X21, DR_REG_X29 };
static const reg_id_t mops_n[6] = { DR_REG_X2,  DR_REG_X7,  DR_REG_X12,
                                    DR_REG_X17, DR_REG_X22, DR_REG_X28 };
static const reg_id_t mops_set_s[6] = { DR_REG_X1,  DR_REG_X6,  DR_REG_X11,
                                        DR_REG_X16, DR_REG_X21, DR_REG_XZR };

/* Checks what the FEAT_MOPS instructions have in common: their memory accesses,
 * NZCV written by the prologue and read by the main and epilogue instructions, and
 * the category of their encoding.
 */
static void
check_mops(void *dc, instr_t *instr, int i, bool is_copy, bool is_prologue,
           bool *psuccess)
{
    EXPECT_EQ("%d", instr_reads_memory(instr), is_copy);
    EXPECT_TRUE(instr_writes_memory(instr));
    EXPECT_EQ("0x%x", instr_get_arith_flags(instr, DR_QUERY_INCLUDE_ALL),
              is_prologue ? EFLAGS_WRITE_NZCV : EFLAGS_READ_NZCV);
    uint enc;
    instr_t *decoded = instr_create(dc);
    if (instr_encode_to_copy(dc, instr, (byte *)&enc, (byte *)&enc) == NULL ||
        decode(dc, (byte *)&enc, decoded) == NULL) {
        EXPECT_TRUE(false);
    } else {
        EXPECT_EQ("0x%x", instr_get_category(decoded),
                  is_copy ? DR_INSTR_CATEGORY_LOAD | DR_INSTR_CATEGORY_STORE
                          : DR_INSTR_CATEGORY_STORE);
    }
    instr_destroy(dc, decoded);
}

/* Overlapping registers, and XZR or SP other than as a set's data register, are
 * CONSTRAINED UNPREDICTABLE: the encoder must refuse them.
 */
static void
check_mops_invalid(void *dc, instr_t *instr, bool *psuccess)
{
    const int i = 0;
    EXPECT_FALSE(instr_is_encoding_possible(instr));
    instr_destroy(dc, instr);
}

static const reg_id_t cpy_invalid[][3] = {
    { DR_REG_X0, DR_REG_X0, DR_REG_X2 },  { DR_REG_X0, DR_REG_X1, DR_REG_X0 },
    { DR_REG_X0, DR_REG_X1, DR_REG_X1 },  { DR_REG_XZR, DR_REG_X1, DR_REG_X2 },
    { DR_REG_X0, DR_REG_XZR, DR_REG_X2 }, { DR_REG_X0, DR_REG_X1, DR_REG_XZR },
    { DR_REG_XSP, DR_REG_X1, DR_REG_X2 }, { DR_REG_W0, DR_REG_W1, DR_REG_W2 },
};

/* For a set the order is Xd, Xn, Xs. */
static const reg_id_t set_invalid[][3] = {
    { DR_REG_X0, DR_REG_X0, DR_REG_X2 },  { DR_REG_X0, DR_REG_X1, DR_REG_X0 },
    { DR_REG_X0, DR_REG_X1, DR_REG_X1 },  { DR_REG_XZR, DR_REG_X1, DR_REG_X2 },
    { DR_REG_X0, DR_REG_XZR, DR_REG_X2 }, { DR_REG_XSP, DR_REG_X1, DR_REG_X2 },
    { DR_REG_X0, DR_REG_X1, DR_REG_XSP }, { DR_REG_W0, DR_REG_W1, DR_REG_W2 },
};

#define TEST_MOPS_INVALID(op, regs)                                           \
    for (size_t j = 0; j < sizeof(regs) / sizeof(regs[0]); j++) {             \
        check_mops_invalid(dc,                                                \
                           INSTR_CREATE_##op(dc, opnd_create_reg(regs[j][0]), \
                                             opnd_create_reg(regs[j][1]),     \
                                             opnd_create_reg(regs[j][2])),    \
                           psuccess);                                         \
    }

TEST_INSTR(cpyfp)
{
    /* Testing CPYFP [<Xd>]!, [<Xs>]!, <Xn>! */
    TEST_LOOP_EXPECT(
        cpyfp, 6,
        INSTR_CREATE_cpyfp(dc, opnd_create_reg(mops_d[i]), opnd_create_reg(mops_s[i]),
                           opnd_create_reg(mops_n[i])),
        {
            EXPECT_DISASSEMBLY("cpyfp  (%x1) %x0 %x1 %x2 -> (%x0) %x0 %x1 %x2",
                               "cpyfp  (%x6) %x5 %x6 %x7 -> (%x5) %x5 %x6 %x7",
                               "cpyfp  (%x11) %x10 %x11 %x12 -> (%x10) %x10 %x11 %x12",
                               "cpyfp  (%x16) %x15 %x16 %x17 -> (%x15) %x15 %x16 %x17",
                               "cpyfp  (%x21) %x20 %x21 %x22 -> (%x20) %x20 %x21 %x22",
                               "cpyfp  (%x29) %x30 %x29 %x28 -> (%x30) %x30 %x29 %x28");
            check_mops(dc, instr, i, true, true, psuccess);
        });
    TEST_MOPS_INVALID(cpyfp, cpy_invalid);
}

TEST_INSTR(cpyfm)
{
    /* Testing CPYFM [<Xd>]!, [<Xs>]!, <Xn>! */
    TEST_LOOP_EXPECT(
        cpyfm, 6,
        INSTR_CREATE_cpyfm(dc, opnd_create_reg(mops_d[i]), opnd_create_reg(mops_s[i]),
                           opnd_create_reg(mops_n[i])),
        {
            EXPECT_DISASSEMBLY("cpyfm  (%x1) %x0 %x1 %x2 -> (%x0) %x0 %x1 %x2",
                               "cpyfm  (%x6) %x5 %x6 %x7 -> (%x5) %x5 %x6 %x7",
                               "cpyfm  (%x11) %x10 %x11 %x12 -> (%x10) %x10 %x11 %x12",
                               "cpyfm  (%x16) %x15 %x16 %x17 -> (%x15) %x15 %x16 %x17",
                               "cpyfm  (%x21) %x20 %x21 %x22 -> (%x20) %x20 %x21 %x22",
                               "cpyfm  (%x29) %x30 %x29 %x28 -> (%x30) %x30 %x29 %x28");
            check_mops(dc, instr, i, true, false, psuccess);
        });
    TEST_MOPS_INVALID(cpyfm, cpy_invalid);
}

TEST_INSTR(cpyfe)
{
    /* Testing CPYFE [<Xd>]!, [<Xs>]!, <Xn>! */
    TEST_LOOP_EXPECT(
        cpyfe, 6,
        INSTR_CREATE_cpyfe(dc, opnd_create_reg(mops_d[i]), opnd_create_reg(mops_s[i]),
                           opnd_create_reg(mops_n[i])),
        {
            EXPECT_DISASSEMBLY("cpyfe  (%x1) %x0 %x1 %x2 -> (%x0) %x0 %x1 %x2",
                               "cpyfe  (%x6) %x5 %x6 %x7 -> (%x5) %x5 %x6 %x7",
                               "cpyfe  (%x11) %x10 %x11 %x12 -> (%x10) %x10 %x11 %x12",
                               "cpyfe  (%x16) %x15 %x16 %x17 -> (%x15) %x15 %x16 %x17",
                               "cpyfe  (%x21) %x20 %x21 %x22 -> (%x20) %x20 %x21 %x22",
                               "cpyfe  (%x29) %x30 %x29 %x28 -> (%x30) %x30 %x29 %x28");
            check_mops(dc, instr, i, true, false, psuccess);
        });
    TEST_MOPS_INVALID(cpyfe, cpy_invalid);
}

TEST_INSTR(cpyp)
{
    /* Testing CPYP [<Xd>]!, [<Xs>]!, <Xn>! */
    TEST_LOOP_EXPECT(
        cpyp, 6,
        INSTR_CREATE_cpyp(dc, opnd_create_reg(mops_d[i]), opnd_create_reg(mops_s[i]),
                          opnd_create_reg(mops_n[i])),
        {
            EXPECT_DISASSEMBLY("cpyp   (%x1) %x0 %x1 %x2 -> (%x0) %x0 %x1 %x2",
                               "cpyp   (%x6) %x5 %x6 %x7 -> (%x5) %x5 %x6 %x7",
                               "cpyp   (%x11) %x10 %x11 %x12 -> (%x10) %x10 %x11 %x12",
                               "cpyp   (%x16) %x15 %x16 %x17 -> (%x15) %x15 %x16 %x17",
                               "cpyp   (%x21) %x20 %x21 %x22 -> (%x20) %x20 %x21 %x22",
                               "cpyp   (%x29) %x30 %x29 %x28 -> (%x30) %x30 %x29 %x28");
            check_mops(dc, instr, i, true, true, psuccess);
        });
    TEST_MOPS_INVALID(cpyp, cpy_invalid);
}

TEST_INSTR(cpym)
{
    /* Testing CPYM [<Xd>]!, [<Xs>]!, <Xn>! */
    TEST_LOOP_EXPECT(
        cpym, 6,
        INSTR_CREATE_cpym(dc, opnd_create_reg(mops_d[i]), opnd_create_reg(mops_s[i]),
                          opnd_create_reg(mops_n[i])),
        {
            EXPECT_DISASSEMBLY("cpym   (%x1) %x0 %x1 %x2 -> (%x0) %x0 %x1 %x2",
                               "cpym   (%x6) %x5 %x6 %x7 -> (%x5) %x5 %x6 %x7",
                               "cpym   (%x11) %x10 %x11 %x12 -> (%x10) %x10 %x11 %x12",
                               "cpym   (%x16) %x15 %x16 %x17 -> (%x15) %x15 %x16 %x17",
                               "cpym   (%x21) %x20 %x21 %x22 -> (%x20) %x20 %x21 %x22",
                               "cpym   (%x29) %x30 %x29 %x28 -> (%x30) %x30 %x29 %x28");
            check_mops(dc, instr, i, true, false, psuccess);
        });
    TEST_MOPS_INVALID(cpym, cpy_invalid);
}

TEST_INSTR(cpye)
{
    /* Testing CPYE [<Xd>]!, [<Xs>]!, <Xn>! */
    TEST_LOOP_EXPECT(
        cpye, 6,
        INSTR_CREATE_cpye(dc, opnd_create_reg(mops_d[i]), opnd_create_reg(mops_s[i]),
                          opnd_create_reg(mops_n[i])),
        {
            EXPECT_DISASSEMBLY("cpye   (%x1) %x0 %x1 %x2 -> (%x0) %x0 %x1 %x2",
                               "cpye   (%x6) %x5 %x6 %x7 -> (%x5) %x5 %x6 %x7",
                               "cpye   (%x11) %x10 %x11 %x12 -> (%x10) %x10 %x11 %x12",
                               "cpye   (%x16) %x15 %x16 %x17 -> (%x15) %x15 %x16 %x17",
                               "cpye   (%x21) %x20 %x21 %x22 -> (%x20) %x20 %x21 %x22",
                               "cpye   (%x29) %x30 %x29 %x28 -> (%x30) %x30 %x29 %x28");
            check_mops(dc, instr, i, true, false, psuccess);
        });
    TEST_MOPS_INVALID(cpye, cpy_invalid);
}

TEST_INSTR(setp)
{
    /* Testing SETP [<Xd>]!, <Xn>!, <Xs> */
    TEST_LOOP_EXPECT(setp, 6,
                     INSTR_CREATE_setp(dc, opnd_create_reg(mops_d[i]),
                                       opnd_create_reg(mops_n[i]),
                                       opnd_create_reg(mops_set_s[i])),
                     {
                         EXPECT_DISASSEMBLY("setp   %x0 %x2 %x1 -> (%x0) %x0 %x2",
                                            "setp   %x5 %x7 %x6 -> (%x5) %x5 %x7",
                                            "setp   %x10 %x12 %x11 -> (%x10) %x10 %x12",
                                            "setp   %x15 %x17 %x16 -> (%x15) %x15 %x17",
                                            "setp   %x20 %x22 %x21 -> (%x20) %x20 %x22",
                                            "setp   %x30 %x28 %xzr -> (%x30) %x30 %x28");
                         check_mops(dc, instr, i, false, true, psuccess);
                     });
    TEST_MOPS_INVALID(setp, set_invalid);
}

TEST_INSTR(setm)
{
    /* Testing SETM [<Xd>]!, <Xn>!, <Xs> */
    TEST_LOOP_EXPECT(setm, 6,
                     INSTR_CREATE_setm(dc, opnd_create_reg(mops_d[i]),
                                       opnd_create_reg(mops_n[i]),
                                       opnd_create_reg(mops_set_s[i])),
                     {
                         EXPECT_DISASSEMBLY("setm   %x0 %x2 %x1 -> (%x0) %x0 %x2",
                                            "setm   %x5 %x7 %x6 -> (%x5) %x5 %x7",
                                            "setm   %x10 %x12 %x11 -> (%x10) %x10 %x12",
                                            "setm   %x15 %x17 %x16 -> (%x15) %x15 %x17",
                                            "setm   %x20 %x22 %x21 -> (%x20) %x20 %x22",
                                            "setm   %x30 %x28 %xzr -> (%x30) %x30 %x28");
                         check_mops(dc, instr, i, false, false, psuccess);
                     });
    TEST_MOPS_INVALID(setm, set_invalid);
}

TEST_INSTR(sete)
{
    /* Testing SETE [<Xd>]!, <Xn>!, <Xs> */
    TEST_LOOP_EXPECT(sete, 6,
                     INSTR_CREATE_sete(dc, opnd_create_reg(mops_d[i]),
                                       opnd_create_reg(mops_n[i]),
                                       opnd_create_reg(mops_set_s[i])),
                     {
                         EXPECT_DISASSEMBLY("sete   %x0 %x2 %x1 -> (%x0) %x0 %x2",
                                            "sete   %x5 %x7 %x6 -> (%x5) %x5 %x7",
                                            "sete   %x10 %x12 %x11 -> (%x10) %x10 %x12",
                                            "sete   %x15 %x17 %x16 -> (%x15) %x15 %x17",
                                            "sete   %x20 %x22 %x21 -> (%x20) %x20 %x22",
                                            "sete   %x30 %x28 %xzr -> (%x30) %x30 %x28");
                         check_mops(dc, instr, i, false, false, psuccess);
                     });
    TEST_MOPS_INVALID(sete, set_invalid);
}

int
main(int argc, char *argv[])
{
#ifdef STANDALONE_DECODER
    void *dcontext = GLOBAL_DCONTEXT;
#else
    void *dcontext = dr_standalone_init();
#endif
    bool result = true;
    bool test_result;
    instr_t *instr;

    enable_all_test_cpu_features();

    /* FEAT_MOPS */
    RUN_INSTR_TEST(cpyfp);
    RUN_INSTR_TEST(cpyfm);
    RUN_INSTR_TEST(cpyfe);
    RUN_INSTR_TEST(cpyp);
    RUN_INSTR_TEST(cpym);
    RUN_INSTR_TEST(cpye);
    RUN_INSTR_TEST(setp);
    RUN_INSTR_TEST(setm);
    RUN_INSTR_TEST(sete);

    print("All v8.8 tests complete.\n");
#ifndef STANDALONE_DECODER
    dr_standalone_exit();
#endif
    if (result)
        return 0;
    return 1;
}

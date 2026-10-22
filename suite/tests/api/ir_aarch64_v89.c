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

/* Checks which registers instr reads and writes.  DR_REG_NULL is none. */
static void
check_reg_use(void *dc, instr_t *instr, int i, reg_id_t read, reg_id_t written,
              bool *psuccess)
{
    EXPECT_EQ("%d", instr_num_srcs(instr), read == DR_REG_NULL ? 0 : 1);
    EXPECT_EQ("%d", instr_num_dsts(instr), written == DR_REG_NULL ? 0 : 1);
    if (read != DR_REG_NULL) {
        EXPECT_TRUE(opnd_is_reg(instr_get_src(instr, 0)) &&
                    opnd_get_reg(instr_get_src(instr, 0)) == read);
    }
    if (written != DR_REG_NULL) {
        EXPECT_TRUE(opnd_is_reg(instr_get_dst(instr, 0)) &&
                    opnd_get_reg(instr_get_dst(instr, 0)) == written);
    }
    EXPECT_FALSE(instr_reads_memory(instr));
    EXPECT_FALSE(instr_writes_memory(instr));
}

/* Checks that enc decodes as opcode, reading read and writing written. */
static void
check_decode(void *dc, uint enc, int opcode, reg_id_t read, reg_id_t written,
             bool *psuccess)
{
    const int i = 0;
    instr_t *instr = instr_create(dc);
    if (decode(dc, (byte *)&enc, instr) == NULL) {
        EXPECT_TRUE(false);
    } else {
        EXPECT_EQ("%d", instr_get_opcode(instr), opcode);
        check_reg_use(dc, instr, i, read, written, psuccess);
    }
    instr_destroy(dc, instr);
}

/* Checks that enc decodes as the generic SYS, reading rt, or SYSL, writing rt. */
static void
check_decode_generic(void *dc, uint enc, int opcode, reg_id_t rt, bool *psuccess)
{
    const int i = 0;
    instr_t *instr = instr_create(dc);
    if (decode(dc, (byte *)&enc, instr) == NULL) {
        EXPECT_TRUE(false);
    } else {
        EXPECT_EQ("%d", instr_get_opcode(instr), opcode);
        EXPECT_EQ("%d", instr_reads_from_reg(instr, rt, DR_QUERY_DEFAULT),
                  opcode == OP_sys);
        EXPECT_EQ("%d", instr_writes_to_reg(instr, rt, DR_QUERY_DEFAULT),
                  opcode == OP_sysl);
    }
    instr_destroy(dc, instr);
}

static const reg_id_t xt[6] = { DR_REG_X0,  DR_REG_X4,  DR_REG_X10,
                                DR_REG_X16, DR_REG_X30, DR_REG_XZR };

TEST_INSTR(chkfeat)
{
    /* Testing CHKFEAT X16: X16 is read and written. */
    TEST_LOOP_EXPECT(chkfeat, 1, INSTR_CREATE_chkfeat(dc), {
        EXPECT_DISASSEMBLY("chkfeat %x16 -> %x16");
        EXPECT_TRUE(instr_reads_from_reg(instr, DR_REG_X16, DR_QUERY_DEFAULT));
        EXPECT_TRUE(instr_writes_to_reg(instr, DR_REG_X16, DR_QUERY_DEFAULT));
        check_reg_use(dc, instr, i, DR_REG_X16, DR_REG_X16, psuccess);
    });
    /* glibc's encoding, which DR decoded as a NOP. */
    check_decode(dc, 0xd503251f, OP_chkfeat, DR_REG_X16, DR_REG_X16, psuccess);
}

TEST_INSTR(gcspushm)
{
    /* Testing GCSPUSHM <Xt>: Xt is read. */
    TEST_LOOP_EXPECT(gcspushm, 6, INSTR_CREATE_gcspushm(dc, opnd_create_reg(xt[i])), {
        EXPECT_DISASSEMBLY("gcspushm %x0", "gcspushm %x4", "gcspushm %x10",
                           "gcspushm %x16", "gcspushm %x30", "gcspushm %xzr");
        check_reg_use(dc, instr, i, xt[i], DR_REG_NULL, psuccess);
    });
    check_decode(dc, 0xd50b7703, OP_gcspushm, DR_REG_X3, DR_REG_NULL, psuccess);
}

TEST_INSTR(gcspopm)
{
    /* Testing GCSPOPM {<Xt>}: Xt is written, and read as it is unchanged when GCS is
     * not enabled.
     */
    TEST_LOOP_EXPECT(gcspopm, 6, INSTR_CREATE_gcspopm(dc, opnd_create_reg(xt[i])), {
        EXPECT_DISASSEMBLY("gcspopm %x0 -> %x0", "gcspopm %x4 -> %x4",
                           "gcspopm %x10 -> %x10", "gcspopm %x16 -> %x16",
                           "gcspopm %x30 -> %x30", "gcspopm %xzr -> %xzr");
        check_reg_use(dc, instr, i, xt[i], xt[i], psuccess);
    });
    check_decode(dc, 0xd52b7723, OP_gcspopm, DR_REG_X3, DR_REG_X3, psuccess);
}

TEST_INSTR(gcsss1)
{
    /* Testing GCSSS1 <Xt>: Xt is read. */
    TEST_LOOP_EXPECT(gcsss1, 6, INSTR_CREATE_gcsss1(dc, opnd_create_reg(xt[i])), {
        EXPECT_DISASSEMBLY("gcsss1 %x0", "gcsss1 %x4", "gcsss1 %x10", "gcsss1 %x16",
                           "gcsss1 %x30", "gcsss1 %xzr");
        check_reg_use(dc, instr, i, xt[i], DR_REG_NULL, psuccess);
        EXPECT_FALSE(instr_writes_to_reg(instr, xt[i], DR_QUERY_DEFAULT));
    });
    /* glibc's gcsss1 x4, which DR decoded as a SYS writing X4. */
    check_decode(dc, 0xd50b7744, OP_gcsss1, DR_REG_X4, DR_REG_NULL, psuccess);
}

TEST_INSTR(gcsss2)
{
    /* Testing GCSSS2 <Xt>: Xt is written, and read as it is unchanged when GCS is not
     * enabled.
     */
    TEST_LOOP_EXPECT(gcsss2, 6, INSTR_CREATE_gcsss2(dc, opnd_create_reg(xt[i])), {
        EXPECT_DISASSEMBLY("gcsss2 %x0 -> %x0", "gcsss2 %x4 -> %x4",
                           "gcsss2 %x10 -> %x10", "gcsss2 %x16 -> %x16",
                           "gcsss2 %x30 -> %x30", "gcsss2 %xzr -> %xzr");
        check_reg_use(dc, instr, i, xt[i], xt[i], psuccess);
    });
    check_decode(dc, 0xd52b7763, OP_gcsss2, DR_REG_X3, DR_REG_X3, psuccess);
}

TEST_INSTR(gcspushx)
{
    /* Testing GCSPUSHX: the exception return record holds X30. */
    TEST_LOOP_EXPECT(gcspushx, 1, INSTR_CREATE_gcspushx(dc), {
        EXPECT_DISASSEMBLY("gcspushx %x30");
        check_reg_use(dc, instr, i, DR_REG_X30, DR_REG_NULL, psuccess);
    });
    check_decode(dc, 0xd508779f, OP_gcspushx, DR_REG_X30, DR_REG_NULL, psuccess);
}

TEST_INSTR(gcspopcx)
{
    /* Testing GCSPOPCX: the exception return record is compared with X30. */
    TEST_LOOP_EXPECT(gcspopcx, 1, INSTR_CREATE_gcspopcx(dc), {
        EXPECT_DISASSEMBLY("gcspopcx %x30");
        check_reg_use(dc, instr, i, DR_REG_X30, DR_REG_NULL, psuccess);
    });
    check_decode(dc, 0xd50877bf, OP_gcspopcx, DR_REG_X30, DR_REG_NULL, psuccess);
}

TEST_INSTR(gcspopx)
{
    /* Testing GCSPOPX */
    TEST_LOOP_EXPECT(gcspopx, 1, INSTR_CREATE_gcspopx(dc), {
        EXPECT_DISASSEMBLY("gcspopx");
        check_reg_use(dc, instr, i, DR_REG_NULL, DR_REG_NULL, psuccess);
    });
    check_decode(dc, 0xd50877df, OP_gcspopx, DR_REG_NULL, DR_REG_NULL, psuccess);
}

/* SYS and SYSL forms next to the GCS aliases stay generic, with SYS reading Xt and
 * SYSL writing it.
 */
TEST_INSTR(gcs_neighbours)
{
    const int i = 0;
    /* GCSPUSHX, GCSPOPCX and GCSPOPX with Rt != 31. */
    check_decode_generic(dc, 0xd508779e, OP_sys, DR_REG_X30, psuccess);
    check_decode_generic(dc, 0xd50877a0, OP_sys, DR_REG_X0, psuccess);
    check_decode_generic(dc, 0xd50877c0, OP_sys, DR_REG_X0, psuccess);
    /* SYS #3, C7, C7, #1 and #3 (SYSL's GCSPOPM and GCSSS2 with L == 0). */
    check_decode_generic(dc, 0xd50b7725, OP_sys, DR_REG_X5, psuccess);
    check_decode_generic(dc, 0xd50b7765, OP_sys, DR_REG_X5, psuccess);
    /* SYSL #3, C7, C7, #0 and #2 (SYS's GCSPUSHM and GCSSS1 with L == 1). */
    check_decode_generic(dc, 0xd52b7705, OP_sysl, DR_REG_X5, psuccess);
    check_decode_generic(dc, 0xd52b7745, OP_sysl, DR_REG_X5, psuccess);
    /* The GCS alias fields encoded through INSTR_CREATE_sys() decode as the alias. */
    instr = INSTR_CREATE_sys(
        dc, opnd_create_immed_uint(3, OPSZ_3b), opnd_create_immed_uint(7, OPSZ_4b),
        opnd_create_immed_uint(7, OPSZ_4b), opnd_create_immed_uint(2, OPSZ_3b),
        opnd_create_reg(DR_REG_X4));
    uint enc = 0;
    if (instr_encode_to_copy(dc, instr, (byte *)&enc, (byte *)&enc) == NULL)
        EXPECT_TRUE(false);
    EXPECT_EQ("0x%08x", enc, 0xd50b7744);
    instr_destroy(dc, instr);
}

/* An app instr whose word changes between our decode and the emit, as when a JIT
 * patches its code, must be emitted as we decoded it: we did not decode, or mangle,
 * the new word.  Here the new word is BR X28, which unmangled would jump through
 * DR's TLS base.  Without FEAT_GCS the GCS instrs cannot be encoded for new code,
 * and emit used to fall back to copying the new word; it did the same for a word we
 * decode as OP_xx.  The decoded instrs' raw bits point at the word, as for app code;
 * standalone, there is no bb building's copy of it, so emit checks the word against
 * the instr's encoding.
 */
#ifndef STANDALONE_DECODER
TEST_INSTR(changed_app_word)
{
    static const struct {
        uint word;
        int opcode;
    } decoded[] = {
        { 0xd50b7700, OP_gcspushm }, /* gcspushm x0 */
        { 0xd52b7720, OP_gcspopm },  /* gcspopm x0 */
        { 0xd50b7744, OP_gcsss1 },   /* gcsss1 x4 */
        { 0x19011440, OP_xx },       /* cpyfpwt [x0]!, [x1]!, x2! */
    };
    const uint br_x28 = 0xd61f0380;
    proc_set_feature(FEATURE_GCS, false);
    for (int i = 0; i < sizeof(decoded) / sizeof(decoded[0]); i++) {
        uint app = decoded[i].word, out = 0;
        instr = instr_create(dc);
        EXPECT_TRUE(decode(dc, (byte *)&app, instr) == (byte *)(&app + 1));
        EXPECT_EQ("%d", instr_get_opcode(instr), decoded[i].opcode);
        EXPECT_TRUE(instr_raw_bits_valid(instr));
        /* Unchanged, and then changed. */
        EXPECT_TRUE(instr_encode_to_copy(dc, instr, (byte *)&out, (byte *)&app) ==
                    (byte *)(&out + 1));
        EXPECT_EQ("0x%08x", out, decoded[i].word);
        app = br_x28;
        out = 0;
        EXPECT_TRUE(instr_encode_to_copy(dc, instr, (byte *)&out, (byte *)&app) ==
                    (byte *)(&out + 1));
        EXPECT_EQ("0x%08x", out, decoded[i].word);
        /* New code with a GCS instr still cannot be encoded on this CPU. */
        if (decoded[i].opcode != OP_xx)
            EXPECT_FALSE(instr_is_encoding_possible(instr));
        instr_destroy(dc, instr);
    }
    proc_set_feature(FEATURE_GCS, true);
}

#endif
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

    /* FEAT_CHK */
    RUN_INSTR_TEST(chkfeat);

    /* FEAT_GCS */
    RUN_INSTR_TEST(gcspushm);
    RUN_INSTR_TEST(gcspopm);
    RUN_INSTR_TEST(gcsss1);
    RUN_INSTR_TEST(gcsss2);
    RUN_INSTR_TEST(gcspushx);
    RUN_INSTR_TEST(gcspopcx);
    RUN_INSTR_TEST(gcspopx);
    RUN_INSTR_TEST(gcs_neighbours);
#ifndef STANDALONE_DECODER
    RUN_INSTR_TEST(changed_app_word);
#endif

    print("All v8.9 tests complete.\n");
#ifndef STANDALONE_DECODER
    dr_standalone_exit();
#endif
    if (result)
        return 0;
    return 1;
}

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
 * Benchmarks and guards for the AArch64 IR work done for every block DR
 * builds (suite/tests/a64_codegen/README.md).  Every application instruction
 * of a block is decoded with decode_common() (there is no fast decode on
 * AArch64), and at emit copy_and_re_relativize_raw_instr() re-encodes it to
 * compare with the live word; instr_get_eflags() on an instruction without
 * valid raw bits looks its opcode up (debug DR also encodes it and decodes
 * the encoding again, and asserts the two agree).  A change that
 * makes any of these cheaper must not change what they compute, so the
 * guards check, on the executable text of libc (real compiler output, decoded
 * at its own address so pc-relative operands are real) and on pseudo-random
 * words (the whole encoding space, at a fixed seed):
 *
 *   decode   decode_from_copy() of a valid word consumes 4 bytes and gives an
 *            opcode; decode_sizeof() and decode_next_pc() agree.
 *   encode   the decoded instruction encodes to 4 bytes (decoded from a
 *            copy, its raw bits are invalid, so the encoder runs), and the
 *            encoding is the original word or decodes to the same
 *            instruction (instr_same); the same instruction made anew, as a
 *            client would (instr_build()), encodes identically, its
 *            instr_length() is 4, and instr_is_encoding_possible() (which
 *            ignores reachability) accepts it.
 *   flags    instr_get_eflags() and instr_get_arith_flags() of the new
 *            instruction agree with the flags usage the decoder recorded.
 *            Pc-relative instructions are counted: debug DR encodes them to
 *            a buffer of its own, where the target is usually out of range.
 *
 *   predicate  a B.EQ decoded in place (so with valid raw bits) whose predicate
 *            is set to NE encodes to B.NE; an undecoded B.EQ (raw bits only) whose
 *            predicate is set still encodes, to its raw bits.
 *
 * Words the decoder does not know (OP_xx) are counted, not checked.
 *
 * All CPU features are enabled for the guards, so the result does not depend
 * on the host.  The benchmarks run first with the host's features (the
 * encoder checks proc_has_feature() for every non-base opcode, a real part of
 * its cost) and print the best of several passes over the libc corpus:
 *
 *   decode        decode_from_copy() into a reused instr_t
 *   encode        instr_encode_to_copy() of decoded instructions (decoded
 *                 from a copy, so their raw bits are invalid)
 *   eflags_new    the first instr_get_eflags() of a new instruction (built
 *                 like a client's, with nothing cached): an opcode lookup
 *   reenc_check   decode, encode and compare, the per-instruction work of
 *                 copy_and_re_relativize_raw_instr()
 *
 * The instructions are made with the drcontext of a thread DR has set up
 * (dr_app_setup(), without starting to run it), as in block building.
 * -standalone uses dr_standalone_init() instead.  (With the shared
 * libdynamorio.so, standalone decoding was 20x slower: every heap allocation
 * and free takes the global heap's recursive lock, whose owner check calls
 * d_r_get_thread_id(), a gettid system call when the thread has no DR TLS.)
 *
 * Usage: api.a64_codegen_ir [-reps N] [-random N] [-bench-only|-guard-only]
 *                           [-standalone]
 */

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* dl_iterate_phdr */
#endif
#include "configure.h"
#include "dr_api.h"

#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RANDOM_PC ((byte *)0x10000000)
#define MAX_REPORTS 20

typedef struct {
    byte *start;
    size_t words;
} corpus_t;

static void *dc;

static int
find_libc_text(struct dl_phdr_info *info, size_t size, void *data)
{
    corpus_t *c = data;
    if (info->dlpi_name == NULL || strstr(info->dlpi_name, "/libc.so") == NULL)
        return 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X) != 0 &&
            ph->p_memsz / 4 > c->words) {
            c->start = (byte *)(info->dlpi_addr + ph->p_vaddr);
            c->words = ph->p_memsz / 4;
        }
    }
    return c->words > 0;
}

static double
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + ts.tv_nsec;
}

static uint64_t
xorshift64(uint64_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

/***************************************************************************
 * Guards
 */

typedef struct {
    const char *name;
    uint64_t words, valid, xx, pcrel, exact, alias, failures;
} guard_counts_t;

static bool
has_pc_operand(instr_t *in)
{
    for (int i = 0; i < instr_num_srcs(in); i++) {
        opnd_t o = instr_get_src(in, i);
        if (opnd_is_pc(o) || opnd_is_rel_addr(o) || opnd_is_instr(o))
            return true;
    }
    for (int i = 0; i < instr_num_dsts(in); i++) {
        opnd_t o = instr_get_dst(in, i);
        if (opnd_is_pc(o) || opnd_is_rel_addr(o) || opnd_is_instr(o))
            return true;
    }
    return false;
}

/* A new instruction with in's opcode, operands and predicate, made the way a
 * client makes one: nothing about it is cached (decoding caches the flags
 * usage), so queries about it go through the encoder.
 */
static instr_t *
rebuild(instr_t *in)
{
    instr_t *n =
        instr_build(dc, instr_get_opcode(in), instr_num_dsts(in), instr_num_srcs(in));
    for (int i = 0; i < instr_num_dsts(in); i++)
        instr_set_dst(n, i, instr_get_dst(in, i));
    for (int i = 0; i < instr_num_srcs(in); i++)
        instr_set_src(n, i, instr_get_src(in, i));
    instr_set_predicate(n, instr_get_predicate(in));
    return n;
}

static void
report(guard_counts_t *g, const char *what, uint enc, byte *pc, uint enc2)
{
    if (++g->failures > MAX_REPORTS)
        return;
    printf("FAIL %s %08x at %p: %s", g->name, enc, pc, what);
    if (enc2 != 0)
        printf(" (re-encoded %08x)", enc2);
    printf("\n    ");
    fflush(stdout);
    disassemble_from_copy(dc, (byte *)&enc, pc, STDOUT, false, false);
    if (enc2 != 0) {
        printf("    -> ");
        fflush(stdout);
        disassemble_from_copy(dc, (byte *)&enc2, pc, STDOUT, false, false);
    }
}

/* Checks the word enc, which is (a copy of) the word at pc. */
static void
guard_word(guard_counts_t *g, uint enc, byte *pc)
{
    instr_t a, b, *n = NULL;
    uint enc2 = 0, enc3 = 0;
    g->words++;
    instr_init(dc, &a);
    instr_init(dc, &b);
    /* Decoding from a copy leaves the raw bits invalid, so encoding a runs
     * the encoder.
     */
    byte *next = decode_from_copy(dc, (byte *)&enc, pc, &a);
    if (next == NULL || instr_get_opcode(&a) == OP_INVALID)
        goto done;
    g->valid++;
    if (next != (byte *)&enc + 4 || instr_get_opcode(&a) < OP_FIRST ||
        instr_get_opcode(&a) > OP_LAST) {
        report(g, "decode did not consume 4 bytes", enc, pc, 0);
        goto done;
    }
    if (decode_sizeof(dc, (byte *)&enc, NULL) != 4 ||
        decode_next_pc(dc, (byte *)&enc) != (byte *)&enc + 4) {
        report(g, "decode_sizeof/decode_next_pc disagree with decode", enc, pc, 0);
        goto done;
    }
    if (instr_get_opcode(&a) == OP_xx) {
        /* Not known to the decoder: the encoder copies the word back. */
        g->xx++;
        goto done;
    }
    n = rebuild(&a);
    if (instr_length(dc, n) != 4) {
        report(g, "instr_length of a new instruction is not 4", enc, pc, 0);
        goto done;
    }
    /* This ignores reachability, as DR does when it encodes an instruction to a
     * buffer of its own, where a pc-relative target is usually out of range.
     */
    if (!instr_is_encoding_possible(n)) {
        report(g, "a new instruction is not encodable ignoring reachability", enc, pc, 0);
        goto done;
    }
    if (instr_encode_to_copy(dc, &a, (byte *)&enc2, pc) != (byte *)&enc2 + 4) {
        report(g, "encode failed", enc, pc, 0);
        goto done;
    }
    if (instr_encode_to_copy(dc, n, (byte *)&enc3, pc) != (byte *)&enc3 + 4 ||
        enc3 != enc2) {
        report(g, "a new instruction encodes differently", enc, pc, enc3);
        goto done;
    }
    /* Debug DR's flags query also encodes the new instruction to a buffer of
     * its own, where a pc-relative target is usually out of range.
     */
    if (has_pc_operand(n))
        g->pcrel++;
    if (instr_get_eflags(n, DR_QUERY_INCLUDE_ALL) !=
            instr_get_eflags(&a, DR_QUERY_INCLUDE_ALL) ||
        instr_get_eflags(n, DR_QUERY_DEFAULT) != instr_get_eflags(&a, DR_QUERY_DEFAULT) ||
        instr_get_arith_flags(n, DR_QUERY_DEFAULT) !=
            instr_get_arith_flags(&a, DR_QUERY_DEFAULT)) {
        report(g, "a new instruction's flags usage differs from the decoder's", enc, pc,
               0);
        goto done;
    }
    if (enc2 == enc) {
        g->exact++;
        goto done;
    }
    if (decode_from_copy(dc, (byte *)&enc2, pc, &b) == NULL || !instr_same(&a, &b)) {
        report(g, "re-encoding is a different instruction", enc, pc, enc2);
        goto done;
    }
    g->alias++;
done:
    if (n != NULL)
        instr_destroy(dc, n);
    instr_free(dc, &a);
    instr_free(dc, &b);
}

static void
guard_print(guard_counts_t *g)
{
    printf("guard %s: %llu words, %llu valid, %llu OP_xx, %llu pc-relative, %llu exact, "
           "%llu aliases, %llu failures\n",
           g->name, (unsigned long long)g->words, (unsigned long long)g->valid,
           (unsigned long long)g->xx, (unsigned long long)g->pcrel,
           (unsigned long long)g->exact, (unsigned long long)g->alias,
           (unsigned long long)g->failures);
}

/* The predicate guard.  Returns the number of failures. */
static uint64_t
guard_predicate(void)
{
    static uint words[1] = { 0x54000060 }; /* b.eq pc+12 */
    const uint b_ne = 0x54000061;
    uint64_t failures = 0;
    uint out;
    instr_t in;
    instr_init(dc, &in);
    if (decode(dc, (byte *)words, &in) == NULL || !instr_raw_bits_valid(&in)) {
        printf("FAIL predicate: decoding b.eq in place\n");
        failures++;
    } else {
        instr_set_predicate(&in, DR_PRED_NE);
        out = 0;
        if (instr_encode_to_copy(dc, &in, (byte *)&out, (byte *)words) == NULL ||
            out != b_ne) {
            printf("FAIL predicate: decoded b.eq set to NE encodes to %08x, not %08x\n",
                   out, b_ne);
            failures++;
        }
    }
    instr_reset(dc, &in);
    instr_set_raw_bits(&in, (byte *)words, 4);
    instr_set_predicate(&in, DR_PRED_EQ);
    out = 0;
    if (!instr_raw_bits_valid(&in) ||
        instr_encode_to_copy(dc, &in, (byte *)&out, (byte *)words) == NULL ||
        out != words[0]) {
        printf("FAIL predicate: undecoded b.eq with its predicate set encodes to %08x, "
               "not %08x\n",
               out, words[0]);
        failures++;
    }
    instr_free(dc, &in);
    printf("guard predicate: %llu failures\n", (unsigned long long)failures);
    return failures;
}

static uint64_t
guards(corpus_t *libc, uint64_t random_words)
{
    guard_counts_t gl = { "libc" }, gr = { "random" };
    for (size_t i = 0; i < libc->words; i++) {
        uint enc;
        memcpy(&enc, libc->start + 4 * i, 4);
        guard_word(&gl, enc, libc->start + 4 * i);
    }
    guard_print(&gl);
    uint64_t seed = 0x9e3779b97f4a7c15ULL;
    for (uint64_t i = 0; i < random_words; i++)
        guard_word(&gr, (uint)xorshift64(&seed), RANDOM_PC);
    guard_print(&gr);
    return gl.failures + gr.failures + guard_predicate();
}

/***************************************************************************
 * Benchmarks
 */

typedef struct {
    uint *words; /* Valid words of the corpus, */
    byte **pcs;  /* and their addresses. */
    size_t n;
} valid_t;

/* Decoded from copies, so with invalid raw bits; or, with fresh, rebuilt as
 * new instructions with nothing cached.
 */
static instr_t **
decode_all(valid_t *v, bool fresh)
{
    instr_t **in = malloc(v->n * sizeof(*in));
    for (size_t i = 0; i < v->n; i++) {
        in[i] = instr_create(dc);
        decode_from_copy(dc, (byte *)&v->words[i], v->pcs[i], in[i]);
        if (fresh) {
            instr_t *n = rebuild(in[i]);
            instr_destroy(dc, in[i]);
            in[i] = n;
        }
    }
    return in;
}

static void
destroy_all(valid_t *v, instr_t **in)
{
    for (size_t i = 0; i < v->n; i++)
        instr_destroy(dc, in[i]);
    free(in);
}

static volatile uint64_t sink;

static double
bench_decode(valid_t *v)
{
    instr_t in;
    instr_init(dc, &in);
    double t = now_ns();
    for (size_t i = 0; i < v->n; i++) {
        instr_reset(dc, &in);
        decode_from_copy(dc, (byte *)&v->words[i], v->pcs[i], &in);
    }
    t = now_ns() - t;
    instr_free(dc, &in);
    return t;
}

static double
bench_encode(valid_t *v)
{
    instr_t **in = decode_all(v, false);
    uint out, sum = 0;
    double t = now_ns();
    for (size_t i = 0; i < v->n; i++) {
        instr_encode_to_copy(dc, in[i], (byte *)&out, v->pcs[i]);
        sum += out;
    }
    t = now_ns() - t;
    sink += sum;
    destroy_all(v, in);
    return t;
}

static double
bench_eflags(valid_t *v)
{
    instr_t **in = decode_all(v, true);
    uint sum = 0;
    double t = now_ns();
    for (size_t i = 0; i < v->n; i++)
        sum += instr_get_eflags(in[i], DR_QUERY_DEFAULT);
    t = now_ns() - t;
    sink += sum;
    destroy_all(v, in);
    return t;
}

static double
bench_reenc_check(valid_t *v)
{
    instr_t in;
    uint out, same = 0;
    instr_init(dc, &in);
    double t = now_ns();
    for (size_t i = 0; i < v->n; i++) {
        instr_reset(dc, &in);
        decode_from_copy(dc, (byte *)&v->words[i], v->pcs[i], &in);
        if (instr_encode_to_copy(dc, &in, (byte *)&out, v->pcs[i]) != NULL &&
            out == v->words[i])
            same++;
    }
    t = now_ns() - t;
    sink += same;
    instr_free(dc, &in);
    return t;
}

static void
benchmarks(corpus_t *libc, int reps)
{
    valid_t v;
    v.words = malloc(libc->words * sizeof(*v.words));
    v.pcs = malloc(libc->words * sizeof(*v.pcs));
    v.n = 0;
    instr_t in;
    instr_init(dc, &in);
    for (size_t i = 0; i < libc->words; i++) {
        uint enc;
        memcpy(&enc, libc->start + 4 * i, 4);
        instr_reset(dc, &in);
        if (decode_from_copy(dc, (byte *)&enc, libc->start + 4 * i, &in) == NULL ||
            instr_get_opcode(&in) == OP_INVALID || instr_get_opcode(&in) == OP_xx)
            continue;
        /* Leave out what the host's encoder cannot take, so every benchmark
         * times the same instructions.
         */
        uint out;
        if (instr_encode_to_copy(dc, &in, (byte *)&out, libc->start + 4 * i) == NULL)
            continue;
        v.words[v.n] = enc;
        v.pcs[v.n] = libc->start + 4 * i;
        v.n++;
    }
    instr_free(dc, &in);
    printf("bench corpus: libc, %zu instructions the host can encode\n", v.n);

#define NUM_BENCH 4
    static const char *const names[NUM_BENCH] = { "decode", "encode", "eflags_new",
                                                  "reenc_check" };
    double best[NUM_BENCH];
    for (int k = 0; k < NUM_BENCH; k++)
        best[k] = 1e300;
    for (int r = 0; r < reps; r++) {
        double t[NUM_BENCH] = { bench_decode(&v), bench_encode(&v), bench_eflags(&v),
                                bench_reenc_check(&v) };
        for (int k = 0; k < NUM_BENCH; k++) {
            if (t[k] < best[k])
                best[k] = t[k];
        }
    }
    for (int k = 0; k < NUM_BENCH; k++)
        printf("bench %-12s %8.1f ns/instr\n", names[k], best[k] / v.n);
    free(v.words);
    free(v.pcs);
}

int
main(int argc, char *argv[])
{
    int reps = 5;
    uint64_t random_words = 1 << 20;
    bool bench = true, guard = true, standalone = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-reps") == 0 && i + 1 < argc)
            reps = atoi(argv[++i]);
        else if (strcmp(argv[i], "-random") == 0 && i + 1 < argc)
            random_words = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-bench-only") == 0)
            guard = false;
        else if (strcmp(argv[i], "-guard-only") == 0)
            bench = false;
        else if (strcmp(argv[i], "-standalone") == 0)
            standalone = true;
        else {
            fprintf(stderr,
                    "usage: %s [-reps N] [-random N] [-bench-only|-guard-only] "
                    "[-standalone]\n",
                    argv[0]);
            return 1;
        }
    }
    if (standalone)
        dc = dr_standalone_init();
    else {
        if (dr_app_setup() != 0) {
            printf("FAIL: dr_app_setup failed\n");
            return 1;
        }
        dc = dr_get_current_drcontext();
    }
    corpus_t libc = { NULL, 0 };
    dl_iterate_phdr(find_libc_text, &libc);
    if (libc.words == 0) {
        printf("FAIL: no executable libc segment found\n");
        return 1;
    }
    if (bench)
        benchmarks(&libc, reps);
    uint64_t failures = 0;
    if (guard) {
        enable_all_test_cpu_features();
        failures = guards(&libc, random_words);
    }
    if (standalone)
        dr_standalone_exit();
    else
        dr_app_cleanup();
    if (failures > 0) {
        printf("FAIL: %llu guard failures\n", (unsigned long long)failures);
        return 1;
    }
    printf("a64_codegen_ir: done\n");
    return 0;
}

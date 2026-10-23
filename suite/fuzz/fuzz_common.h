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

/* Shared helpers for the libFuzzer harnesses in this directory.  Each harness
 * defines LLVMFuzzerTestOneInput() and links against drdecode_fuzz, a copy of
 * the static decoder library built with internal ASSERTs enabled.
 */

#ifndef _FUZZ_COMMON_H_
#    define _FUZZ_COMMON_H_ 1

#    include "dr_api.h"

#    include <stddef.h>
#    include <stdint.h>
#    include <stdio.h>
#    include <stdlib.h>
#    include <string.h>

#    define GD GLOBAL_DCONTEXT

/* A broken invariant: print enough to reproduce, then abort so libFuzzer
 * saves the input.
 */
#    define FUZZ_CHECK(cond, ...)                                                       \
        do {                                                                            \
            if (!(cond)) {                                                              \
                fprintf(stderr, "FUZZ_CHECK failed: %s:%d: %s\n  ", __FILE__, __LINE__, \
                        #cond);                                                         \
                fprintf(stderr, __VA_ARGS__);                                           \
                fprintf(stderr, "\n");                                                  \
                abort();                                                                \
            }                                                                           \
        } while (0)

/* How the harness treats CLIENT_ASSERTs (API usage errors) raised inside the
 * library.  Harnesses that build instructions from fuzzer bytes can trip
 * usage checks legitimately and set this to true, which mimics a release
 * build where those checks are compiled out.  Setting the environment
 * variable DR_FUZZ_STRICT_CLIENT_ASSERTS=1 overrides it.  Internal ASSERTs
 * are always findings.  Both hooks are in fuzz_hooks.c.
 */
extern bool fuzz_ignore_client_asserts;

/* Known, already-reported bugs a harness can step around so a campaign finds
 * new ones instead of rediscovering these.  DR_FUZZ_KNOWN is a comma-separated
 * list of the names below (or "all"); by default nothing is skipped, so the
 * seed-corpus tests fail until the bugs are fixed.  See README.md.
 *   sve-vl-gt-512         VLs above 512 overflow dr_mcontext_t's Z/P slots
 *   disas-bufsz-0         disassembling into a 0-byte buffer writes buf[-1]
 *   disas-arm-syntax      DR_DISASM_ARM hits ASSERT_NOT_REACHED on A64
 *   addr-null-out         instr_compute_address_ex(addr=NULL) on SVE gathers
 *   addr-sve-prefetch     SVE prefetch vector addressing asserts
 *   xzr-reg-value         reg_get_value*() rejects XZR/WZR (e.g. as an index)
 *   mov-constant-shift    instr_is_mov_constant() ignores movz/movn's shift
 *   memtag-disp-shift     decoding STG/LDG/STGP with a negative offset left-
 *                         shifts a negative int (UB)
 *   reg-value-ex          reg_{get,set}_value_ex() send W/V/FFR/system
 *                         registers to the pointer-sized path (assert / bad
 *                         write) though they document SIMD support
 *   disas-float-range     drdecode prints FP immediates >= 2^32 or NaN via an
 *                         out-of-range float-to-uint conversion (UB)
 *   ffr-implicit          RDFFR/WRFFR's implicit FFR use is missing or
 *                         reversed in the register-use queries
 */
static inline bool
fuzz_known(const char *name)
{
    static const char *known;
    if (known == NULL) {
        known = getenv("DR_FUZZ_KNOWN");
        if (known == NULL)
            known = "";
    }
    if (strcmp(known, "all") == 0)
        return true;
    size_t len = strlen(name);
    for (const char *p = strstr(known, name); p != NULL; p = strstr(p + 1, name)) {
        if ((p == known || p[-1] == ',') && (p[len] == ',' || p[len] == '\0'))
            return true;
    }
    return false;
}

/* Whether decoding this word is known to hit a listed bug before any check. */
static inline bool
fuzz_word_known(uint word)
{
    if (fuzz_known("memtag-disp-shift")) {
        /* LDG/STG/STZG/ST2G/STZ2G/LDGM/STGM... and STGP. */
        if ((word & 0xff200000) == 0xd9200000)
            return true;
        uint stgp = word & 0xffc00000;
        if (stgp == 0x68800000 || stgp == 0x69000000 || stgp == 0x69800000)
            return true;
    }
    return false;
}

/* The SVE vector lengths (in bits) that dr_set_vector_length() accepts. */
static const int fuzz_sve_vls[] = { 128,  256,  384,  512,  640,  768,  896,  1024,
                                    1152, 1280, 1408, 1536, 1664, 1792, 1920, 2048 };
#    define FUZZ_NUM_SVE_VLS (sizeof(fuzz_sve_vls) / sizeof(fuzz_sve_vls[0]))

/* Consumes bytes from the front of the fuzzer input.  Reads past the end
 * return zeros so harnesses never need to special-case short inputs.
 */
typedef struct {
    const uint8_t *data;
    size_t size;
} fuzz_input_t;

static inline uint8_t
fuzz_u8(fuzz_input_t *in)
{
    if (in->size == 0)
        return 0;
    uint8_t v = in->data[0];
    in->data++;
    in->size--;
    return v;
}

static inline uint32_t
fuzz_u32(fuzz_input_t *in)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++)
        v |= (uint32_t)fuzz_u8(in) << (8 * i);
    return v;
}

static inline uint64_t
fuzz_u64(fuzz_input_t *in)
{
    uint64_t lo = fuzz_u32(in);
    return lo | ((uint64_t)fuzz_u32(in) << 32);
}

static inline bool
fuzz_vl_allowed(int vl)
{
    if (fuzz_known("sve-vl-gt-512") && vl > 512)
        return false;
    return true;
}

/* Sets the SVE vector length to the idx-th allowed length. */
static inline int
fuzz_set_vl(int idx)
{
    int allowed[FUZZ_NUM_SVE_VLS], num = 0;
    for (size_t i = 0; i < FUZZ_NUM_SVE_VLS; i++) {
        if (fuzz_vl_allowed(fuzz_sve_vls[i]))
            allowed[num++] = fuzz_sve_vls[i];
    }
    int vl = allowed[idx % num];
    bool ok = dr_set_vector_length(vl);
    FUZZ_CHECK(ok, "dr_set_vector_length(%d) rejected a legal length", vl);
    return vl;
}

/* Disassembles into a buffer and checks that the bytes after the reported
 * length are untouched and that the string is NUL-terminated within bufsz.
 * ASan catches overruns of the heap block itself; the canary catches writes
 * that stay inside it.
 */
static inline void
fuzz_check_instr_disassembly(instr_t *instr, size_t bufsz)
{
    const size_t slack = 16;
    char *buf = (char *)malloc(bufsz + slack);
    memset(buf, 0xa5, bufsz + slack);
    size_t len = instr_disassemble_to_buffer(GD, instr, buf, bufsz);
    if (bufsz > 0) {
        FUZZ_CHECK(len < bufsz, "instr_disassemble_to_buffer returned %zu for bufsz %zu",
                   len, bufsz);
        FUZZ_CHECK(buf[len] == '\0', "disassembly not NUL-terminated at %zu", len);
        FUZZ_CHECK(strlen(buf) == len, "strlen %zu != reported %zu", strlen(buf), len);
    }
    for (size_t i = bufsz; i < bufsz + slack; i++) {
        FUZZ_CHECK((uint8_t)buf[i] == 0xa5, "disassembly wrote byte %zu past bufsz %zu",
                   i - bufsz, bufsz);
    }
    free(buf);
}

/* One-time standalone-decoder setup shared by all harnesses. */
static inline void
fuzz_init_once(void)
{
    static bool initialized;
    if (initialized)
        return;
    initialized = true;
    /* drdecode needs no dr_standalone_init(); just pin the ISA mode. */
    dr_set_isa_mode(GD, DR_ISA_ARM_A64, NULL);
}

#endif /* _FUZZ_COMMON_H_ */

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

/* C interface between tool.drcacheoff.a64_prop_trace's oracle (a64_prop_trace.c)
 * and its drmemtrace post-processing and reading (a64_prop_trace_reader.cpp).
 */

#ifndef A64_PROP_TRACE_H
#define A64_PROP_TRACE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { A64PT_NONE, A64PT_INSTR, A64PT_DATA, A64PT_FLUSH, A64PT_MARKER, A64PT_OTHER };

/* Record types (the reader maps trace_type_t and trace_marker_type_t onto these,
 * so that the C oracle does not depend on the C++ headers).
 */
enum {
    /* Instructions. */
    A64PT_T_INSTR,
    A64PT_T_DIRECT_JUMP,
    A64PT_T_INDIRECT_JUMP,
    A64PT_T_CONDITIONAL_JUMP,
    A64PT_T_DIRECT_CALL,
    A64PT_T_INDIRECT_CALL,
    A64PT_T_RETURN,
    A64PT_T_TAKEN_JUMP,
    A64PT_T_UNTAKEN_JUMP,
    A64PT_T_INSTR_OTHER,
    /* Data and flushes. */
    A64PT_T_READ,
    A64PT_T_WRITE,
    A64PT_T_PREFETCH, /* the generic TRACE_TYPE_PREFETCH */
    /* Load, instruction and store prefetches to L1, L1 non-temporal, L2, ...:
     * A64PT_T_PF_BASE + 6 * kind (0 load, 1 instr, 2 store) + 2 * level +
     * non-temporal.
     */
    A64PT_T_PF_BASE,
    A64PT_T_PF_LAST = A64PT_T_PF_BASE + 17,
    A64PT_T_PREFETCH_OTHER,
    A64PT_T_DATA_FLUSH,
    A64PT_T_INSTR_FLUSH,
    A64PT_T_DATA_OTHER,
    /* Markers. */
    A64PT_M_KERNEL_EVENT,
    A64PT_M_KERNEL_XFER,
    A64PT_M_TIMESTAMP,
    A64PT_M_CPU_ID,
    A64PT_M_SYSCALL,
    A64PT_M_MAYBE_BLOCKING_SYSCALL,
    A64PT_M_SYSCALL_FAILED,
    A64PT_M_FUNC,
    A64PT_M_UNCOMPLETED_INSTRUCTION,
    A64PT_M_RSEQ_ABORT,
    A64PT_M_SIGNAL_NUMBER,
    A64PT_M_SKIPPED_MEMREF,
    A64PT_M_OTHER,
    A64PT_T_UNKNOWN,
};

/* One trace record, flattened. */
typedef struct {
    uint8_t kind;      /* A64PT_* */
    uint8_t enc_new;   /* instr: encoding_is_new */
    uint16_t type;     /* A64PT_T_* or A64PT_M_* */
    uint16_t raw_type; /* the trace_type_t, or the trace_marker_type_t */
    uint16_t pad;
    uint32_t size; /* instr length, or data/flush size */
    uint32_t enc;  /* instr: the first 4 encoding bytes */
    uint64_t tid;
    uint64_t pc;   /* instr pc, or the pc of a data/flush record */
    uint64_t addr; /* data/flush address, marker value, or an instr's
                    * indirect_branch_target */
} a64pt_rec_t;

typedef struct {
    long ninstrs, ndata;
    long nbad_pc; /* instructions outside the allowed ranges and [lo, hi) */
    uint64_t first_bad_pc;
    long ncode_outside_runs; /* instructions in [lo, hi) outside runs */
    uint64_t first_code_outside_runs;
    int nthreads;
} a64pt_stats_t;

/* Runs raw2trace on the single drmemtrace.*.dir/raw under outdir, writing to
 * .../trace, whose path goes to trace_dir.  Returns 0 (with err) on failure.
 */
int
a64pt_post_process(const char *outdir, char *trace_dir, size_t trace_dir_len, char *err,
                   size_t errlen);

/* Reads the final trace in trace_dir.  Keeps every record of each "run": from
 * an instruction at start_pc to the next instruction at end_pc, both included.
 * Counts instructions whose pc is neither in the code [lo, hi) nor in one of
 * the nranges [ranges[2i], ranges[2i+1]), and instructions in the code outside
 * runs.  Returns the number of records kept (malloc'ed into *recs) or -1
 * (with err).
 */
long
a64pt_read(const char *trace_dir, uint64_t lo, uint64_t hi, uint64_t start_pc,
           uint64_t end_pc, const uint64_t *ranges, int nranges, a64pt_rec_t **recs,
           a64pt_stats_t *st, char *err, size_t errlen);

/* The name of a raw trace_type_t (not for markers). */
const char *
a64pt_type_name(int raw_type);

#ifdef __cplusplus
}
#endif

#endif /* A64_PROP_TRACE_H */

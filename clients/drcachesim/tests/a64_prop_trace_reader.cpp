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

/* The drmemtrace side of tool.drcacheoff.a64_prop_trace (see a64_prop_trace.c):
 * offline post-processing (raw2trace) of the tracer's raw files and reading
 * the final trace back through the scheduler, exposed to the C test as plain
 * records.  Nothing here interprets the records: the oracle is in the C file.
 */

#undef DR_REG_ENUM_COMPATIBILITY

#include "dr_api.h"
#include "drmemtrace/raw2trace.h"
#include "raw2trace_directory.h"
#include "scheduler.h"
#include "trace_entry.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <string>
#include <vector>

#include "a64_prop_trace.h"

using namespace dynamorio::drmemtrace;

static void
set_err(char *err, size_t errlen, const std::string &msg)
{
    if (err != nullptr && errlen > 0)
        snprintf(err, errlen, "%s", msg.c_str());
}

extern "C" int
a64pt_post_process(const char *outdir, char *trace_dir, size_t trace_dir_len, char *err,
                   size_t errlen)
{
    /* The tracer made exactly one drmemtrace.*.dir under outdir. */
    std::string logdir;
    DIR *d = opendir(outdir);
    if (d == nullptr) {
        set_err(err, errlen, std::string("cannot open ") + outdir);
        return 0;
    }
    int found = 0;
    while (struct dirent *e = readdir(d)) {
        if (strncmp(e->d_name, "drmemtrace.", 11) == 0) {
            logdir = std::string(outdir) + "/" + e->d_name;
            found++;
        }
    }
    closedir(d);
    if (found != 1) {
        set_err(err, errlen,
                "expected one drmemtrace.*.dir in " + std::string(outdir) + ", found " +
                    std::to_string(found));
        return 0;
    }
    std::string raw = logdir + "/raw", out = logdir + "/trace";
    void *dr_context = dr_standalone_init();
    std::string error;
    {
        raw2trace_directory_t dir;
        if (!dr_create_dir(out.c_str()))
            error = "cannot create " + out;
        if (error.empty())
            error = dir.initialize(raw, out);
        if (error.empty()) {
            raw2trace_t raw2trace(dir.modfile_bytes_, dir.in_files_, dir.out_files_,
                                  dir.out_archives_, dir.encoding_file_,
                                  dir.serial_schedule_file_, dir.cpu_schedule_file_,
                                  dr_context);
            error = raw2trace.do_conversion();
            if (!error.empty())
                error = "raw2trace failed: " + error;
        }
    }
    dr_standalone_exit();
    if (!error.empty()) {
        set_err(err, errlen, error);
        return 0;
    }
    snprintf(trace_dir, trace_dir_len, "%s", out.c_str());
    return 1;
}

static uint16_t
map_type(trace_type_t t)
{
    switch (t) {
    case TRACE_TYPE_INSTR: return A64PT_T_INSTR;
    case TRACE_TYPE_INSTR_DIRECT_JUMP: return A64PT_T_DIRECT_JUMP;
    case TRACE_TYPE_INSTR_INDIRECT_JUMP: return A64PT_T_INDIRECT_JUMP;
    case TRACE_TYPE_INSTR_CONDITIONAL_JUMP: return A64PT_T_CONDITIONAL_JUMP;
    case TRACE_TYPE_INSTR_DIRECT_CALL: return A64PT_T_DIRECT_CALL;
    case TRACE_TYPE_INSTR_INDIRECT_CALL: return A64PT_T_INDIRECT_CALL;
    case TRACE_TYPE_INSTR_RETURN: return A64PT_T_RETURN;
    case TRACE_TYPE_INSTR_TAKEN_JUMP: return A64PT_T_TAKEN_JUMP;
    case TRACE_TYPE_INSTR_UNTAKEN_JUMP: return A64PT_T_UNTAKEN_JUMP;
    case TRACE_TYPE_READ: return A64PT_T_READ;
    case TRACE_TYPE_WRITE: return A64PT_T_WRITE;
    case TRACE_TYPE_PREFETCH: return A64PT_T_PREFETCH;
    case TRACE_TYPE_PREFETCH_READ_L1: return A64PT_T_PF_BASE + 0;
    case TRACE_TYPE_PREFETCH_READ_L1_NT: return A64PT_T_PF_BASE + 1;
    case TRACE_TYPE_PREFETCH_READ_L2: return A64PT_T_PF_BASE + 2;
    case TRACE_TYPE_PREFETCH_READ_L2_NT: return A64PT_T_PF_BASE + 3;
    case TRACE_TYPE_PREFETCH_READ_L3: return A64PT_T_PF_BASE + 4;
    case TRACE_TYPE_PREFETCH_READ_L3_NT: return A64PT_T_PF_BASE + 5;
    case TRACE_TYPE_PREFETCH_INSTR_L1: return A64PT_T_PF_BASE + 6;
    case TRACE_TYPE_PREFETCH_INSTR_L1_NT: return A64PT_T_PF_BASE + 7;
    case TRACE_TYPE_PREFETCH_INSTR_L2: return A64PT_T_PF_BASE + 8;
    case TRACE_TYPE_PREFETCH_INSTR_L2_NT: return A64PT_T_PF_BASE + 9;
    case TRACE_TYPE_PREFETCH_INSTR_L3: return A64PT_T_PF_BASE + 10;
    case TRACE_TYPE_PREFETCH_INSTR_L3_NT: return A64PT_T_PF_BASE + 11;
    case TRACE_TYPE_PREFETCH_WRITE_L1: return A64PT_T_PF_BASE + 12;
    case TRACE_TYPE_PREFETCH_WRITE_L1_NT: return A64PT_T_PF_BASE + 13;
    case TRACE_TYPE_PREFETCH_WRITE_L2: return A64PT_T_PF_BASE + 14;
    case TRACE_TYPE_PREFETCH_WRITE_L2_NT: return A64PT_T_PF_BASE + 15;
    case TRACE_TYPE_PREFETCH_WRITE_L3: return A64PT_T_PF_BASE + 16;
    case TRACE_TYPE_PREFETCH_WRITE_L3_NT: return A64PT_T_PF_BASE + 17;
    case TRACE_TYPE_DATA_FLUSH: return A64PT_T_DATA_FLUSH;
    case TRACE_TYPE_INSTR_FLUSH: return A64PT_T_INSTR_FLUSH;
    default:
        if (type_is_instr(t))
            return A64PT_T_INSTR_OTHER;
        if (type_is_prefetch(t))
            return A64PT_T_PREFETCH_OTHER;
        if (type_is_data(t))
            return A64PT_T_DATA_OTHER;
        return A64PT_T_UNKNOWN;
    }
}

static uint16_t
map_marker(trace_marker_type_t t)
{
    switch (t) {
    case TRACE_MARKER_TYPE_KERNEL_EVENT: return A64PT_M_KERNEL_EVENT;
    case TRACE_MARKER_TYPE_KERNEL_XFER: return A64PT_M_KERNEL_XFER;
    case TRACE_MARKER_TYPE_TIMESTAMP: return A64PT_M_TIMESTAMP;
    case TRACE_MARKER_TYPE_CPU_ID: return A64PT_M_CPU_ID;
    case TRACE_MARKER_TYPE_SYSCALL: return A64PT_M_SYSCALL;
    case TRACE_MARKER_TYPE_MAYBE_BLOCKING_SYSCALL: return A64PT_M_MAYBE_BLOCKING_SYSCALL;
    case TRACE_MARKER_TYPE_SYSCALL_FAILED: return A64PT_M_SYSCALL_FAILED;
    case TRACE_MARKER_TYPE_FUNC_ID:
    case TRACE_MARKER_TYPE_FUNC_RETADDR:
    case TRACE_MARKER_TYPE_FUNC_ARG:
    case TRACE_MARKER_TYPE_FUNC_RETVAL: return A64PT_M_FUNC;
    case TRACE_MARKER_TYPE_UNCOMPLETED_INSTRUCTION:
        return A64PT_M_UNCOMPLETED_INSTRUCTION;
    case TRACE_MARKER_TYPE_RSEQ_ABORT: return A64PT_M_RSEQ_ABORT;
    case TRACE_MARKER_TYPE_SIGNAL_NUMBER: return A64PT_M_SIGNAL_NUMBER;
    default: return A64PT_M_OTHER;
    }
}

static bool
pc_allowed(uint64_t pc, const uint64_t *ranges, int nranges)
{
    for (int i = 0; i < nranges; i++) {
        if (pc >= ranges[2 * i] && pc < ranges[2 * i + 1])
            return true;
    }
    return false;
}

extern "C" long
a64pt_read(const char *trace_dir, uint64_t lo, uint64_t hi, uint64_t start_pc,
           uint64_t end_pc, const uint64_t *ranges, int nranges, a64pt_rec_t **recs_out,
           a64pt_stats_t *st, char *err, size_t errlen)
{
    memset(st, 0, sizeof(*st));
    *recs_out = nullptr;
    scheduler_t scheduler;
    std::vector<scheduler_t::input_workload_t> sched_inputs;
    sched_inputs.emplace_back(trace_dir);
    if (scheduler.init(sched_inputs, 1, scheduler_t::make_scheduler_serial_options()) !=
        scheduler_t::STATUS_SUCCESS) {
        set_err(err, errlen,
                "failed to initialize the scheduler: " + scheduler.get_error_string());
        return -1;
    }
    std::vector<a64pt_rec_t> recs;
    std::vector<memref_tid_t> tids;
    auto *stream = scheduler.get_stream(0);
    memref_t m;
    /* Keep the records of each run: from the instruction at start_pc to the
     * next one at end_pc, both included.
     */
    bool in_run = false;
    for (scheduler_t::stream_status_t status = stream->next_record(m);
         status != scheduler_t::STATUS_EOF; status = stream->next_record(m)) {
        if (status == scheduler_t::STATUS_WAIT || status == scheduler_t::STATUS_IDLE)
            continue;
        if (status != scheduler_t::STATUS_OK) {
            set_err(err, errlen, "reader error " + std::to_string(status));
            return -1;
        }
        a64pt_rec_t r;
        memset(&r, 0, sizeof(r));
        r.tid = (uint64_t)m.instr.tid;
        if (type_is_instr(m.instr.type) || m.instr.type == TRACE_TYPE_INSTR_NO_FETCH) {
            if (std::find(tids.begin(), tids.end(), m.instr.tid) == tids.end())
                tids.push_back(m.instr.tid);
            r.kind = A64PT_INSTR;
            r.type = map_type(m.instr.type);
            r.raw_type = (uint16_t)m.instr.type;
            r.pc = m.instr.addr;
            r.size = (uint32_t)m.instr.size;
            memcpy(&r.enc, m.instr.encoding, sizeof(r.enc));
            r.enc_new = m.instr.encoding_is_new ? 1 : 0;
            r.addr = m.instr.indirect_branch_target;
            st->ninstrs++;
            bool in_code = r.pc >= lo && r.pc < hi;
            if (!pc_allowed(r.pc, ranges, nranges) && !in_code) {
                if (st->nbad_pc == 0)
                    st->first_bad_pc = r.pc;
                st->nbad_pc++;
            }
            if (!in_run && r.pc == start_pc)
                in_run = true;
            if (in_run)
                recs.push_back(r);
            else if (in_code) {
                if (st->ncode_outside_runs == 0)
                    st->first_code_outside_runs = r.pc;
                st->ncode_outside_runs++;
            }
            if (in_run && r.pc == end_pc)
                in_run = false;
            continue;
        }
        if (type_is_data(m.data.type)) {
            r.kind = (m.data.type == TRACE_TYPE_DATA_FLUSH ||
                      m.data.type == TRACE_TYPE_INSTR_FLUSH)
                ? A64PT_FLUSH
                : A64PT_DATA;
            r.type = map_type(m.data.type);
            r.raw_type = (uint16_t)m.data.type;
            r.pc = m.data.pc;
            r.addr = m.data.addr;
            r.size = (uint32_t)m.data.size;
            st->ndata++;
        } else if (m.marker.type == TRACE_TYPE_MARKER) {
            r.kind = A64PT_MARKER;
            r.type = map_marker(m.marker.marker_type);
            r.raw_type = (uint16_t)m.marker.marker_type;
            r.addr = m.marker.marker_value;
        } else {
            r.kind = A64PT_OTHER;
            r.type = A64PT_T_UNKNOWN;
            r.raw_type = (uint16_t)m.instr.type;
        }
        if (in_run)
            recs.push_back(r);
    }
    st->nthreads = (int)tids.size();
    a64pt_rec_t *out = (a64pt_rec_t *)malloc(sizeof(a64pt_rec_t) * (recs.size() + 1));
    if (out == nullptr) {
        set_err(err, errlen, "out of memory");
        return -1;
    }
    if (!recs.empty())
        memcpy(out, recs.data(), sizeof(a64pt_rec_t) * recs.size());
    *recs_out = out;
    return (long)recs.size();
}

extern "C" const char *
a64pt_type_name(int raw_type)
{
    if (raw_type < 0 || raw_type > TRACE_TYPE_INVALID)
        return "?";
    return trace_type_names[raw_type];
}

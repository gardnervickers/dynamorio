# **********************************************************
# Copyright (c) 2026 Google, Inc.    All rights reserved.
# **********************************************************

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of Google, Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

# Benchmarks and guards for the cost of DR's AArch64 code generation: see
# README.md here.  Included from suite/tests/CMakeLists.txt on AArch64 Linux.
# The tests get the "a64_codegen" ctest label at the end of that file, and
# "ninja a64_codegen_tests && ctest -L a64_codegen" builds and runs them.  The
# guards fail the test; the benchmark numbers are only printed.

# Decode, encode and flags queries over libc's text and random words.
if (DEBUG)
  # Debug DR's benchmark numbers mean little, and its encoder reports every
  # instruction the host cannot encode, as the benchmark corpus is filtered:
  # only the guards.
  set(a64_codegen_ir_ops "-guard-only")
  set(api.a64_codegen_ir_timeout 600)
else ()
  set(a64_codegen_ir_ops "")
  set(api.a64_codegen_ir_timeout 300)
endif ()
# Static DR: the test sets up DR (without running under it) to use a real
# thread's drcontext.
tobuild_api(api.a64_codegen_ir api/a64_codegen_ir.c "" "${a64_codegen_ir_ops}"
  OFF ON OFF)
# The same with the shared library in standalone mode, as offline decoders use it.
set(a64_codegen_ir_shared_ops -standalone ${a64_codegen_ir_ops})
tobuild_api(api.a64_codegen_ir_shared api/a64_codegen_ir.c ""
  "${a64_codegen_ir_shared_ops}" OFF OFF OFF)
set(api.a64_codegen_ir_shared_timeout ${api.a64_codegen_ir_timeout})

# Building and running chains of blocks under static DR, in a child per client
# mode and DR option set.
if (DEBUG AND NOT A64_LONG_TESTS)
  # Debug DR's benchmark numbers mean little, and its time goes to the verbatim
  # guard's translations (dr_app_pc_from_cache_pc() rebuilds the block) and to
  # building blocks: by default, one copy of the chain for the build benchmark
  # (so no check that copies are the same size), few exec runs, the verbatim
  # guard on every 16th block, and half the fault chain, which still has every
  # position and kind of fault once without the marker and once with it.
  # Under a minute; about 5 minutes with A64_LONG_TESTS, as before.
  set(a64_codegen_build_ops "-reps;1;-runs;20;-verbatim-stride;16;-fault-blocks;162")
  set(api.a64_codegen_build_timeout 600)
elseif (DEBUG)
  set(a64_codegen_build_ops "-fault-blocks;162")
  set(api.a64_codegen_build_timeout 900)
else ()
  set(a64_codegen_build_ops "")
  set(api.a64_codegen_build_timeout 300)
endif ()
tobuild_api(api.a64_codegen_build api/a64_codegen_build.c "" "${a64_codegen_build_ops}"
  OFF ON OFF)
use_DynamoRIO_extension(api.a64_codegen_build drmgr_static)
use_DynamoRIO_extension(api.a64_codegen_build drreg_static)

# The scaling test: the same binary building 300k blocks per configuration in
# release, with Seedbox's options.  The code is all in one writable mapping, as a
# JIT's, and every block also calls one shared stub, so the stub's incoming-link
# list grows with the cache.  After each bucket of 100k blocks a line is flushed
# in each of 4 chains; a flush must not make more blocks build again than a
# -sw_flush_granule region holds, twice over ("auto"), which, unlike the times,
# does not depend on the machine.  Debug runs it small.
#
# The timing guard (fail if the last bucket costs over 1.5x as much per block as
# the first: a cost that grows with the size of the code cache, as fcache's free
# lists once did, 62f76c5f4) needs a quiet machine: a slowdown of the whole last
# bucket, from throttling or contention, fails it too.  It is off unless
# A64_CODEGEN_TIMING_GUARD is set.
option(A64_CODEGEN_TIMING_GUARD
  "api.a64_codegen_scale also fails on a growth in time per block" OFF)
if (DEBUG)
  set(a64_codegen_scale_ops
    "-scale;20000;-bucket;10000;-slice;5000;-modes;dr,progress;-ops;seedbox;-layout;onemap,rwx,fanin;-flushes;2;-flush-limit;auto")
  set(api.a64_codegen_scale_timeout 900)
else ()
  set(a64_codegen_scale_ops
    "-scale;300000;-bucket;100000;-modes;dr,progress;-ops;seedbox;-layout;onemap,rwx,fanin;-flushes;4;-flush-limit;auto")
  if (A64_CODEGEN_TIMING_GUARD)
    set(a64_codegen_scale_ops "${a64_codegen_scale_ops};-scale-guard")
  endif ()
  set(api.a64_codegen_scale_timeout 300)
endif ()
torunonly_api(api.a64_codegen_scale api.a64_codegen_build api/a64_codegen_build.c ""
  "${a64_codegen_scale_ops}" OFF OFF)

# Patching code as a JIT does: a block across a page boundary, patched and
# invalidated with IC IVAU (or, with hardware cache consistency, found by the
# write) while worker threads run it.  An ADD on either side, in phases (the
# workers wait while it is rewritten), and a B retargeted while they run it;
# nobody may run code older than the patch they have seen published, and every
# worker checks every patch.
if (DEBUG)
  set(a64_codegen_patch_ops "-patch;200;-threads;2;-modes;dr;-ops;default,seedbox")
  set(api.a64_codegen_patch_timeout 900)
else ()
  set(a64_codegen_patch_ops
    "-patch;1000;-threads;3;-modes;dr,progress;-ops;default,seedbox")
  set(api.a64_codegen_patch_timeout 300)
endif ()
torunonly_api(api.a64_codegen_patch api.a64_codegen_build api/a64_codegen_build.c ""
  "${a64_codegen_patch_ops}" OFF OFF)

# After a flush, an indirect branch must not reach a deleted fragment through an
# ibl table: a hot indirect target, a trace with traces on, patched and flushed
# with all threads synched.  Without traces (Seedbox's options) and with traces
# in shared bb and trace ibl tables.  (Shared bb with private trace tables
# crashes in this test on 62f76c5f4 and since: PROGRESS.md.)
if (DEBUG)
  # Traces of writable code with shared bb ibl tables trip a debug assert
  # (monitor.c's unlink_ibt_trace_head(): a private trace head) on 62f76c5f4 too.
  set(a64_codegen_ibl_ops "-ibl;10;-modes;dr;-ops;seedbox")
  set(api.a64_codegen_ibl_timeout 900)
else ()
  set(a64_codegen_ibl_ops "-ibl;20;-modes;dr,progress;-ops;seedbox,ibtraces_shared")
  set(api.a64_codegen_ibl_timeout 300)
endif ()
torunonly_api(api.a64_codegen_ibl api.a64_codegen_build api/a64_codegen_build.c ""
  "${a64_codegen_ibl_ops}" OFF OFF)

set(a64_codegen_testnames api.a64_codegen_ir api.a64_codegen_ir_shared
  api.a64_codegen_build api.a64_codegen_scale api.a64_codegen_patch
  api.a64_codegen_ibl)
add_custom_target(a64_codegen_tests)
add_dependencies(a64_codegen_tests api.a64_codegen_ir api.a64_codegen_ir_shared
  api.a64_codegen_build)

include("${CMAKE_CURRENT_SOURCE_DIR}/a64_codegen/client.a64_cleancall_ool.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/a64_codegen/client.a64_mops.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/a64_codegen/client.a64_emit_decoded.cmake")

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

# Building and running chains of blocks under static DR, in a child per client
# mode and DR option set.
tobuild_api(api.a64_codegen_build api/a64_codegen_build.c "" "" OFF ON OFF)
use_DynamoRIO_extension(api.a64_codegen_build drmgr_static)
use_DynamoRIO_extension(api.a64_codegen_build drreg_static)
if (DEBUG)
  set(api.a64_codegen_build_timeout 900)
else ()
  set(api.a64_codegen_build_timeout 300)
endif ()

# The scaling guard: the same binary building 300k blocks per configuration in
# release, with Seedbox's options, which fails if the last 100k cost over 1.5x as
# much per block as the first: a cost that grows with the size of the code
# cache, as fcache's free lists once did (62f76c5f4).  Debug DR's costs are its
# checks', so there it only runs the mode, small, with flushes, and guards the
# results.
if (DEBUG)
  set(a64_codegen_scale_ops
    "-scale;20000;-bucket;10000;-slice;5000;-modes;dr,progress;-ops;default,seedbox;-flushes;2")
  set(api.a64_codegen_scale_timeout 900)
else ()
  set(a64_codegen_scale_ops
    "-scale;300000;-bucket;100000;-modes;dr,progress;-ops;seedbox;-scale-guard")
  set(api.a64_codegen_scale_timeout 300)
endif ()
torunonly_api(api.a64_codegen_scale api.a64_codegen_build api/a64_codegen_build.c ""
  "${a64_codegen_scale_ops}" OFF OFF)

set(a64_codegen_testnames api.a64_codegen_ir api.a64_codegen_build
  api.a64_codegen_scale)
add_custom_target(a64_codegen_tests)
add_dependencies(a64_codegen_tests api.a64_codegen_ir api.a64_codegen_build)

include("${CMAKE_CURRENT_SOURCE_DIR}/a64_codegen/client.a64_cleancall_ool.cmake")

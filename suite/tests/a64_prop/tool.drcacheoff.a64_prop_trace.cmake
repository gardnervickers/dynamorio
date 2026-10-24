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

# End-to-end property of the offline pipeline (tracer, raw2trace, reader) on
# generated AArch64 code, with the native CPU and the a64_dr_prop generator's
# access model as the oracle: see clients/drcachesim/tests/a64_prop_trace.c.
if (BUILD_CLIENTS AND NOT ANDROID)
  set(a64pt_dir ${PROJECT_SOURCE_DIR}/clients/drcachesim/tests)
  add_api_exe(tool.drcacheoff.a64_prop_trace
    ${a64pt_dir}/a64_prop_trace_reader.cpp OFF ON)
  set_cflags(${a64pt_dir}/a64_prop_trace.c)
  target_sources(tool.drcacheoff.a64_prop_trace PRIVATE
    ${a64pt_dir}/a64_prop_trace.c "${a64_prop_support_c}")
  use_DynamoRIO_static_client(tool.drcacheoff.a64_prop_trace drmemtrace_static)
  use_DynamoRIO_drmemtrace_tracer(tool.drcacheoff.a64_prop_trace)
  target_link_libraries(tool.drcacheoff.a64_prop_trace drmemtrace_raw2trace
    drmemtrace_analyzer test_helpers)
  link_with_pthread(tool.drcacheoff.a64_prop_trace)
  target_include_directories(tool.drcacheoff.a64_prop_trace PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/api"
    "${PROJECT_SOURCE_DIR}/clients/drcachesim"
    "${PROJECT_SOURCE_DIR}/clients/drcachesim/common"
    "${PROJECT_SOURCE_DIR}/clients/drcachesim/reader"
    "${PROJECT_SOURCE_DIR}/clients/drcachesim/tracer"
    "${PROJECT_SOURCE_DIR}/clients/drcachesim/scheduler")
  # 128 blocks per variant at full size, which takes minutes against a debug DR:
  # by default the test runs against a release DR only.
  if (A64_LONG_TESTS OR NOT DEBUG)
    a64_prop_args(a64pt_args SHORT -n 16 LONG "")
    torunonly_api(tool.drcacheoff.a64_prop_trace tool.drcacheoff.a64_prop_trace
      ${a64pt_dir}/a64_prop_trace.c "" "${a64pt_args}" OFF OFF)
    set(tool.drcacheoff.a64_prop_trace_basedir ${a64pt_dir})
    set(tool.drcacheoff.a64_prop_trace_timeout 300)
    a64_prop_register(TESTS tool.drcacheoff.a64_prop_trace
      TARGETS tool.drcacheoff.a64_prop_trace)
  endif ()
endif ()

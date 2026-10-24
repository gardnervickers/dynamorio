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

# The AArch64 real-workload smoke gate, and the client it runs: see README.md
# here.  Included from suite/tests/CMakeLists.txt on AArch64 Linux.

# An instruction-budget client in the shape of Seedbox's progress client, for
# the smoke tests and for other stress tests that want DR under a realistic
# client: see client-interface/a64_progress_like.dll.c for its options.
add_library(client.a64_progress_like.dll SHARED
  client-interface/a64_progress_like.dll.c)
setup_test_client_dll_basics(client.a64_progress_like.dll)
use_DynamoRIO_extension(client.a64_progress_like.dll drmgr)
use_DynamoRIO_extension(client.a64_progress_like.dll drreg)

# The real-workload smoke gate (README.md): each workload runs natively, then
# under drrun with Seedbox's options and the client above, pinned to one CPU,
# and must print the same output.  A test whose toolchain was not found at
# configure time is still added, and reports itself skipped.
#
# By default (for CI) only a release build has the gate, at Seedbox's budget,
# with one run under DR per workload; A64_LONG_TESTS (suite/tests/CMakeLists.txt)
# adds the small budget, the repeated runs and the debug build.
set(A64_SMOKE_BUDGETS "" CACHE STRING
  "instructions per progress call for the a64_smoke tests, one test per budget (empty: 50000, or 1000;50000 with A64_LONG_TESTS)")
if (A64_SMOKE_BUDGETS)
  set(a64_smoke_budgets ${A64_SMOKE_BUDGETS})
elseif (A64_LONG_TESTS)
  set(a64_smoke_budgets 1000 50000)
else ()
  set(a64_smoke_budgets 50000)
endif ()
set(A64_SMOKE_CPU 0 CACHE STRING "the CPU the a64_smoke tests are pinned to")
set(a64_smoke_src ${CMAKE_CURRENT_SOURCE_DIR}/a64_smoke)
set(a64_smoke_out ${CMAKE_CURRENT_BINARY_DIR}/a64_smoke)
set(a64_smoke_targets drrun client.a64_progress_like.dll)
if (DEBUG AND NOT A64_LONG_TESTS)
  message(STATUS "Debug build without A64_LONG_TESTS: the a64_smoke tests are not defined")
  # "ninja a64_smoke_tests" still builds the client (jvm.cmake's tests use it).
  add_custom_target(a64_smoke_tests)
  add_dependencies(a64_smoke_tests ${a64_smoke_targets})
  return ()
endif ()

# a64_smoke_test(NAME REPS TIMEOUT SKIP_REASON COMMAND...): a test per budget,
# named a64_smoke.NAME.b<budget>, with REPS runs under DR (one without
# A64_LONG_TESTS).
function(a64_smoke_test name reps timeout skip)
  if (NOT A64_LONG_TESTS)
    set(reps 1)
  endif ()
  foreach (budget ${a64_smoke_budgets})
    set(test a64_smoke.${name}.b${budget})
    if (skip)
      set(skip_args -skip "${skip}")
    else ()
      set(skip_args "")
    endif ()
    add_test(NAME ${test}
      COMMAND bash ${a64_smoke_src}/run_smoke.sh -name ${test}
        -logdir ${a64_smoke_out}/logs -drrun $<TARGET_FILE:drrun>
        -client $<TARGET_FILE:client.a64_progress_like.dll>
        -client_args "--instructions-per-progress-call ${budget} --progress-points-per-block 1"
        -cpu ${A64_SMOKE_CPU} -timeout ${timeout} -reps ${reps} ${skip_args}
        -- ${ARGN})
    math(EXPR ctest_timeout "(${reps} + 1) * ${timeout} + 60")
    # Pinned to one CPU: running two at once would only slow both down.
    set_tests_properties(${test} PROPERTIES LABELS a64_smoke SKIP_RETURN_CODE 77
      TIMEOUT ${ctest_timeout} RUN_SERIAL ON)
  endforeach ()
endfunction ()

# Debug DR is several times slower: same workloads, longer limits.
if (DEBUG)
  set(a64_smoke_timeout 1200)
else ()
  set(a64_smoke_timeout 300)
endif ()

# C: code rewritten and flushed while other threads run it and take signals,
# and ldxr/stxr loops across flushes.
add_executable(a64_smoke_jit ${a64_smoke_src}/jit_signals.c)
set_target_properties(a64_smoke_jit PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${a64_smoke_out})
link_with_pthread(a64_smoke_jit)
list(APPEND a64_smoke_targets a64_smoke_jit)
a64_smoke_test(c_flush 1 ${a64_smoke_timeout} "" $<TARGET_FILE:a64_smoke_jit> flush 10000)
a64_smoke_test(c_jit 2 ${a64_smoke_timeout} "" $<TARGET_FILE:a64_smoke_jit> jit 3000)
a64_smoke_test(c_exclusive 2 ${a64_smoke_timeout} ""
  $<TARGET_FILE:a64_smoke_jit> exclusive 2000)

# Go: the runtime's own threads, signals, stacks and collector, and many child
# processes, each a fresh runtime start under DR.  Built with the Go found at
# configure time, offline (GOTOOLCHAIN=local, no dependencies).
find_program(A64_SMOKE_GO go DOC "Go toolchain for the a64_smoke Go workload")
if (A64_SMOKE_GO)
  execute_process(COMMAND ${A64_SMOKE_GO} env GOVERSION
    OUTPUT_VARIABLE go_version OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
endif ()
if (A64_SMOKE_GO AND go_version MATCHES "^go([0-9]+\\.[0-9]+)")
  # The module is written here, declaring the toolchain's own language
  # version, so the runtime runs with that release's default settings (the
  # GOMAXPROCS updater, for one), as programs built for it do.
  set(a64_smoke_go_dir ${a64_smoke_out}/go)
  file(WRITE ${a64_smoke_go_dir}/go.mod "module a64smoke\n\ngo ${CMAKE_MATCH_1}\n")
  set(a64_smoke_go_bin ${a64_smoke_out}/a64_smoke_go)
  add_custom_command(OUTPUT ${a64_smoke_go_bin}
    COMMAND ${CMAKE_COMMAND} -E copy ${a64_smoke_src}/go/main.go ${a64_smoke_go_dir}/
    COMMAND ${CMAKE_COMMAND} -E env CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=mod
      GOCACHE=${a64_smoke_out}/gocache GOPATH=${a64_smoke_out}/gopath
      ${A64_SMOKE_GO} build -trimpath -o ${a64_smoke_go_bin} .
    WORKING_DIRECTORY ${a64_smoke_go_dir}
    DEPENDS ${a64_smoke_src}/go/main.go
    COMMENT "Building the a64_smoke Go workload"
    VERBATIM)
  add_custom_target(a64_smoke_go ALL DEPENDS ${a64_smoke_go_bin})
  list(APPEND a64_smoke_targets a64_smoke_go)
  set(go_skip "")
else ()
  set(a64_smoke_go_bin go-not-found)
  set(go_skip "no usable go toolchain found at configure time")
endif ()
a64_smoke_test(go 3 ${a64_smoke_timeout} "${go_skip}" ${a64_smoke_go_bin} 1 96)

# Python: CPython threads handing the GIL over every 200us.
find_program(A64_SMOKE_PYTHON python3 DOC "python3 for the a64_smoke Python workload")
if (A64_SMOKE_PYTHON)
  set(py_skip "")
else ()
  set(A64_SMOKE_PYTHON python3-not-found)
  set(py_skip "no python3 found at configure time")
endif ()
a64_smoke_test(python 3 ${a64_smoke_timeout} "${py_skip}"
  ${A64_SMOKE_PYTHON} ${a64_smoke_src}/gil_threads.py 6 20000)

# "ninja a64_smoke_tests && ctest -L a64_smoke" builds and runs the gate.
add_custom_target(a64_smoke_tests)
add_dependencies(a64_smoke_tests ${a64_smoke_targets})

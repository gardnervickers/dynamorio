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

# libFuzzer harnesses for the AArch64 IR (decoder, encoder, disassembler and
# operand/instr queries).  See README.md for how to build and run them.
#
# With clang, each harness links -fsanitize=fuzzer.  Otherwise (or with
# FUZZ_ENGINE=replay) it links replay_main.c, which just runs saved inputs, so
# the seed corpus and crash reproducers still run as ordinary tests.

cmake_minimum_required(VERSION 3.14)

if (NOT AARCH64)
  message(FATAL_ERROR "suite/fuzz currently only targets AArch64")
endif ()
if (NOT DEBUG)
  message(WARNING "BUILD_FUZZERS without DEBUG: CLIENT_ASSERT checks are compiled out")
endif ()

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(FUZZ_ENGINE_DEFAULT "libfuzzer")
else ()
  set(FUZZ_ENGINE_DEFAULT "replay")
endif ()
set(FUZZ_ENGINE "${FUZZ_ENGINE_DEFAULT}" CACHE STRING
  "libfuzzer: link -fsanitize=fuzzer; replay: link a driver that only runs saved inputs")

# Known, not-yet-fixed issues the tests step around (see DR_FUZZ_KNOWN in
# fuzz_common.h).  None are open.
set(FUZZ_KNOWN_ISSUES "" CACHE STRING
  "DR_FUZZ_KNOWN value for the fuzz.* tests")

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build fuzzers")
endif ()

# Must run at directory scope before the per-target setup below.
configure_DynamoRIO_global(OFF OFF)

find_package(Python3 COMPONENTS Interpreter)

set(seed_dir "${CMAKE_CURRENT_BINARY_DIR}/seeds")
file(GLOB dis_a64_files "${PROJECT_SOURCE_DIR}/suite/tests/api/dis-a64*.txt")

function (add_a64_fuzzer name)
  # The encode harness builds and resizes operand lists itself, so leaks there
  # are harness or IR bugs: check for them (regressions/a64_encode_fuzzer/
  # set-num-opnds-leak).
  if (name STREQUAL "a64_encode_fuzzer")
    set(leaks 1)
  else ()
    set(leaks 0)
  endif ()
  # gcc's ASan detects stack use after return by default, which makes the
  # semantics seeds (a few million register queries) take over 25 minutes
  # instead of 20 seconds.
  set(asan "ASAN_OPTIONS=detect_leaks=${leaks}:detect_stack_use_after_return=0")
  set(srcs ${name}.c fuzz_hooks.c)
  if (NOT FUZZ_ENGINE STREQUAL "libfuzzer")
    set(srcs ${srcs} replay_main.c)
  endif ()
  add_executable(${name} ${srcs})
  # Built by the top-level a64_prop_tests target, with the "a64_prop" ctests.
  set_property(GLOBAL APPEND PROPERTY DR_A64_PROP_TARGETS ${name})
  # As configure_DynamoRIO_decoder(), but against the assert-enabled library.
  DynamoRIO_extra_cflags(extra_cflags "" OFF)
  _DR_append_property_string(TARGET ${name} COMPILE_FLAGS "${extra_cflags}")
  DynamoRIO_extra_defines(extra_defs OFF)
  _DR_append_property_list(TARGET ${name} COMPILE_DEFINITIONS "${extra_defs}")
  target_link_libraries(${name} drdecode_fuzz)
  add_dependencies(${name} api_headers)
  _DR_append_property_string(TARGET ${name} COMPILE_FLAGS "${FUZZ_SANITIZER_FLAGS}")
  if (FUZZ_ENGINE STREQUAL "libfuzzer")
    _DR_append_property_string(TARGET ${name} LINK_FLAGS
      "${FUZZ_SANITIZER_FLAGS} -fsanitize=fuzzer")
  else ()
    _DR_append_property_string(TARGET ${name} LINK_FLAGS "${FUZZ_SANITIZER_FLAGS}")
  endif ()

  # Seed corpus from the disassembler's test vectors, which cover every
  # opcode the decoder knows.
  if (Python3_FOUND)
    add_custom_command(OUTPUT "${seed_dir}/${name}.stamp"
      COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/make_seeds.py"
        --harness ${name} --out "${seed_dir}/${name}" ${dis_a64_files}
      COMMAND ${CMAKE_COMMAND} -E touch "${seed_dir}/${name}.stamp"
      DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/make_seeds.py" ${dis_a64_files}
      VERBATIM)
    add_custom_target(${name}_seeds ALL DEPENDS "${seed_dir}/${name}.stamp")
    # Replays the seeds once: a regression test for the harness invariants
    # over every known-good encoding.
    if (FUZZ_ENGINE STREQUAL "libfuzzer")
      set(run_args -runs=0 "${seed_dir}/${name}")
    else ()
      set(run_args "${seed_dir}/${name}")
    endif ()
    add_test(NAME fuzz.${name}.seeds COMMAND ${name} ${run_args})
    # A floor on how many mutated requests the encoder accepts (about 7800 of
    # 22000 do), so an encoder that rejects everything cannot pass.
    set(seed_env "DR_FUZZ_KNOWN=${FUZZ_KNOWN_ISSUES};${asan}")
    if (name STREQUAL "a64_encode_fuzzer")
      set(seed_env "${seed_env};DR_FUZZ_MIN_ENCODED=3000")
    endif ()
    set_tests_properties(fuzz.${name}.seeds PROPERTIES ENVIRONMENT "${seed_env}")
    set_property(TEST fuzz.${name}.seeds APPEND PROPERTY LABELS a64_prop a64_fuzz)
    set_property(GLOBAL APPEND PROPERTY DR_A64_PROP_TARGETS ${name}_seeds)
  endif ()

  # Inputs that once found a bug: each must keep passing.
  set(regress_dir "${CMAKE_CURRENT_SOURCE_DIR}/regressions/${name}")
  if (EXISTS "${regress_dir}")
    if (FUZZ_ENGINE STREQUAL "libfuzzer")
      add_test(NAME fuzz.${name}.regressions COMMAND ${name} -runs=0 "${regress_dir}")
    else ()
      add_test(NAME fuzz.${name}.regressions COMMAND ${name} "${regress_dir}")
    endif ()
    set_tests_properties(fuzz.${name}.regressions PROPERTIES
      ENVIRONMENT "DR_FUZZ_KNOWN=${FUZZ_KNOWN_ISSUES};${asan}")
    set_property(TEST fuzz.${name}.regressions APPEND PROPERTY
      LABELS a64_prop a64_fuzz)
  endif ()
endfunction ()

add_a64_fuzzer(a64_decode_fuzzer)
add_a64_fuzzer(a64_encode_fuzzer)
add_a64_fuzzer(a64_semantics_fuzzer)

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

# HotSpot JIT stress under DR (jvm/README.md).  Included from
# suite/tests/CMakeLists.txt on AArch64 Linux after a64_smoke.cmake (whose
# progress-like client the client smoke test uses).  Needs a JDK 25 (javac,
# jar) at configure time; without one the tests are not defined.  Label JVM.
# By default (for CI) one short case in a release build; A64_LONG_TESTS
# (suite/tests/CMakeLists.txt) runs the two smoke sets instead, also in debug.
find_package(Java 25 COMPONENTS Development QUIET)
find_package(Python3 COMPONENTS Interpreter QUIET)
if (NOT Java_FOUND OR NOT Python3_FOUND)
  message(STATUS "No JDK 25 or no Python 3: the JVM tests (label JVM) are not defined")
elseif (DEBUG AND NOT A64_LONG_TESTS)
  message(STATUS "Debug build without A64_LONG_TESTS: the JVM tests (label JVM) are not defined")
else ()
  get_target_path_for_execution(jvm_drrun drrun "${location_suffix}")
  set(jvm_jitstress ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/jvm/jitstress.py)
  # jitstress_quick: about a minute with a release DR; the smoke sets 3-7
  # minutes each, and a debug DR is 3-6x slower.
  if (DEBUG)
    set(jvm_timeout 3600)
    set(jvm_scale --timeout-scale 8)
  else ()
    set(jvm_timeout 600)
    set(jvm_scale "")
  endif ()
  set(jvm_common --drrun ${jvm_drrun} --java ${Java_JAVA_EXECUTABLE} ${jvm_scale}
    --javac ${Java_JAVAC_EXECUTABLE} --jar ${Java_JAR_EXECUTABLE}
    --work ${CMAKE_CURRENT_BINARY_DIR}/jitstress-work)
  if (A64_LONG_TESTS)
    # IcNull under Seedbox's options and DR's defaults, on one CPU.
    add_test(NAME jvm.jitstress_ic_smoke
      COMMAND ${jvm_jitstress} smoke --set ic ${jvm_common})
    set(jvm_tests jvm.jitstress_ic_smoke)
    # DeoptCycle and IcNull under the progress-like client.  Release only: under
    # a debug DR with the client, C2 compiles too little for the floors
    # (DeoptCycle: 1-2 C2 compiles, no recompiles of dc1-3, no deopts).
    if (NOT DEBUG)
      add_test(NAME jvm.jitstress_client_smoke
        COMMAND ${jvm_jitstress} smoke --set client ${jvm_common}
          --client $<TARGET_FILE:client.a64_progress_like.dll>)
      list(APPEND jvm_tests jvm.jitstress_client_smoke)
    endif ()
  else ()
    # The default (CI) set: one short IcNull case under Seedbox's options.
    add_test(NAME jvm.jitstress_quick
      COMMAND ${jvm_jitstress} smoke --set quick ${jvm_common})
    set(jvm_tests jvm.jitstress_quick)
  endif ()
  set_tests_properties(${jvm_tests} PROPERTIES
    LABELS JVM TIMEOUT ${jvm_timeout}
    PASS_REGULAR_EXPRESSION "jitstress: 0 of [0-9]+ cases failed"
    # The work directory (compiled program, cached references) is shared.
    RESOURCE_LOCK jitstress-work)
endif ()

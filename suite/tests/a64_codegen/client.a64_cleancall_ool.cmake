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

# Included from a64_codegen.cmake.
# Out-of-line clean calls interrupted at every instruction of the call site and
# of the clean_call_{save,restore} routines (see
# client-interface/a64_cleancall_ool.c): a static-DR executable with its client.
# "basic" runs every variant, "stress" adds a timer signal and a client thread
# that suspends the app thread in a loop, and "sweep" ptraces the app thread to
# deliver a signal and a suspension at each instruction in turn (with the
# client's fragments' translations recomputed, and stored at emit).
if (NOT ANDROID)
  tobuild_api(client.a64_cleancall_ool client-interface/a64_cleancall_ool.c
    "" "basic" OFF ON OFF)
  link_with_pthread(client.a64_cleancall_ool)
  set(client.a64_cleancall_ool_expectbase "a64_cleancall_ool_basic")
  torunonly_api(client.a64_cleancall_ool_stress client.a64_cleancall_ool
    client-interface/a64_cleancall_ool.c "" "stress" OFF OFF)
  set(client.a64_cleancall_ool_stress_expectbase "a64_cleancall_ool_stress")
  set(client.a64_cleancall_ool_stress_timeout 300)
  torunonly_api(client.a64_cleancall_ool_sweep client.a64_cleancall_ool
    client-interface/a64_cleancall_ool.c "" "sweep" OFF OFF)
  set(client.a64_cleancall_ool_sweep_expectbase "a64_cleancall_ool_sweep")
  set(client.a64_cleancall_ool_sweep_timeout 300)
  # The same, translating from the info stored at emit.
  torunonly_api(client.a64_cleancall_ool_sweep_store client.a64_cleancall_ool
    client-interface/a64_cleancall_ool.c "" "sweep;store" OFF OFF)
  set(client.a64_cleancall_ool_sweep_store_expectbase "a64_cleancall_ool_sweep")
  set(client.a64_cleancall_ool_sweep_store_timeout 300)
  list(APPEND a64_codegen_testnames client.a64_cleancall_ool
    client.a64_cleancall_ool_sweep client.a64_cleancall_ool_sweep_store
    client.a64_cleancall_ool_stress)
  # Its oracle allows for legal deferral, but it has still failed only under heavy
  # machine load: a verification script can report it without blocking on it.
  list(APPEND a64_codegen_timing_testnames client.a64_cleancall_ool_stress)
  add_dependencies(a64_codegen_tests client.a64_cleancall_ool)
endif ()

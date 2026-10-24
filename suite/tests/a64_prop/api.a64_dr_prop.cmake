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

# Differential properties of execution under DR with the native CPU as the
# oracle: random code blocks run natively and under static DR in forked
# children, one per option variant.  See api/a64_dr_prop.c.
if (NOT ANDROID)
  tobuild_api(api.a64_dr_prop api/a64_dr_prop.c "" "transparency" OFF ON OFF)
  target_sources(api.a64_dr_prop PRIVATE "${a64_prop_support_c}")
  use_DynamoRIO_extension(api.a64_dr_prop drmgr_static)
  use_DynamoRIO_extension(api.a64_dr_prop drreg_static)
  use_DynamoRIO_extension(api.a64_dr_prop drutil_static)
  use_DynamoRIO_extension(api.a64_dr_prop drx_static)
  link_with_pthread(api.a64_dr_prop)
  if (DEBUG)
    # Variants using internal options only run against a debug DR.
    append_property_string(TARGET api.a64_dr_prop COMPILE_FLAGS
      "-DA64_DR_PROP_DEBUG_DR")
  endif ()
  set(api.a64_dr_prop_expectbase "a64_dr_prop_transparency")
  set(api.a64_dr_prop_timeout 600)
  torunonly_api(api.a64_dr_prop_signals api.a64_dr_prop api/a64_dr_prop.c ""
    "signals" OFF OFF)
  set(api.a64_dr_prop_signals_expectbase "a64_dr_prop_signals")
  set(api.a64_dr_prop_signals_timeout 600)
  torunonly_api(api.a64_dr_prop_instr api.a64_dr_prop api/a64_dr_prop.c ""
    "instr" OFF OFF)
  set(api.a64_dr_prop_instr_expectbase "a64_dr_prop_instr")
  set(api.a64_dr_prop_instr_timeout 600)
  # Mode "ssbs" (compare PSTATE.SSBS strictly) is a diagnostic, not a
  # test: SSBS in signal frames is not deterministic even natively.
  a64_prop_register(TESTS api.a64_dr_prop api.a64_dr_prop_signals api.a64_dr_prop_instr
    TARGETS api.a64_dr_prop)
endif ()

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

# Cross-thread code publication and self-modifying code with the
# architecture's cache maintenance rules as the oracle: see api/a64_prop_jit.c.
if (NOT ANDROID)
  add_api_exe(api.a64_prop_jit api/a64_prop_jit.c OFF ON)
  target_sources(api.a64_prop_jit PRIVATE "${a64_prop_support_c}")
  link_with_pthread(api.a64_prop_jit)
  # The "_window" and "_progress" variants' in-process client.
  use_DynamoRIO_extension(api.a64_prop_jit drmgr_static)
  use_DynamoRIO_extension(api.a64_prop_jit drreg_static)
  if (DEBUG)
    append_property_string(TARGET api.a64_prop_jit COMPILE_FLAGS
      "-DA64_DR_PROP_DEBUG_DR")
  endif ()
  # Each variant runs rounds for -secs (5 against a debug DR, 10 against a
  # release one, at full size), and selfmod's regression rounds for
  # -regress_secs each (3).
  a64_prop_args(a64pj_publish SHORT publish -secs 1 LONG publish)
  a64_prop_args(a64pj_selfmod SHORT selfmod -secs 2 -regress_secs 0.5 LONG selfmod)
  torunonly_api(api.a64_prop_jit_publish api.a64_prop_jit api/a64_prop_jit.c ""
    "${a64pj_publish}" OFF OFF)
  set(api.a64_prop_jit_publish_expectbase "a64_prop_jit_publish")
  set(api.a64_prop_jit_publish_timeout 300)
  torunonly_api(api.a64_prop_selfmod api.a64_prop_jit api/a64_prop_jit.c ""
    "${a64pj_selfmod}" OFF OFF)
  set(api.a64_prop_selfmod_expectbase "a64_prop_jit_selfmod")
  set(api.a64_prop_selfmod_timeout 300)
  # patch: a call retargeted under a running thread, which faults in the old
  # target before the cache maintenance (a deterministic regression).  With a
  # static DR, elision is always off (-code_api), so the elision case runs a
  # build of the test without DR under drrun with Seedbox's options.
  torunonly_api(api.a64_prop_jit_patch_static api.a64_prop_jit api/a64_prop_jit.c ""
    "patch" OFF OFF)
  set(api.a64_prop_jit_patch_static_expectbase "a64_prop_jit_patch")
  set(api.a64_prop_jit_patch_static_timeout 120)
  add_exe(api.a64_prop_jit_app api/a64_prop_jit.c)
  target_sources(api.a64_prop_jit_app PRIVATE "${a64_prop_support_c}")
  append_property_string(TARGET api.a64_prop_jit_app COMPILE_FLAGS
    "-DA64P_EXTERNAL_DR")
  link_with_pthread(api.a64_prop_jit_app)
  # Not through torun(): it appends -code_api to the options, which turns
  # elision back off after -opt_speed.
  get_target_path_for_execution(a64pj_drrun drrun "${location_suffix}")
  get_target_path_for_execution(a64pj_app api.a64_prop_jit_app "${location_suffix}")
  add_test(NAME api.a64_prop_jit_patch
    COMMAND ${a64pj_drrun} -s 120 -quiet -killpg
      -opt_speed -disable_traces -ldstex2cas -no_hw_cache_consistency -fake_ctr_dic
      -- ${a64pj_app} patch -external nohwcc)
  set_tests_properties(api.a64_prop_jit_patch PROPERTIES TIMEOUT 120
    PASS_REGULAR_EXPRESSION "patch: all properties hold"
    FAIL_REGULAR_EXPRESSION "FAIL")
  a64_prop_register(TESTS api.a64_prop_jit_patch api.a64_prop_jit_patch_static
    TIMING api.a64_prop_jit_publish api.a64_prop_selfmod
    TARGETS api.a64_prop_jit api.a64_prop_jit_app)
endif ()

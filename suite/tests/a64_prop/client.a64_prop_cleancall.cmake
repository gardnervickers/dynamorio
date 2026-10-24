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

# Clean-call ABI and drreg allocation properties with the native CPU as the
# oracle (see client-interface/a64_prop_cleancall.c): a static-DR executable
# with an in-process client, sharing a64_dr_prop's generator.
if (NOT ANDROID)
  # -n blocks per variant.
  a64_prop_args(a64pc_cleancall SHORT cleancall -n 30 LONG cleancall -n 100)
  a64_prop_args(a64pc_drreg SHORT drreg -n 8 LONG drreg -n 40)
  tobuild_api(client.a64_prop_cleancall client-interface/a64_prop_cleancall.c
    "" "${a64pc_cleancall}" OFF ON OFF)
  target_sources(client.a64_prop_cleancall PRIVATE "${a64_prop_support_c}")
  use_DynamoRIO_extension(client.a64_prop_cleancall drmgr_static)
  use_DynamoRIO_extension(client.a64_prop_cleancall drreg_static)
  if (DEBUG)
    append_property_string(TARGET client.a64_prop_cleancall COMPILE_FLAGS
      "-DA64_DR_PROP_DEBUG_DR")
  endif ()
  set(client.a64_prop_cleancall_timeout 300)
  torunonly_api(client.a64_prop_drreg client.a64_prop_cleancall
    client-interface/a64_prop_cleancall.c "" "${a64pc_drreg}" OFF OFF)
  set(client.a64_prop_drreg_expectbase "a64_prop_drreg")
  set(client.a64_prop_drreg_timeout 300)
  a64_prop_register(TESTS client.a64_prop_cleancall client.a64_prop_drreg
    TARGETS client.a64_prop_cleancall)
endif ()

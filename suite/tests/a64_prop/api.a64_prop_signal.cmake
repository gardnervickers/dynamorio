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

# Signal ABI and DR-internal-path properties: hand-written scenarios with
# seeded parameters, native run as the oracle.  See api/a64_prop_signal.c.
if (NOT ANDROID)
  tobuild_api(api.a64_prop_signal_abi api/a64_prop_signal.c "" "abi" OFF ON OFF)
  target_sources(api.a64_prop_signal_abi PRIVATE "${a64_prop_support_c}")
  use_DynamoRIO_extension(api.a64_prop_signal_abi drmgr_static)
  use_DynamoRIO_extension(api.a64_prop_signal_abi drreg_static)
  use_DynamoRIO_extension(api.a64_prop_signal_abi drx_static)
  link_with_pthread(api.a64_prop_signal_abi)
  if (DEBUG)
    append_property_string(TARGET api.a64_prop_signal_abi COMPILE_FLAGS
      "-DA64_DR_PROP_DEBUG_DR")
  endif ()
  set(api.a64_prop_signal_abi_expectbase "a64_prop_signal_abi")
  set(api.a64_prop_signal_abi_timeout 300)
  torunonly_api(api.a64_prop_signal_paths api.a64_prop_signal_abi
    api/a64_prop_signal.c "" "paths" OFF OFF)
  set(api.a64_prop_signal_paths_expectbase "a64_prop_signal_paths")
  set(api.a64_prop_signal_paths_timeout 600)
  # setitimer/alarm/getitimer sequences, with DR's own itimers as variants.
  torunonly_api(api.a64_prop_signal_itimer api.a64_prop_signal_abi
    api/a64_prop_signal.c "" "itimer" OFF OFF)
  set(api.a64_prop_signal_itimer_expectbase "a64_prop_signal_itimer")
  set(api.a64_prop_signal_itimer_timeout 300)
  a64_prop_register(TIMING api.a64_prop_signal_abi api.a64_prop_signal_paths
    api.a64_prop_signal_itimer TARGETS api.a64_prop_signal_abi)
endif ()

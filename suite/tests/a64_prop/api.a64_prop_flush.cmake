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

# The flush API's contracts and resets under load: see api/a64_prop_flush.c.
if (NOT ANDROID)
  # Each DR variant runs for -secs (20 at full size).
  a64_prop_args(a64pf_args SHORT flush -secs 4 LONG flush)
  tobuild_api(api.a64_prop_flush api/a64_prop_flush.c "" "${a64pf_args}" OFF ON OFF)
  target_sources(api.a64_prop_flush PRIVATE "${a64_prop_support_c}")
  link_with_pthread(api.a64_prop_flush)
  if (DEBUG)
    append_property_string(TARGET api.a64_prop_flush COMPILE_FLAGS
      "-DA64_DR_PROP_DEBUG_DR")
  endif ()
  set(api.a64_prop_flush_timeout 400)
  a64_prop_register(TIMING api.a64_prop_flush TARGETS api.a64_prop_flush)
endif ()

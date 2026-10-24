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

# Attach/detach/re-attach under load: see api/a64_prop_lifecycle.c.
if (NOT ANDROID)
  # 60 attach/detach rounds at full size.
  a64_prop_args(a64pl_args SHORT lifecycle -rounds 15 LONG lifecycle)
  tobuild_api(api.a64_prop_lifecycle api/a64_prop_lifecycle.c "" "${a64pl_args}"
    OFF ON OFF)
  target_sources(api.a64_prop_lifecycle PRIVATE "${a64_prop_support_c}")
  link_with_pthread(api.a64_prop_lifecycle)
  if (DEBUG)
    append_property_string(TARGET api.a64_prop_lifecycle COMPILE_FLAGS
      "-DA64_DR_PROP_DEBUG_DR")
  endif ()
  set(api.a64_prop_lifecycle_timeout 300)
  a64_prop_register(TIMING api.a64_prop_lifecycle TARGETS api.a64_prop_lifecycle)
endif ()

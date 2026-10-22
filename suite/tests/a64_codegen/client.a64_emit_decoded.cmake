# **********************************************************
# Copyright (c) 2026 Google, Inc.  All rights reserved.
# **********************************************************
#
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
# client.a64_emit_decoded: an app instr whose bytes change between our decode and
# the emit, as a JIT's patch may race with our decode, is emitted as decoded on a
# CPU where it cannot be encoded (GCSPUSHM without FEAT_GCS), not as the new bytes.
add_exe(a64_emit_decoded_app
  ${CMAKE_CURRENT_SOURCE_DIR}/client-interface/a64_emit_decoded_app.asm "" "")
append_pure_asm_app_link_flags(a64_emit_decoded_app)
set(client.a64_emit_decoded_realtest a64_emit_decoded_app)
set(client.a64_emit_decoded_client_source client-interface/a64_emit_decoded.dll.c)
tobuild_ci(client.a64_emit_decoded client-interface/a64_emit_decoded.c "" "" "")
list(APPEND a64_codegen_testnames client.a64_emit_decoded)
add_dependencies(a64_codegen_tests a64_emit_decoded_app client.a64_emit_decoded.dll)

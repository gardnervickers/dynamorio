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
# client.a64_mops: each FEAT_MOPS main and epilogue instruction in the code cache
# follows its prologue (and main) instruction, as the kernel's rewind on a
# mismatched-option exception needs, with instrumentation, stolen-register
# mangling and block starts in between in the app.  The app is the pure-asm
# allasm_aarch64_mops, which the drmemtrace MOPS tests also run.
set(client.a64_mops_realtest allasm_aarch64_mops)
set(client.a64_mops_client_source client-interface/a64_mops.dll.c)
tobuild_ci(client.a64_mops client-interface/a64_mops.c "" "" "")
list(APPEND a64_codegen_testnames client.a64_mops)
add_dependencies(a64_codegen_tests allasm_aarch64_mops client.a64_mops.dll)

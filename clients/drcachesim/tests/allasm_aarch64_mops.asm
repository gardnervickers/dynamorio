/* **********************************************************
 * Copyright (c) 2026 Google, Inc. All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Runs FEAT_MOPS copies and sets of 0 bytes, one of them at address 0, as raw
 * words so that no assembler support is needed.  Without FEAT_MOPS each of the 12
 * instructions raises SIGILL, and the handler skips it: the tracer still sees
 * each one, and its instrumentation runs before the instruction does.
 * Used by the drmemtrace tests (allasm-aarch64-mops-*), which check that no
 * memory record is written for them, and by client.a64_mops.
 * Data references, without FEAT_MOPS: 4 stores to build the sigaction, then
 * one load and one store in each of the 12 handler runs.
 */

        .global  _start

        .align   6
_start:
        // Align stack pointer and get some space.
        mov      x0, sp
        bic      x0, x0, #63
        sub      x0, x0, #1024
        mov      sp, x0

        // rt_sigaction(SIGILL, &act, NULL, 8), with act on the stack:
        // { handler, SA_SIGINFO | SA_RESTORER, restorer, mask 0 }.
        sub      sp, sp, #32
        adr      x9, handler
        str      x9, [sp]
        mov      x9, #4
        movk     x9, #0x400, lsl #16
        str      x9, [sp, #8]
        adr      x9, restorer
        str      x9, [sp, #16]
        str      xzr, [sp, #24]
        mov      w0, #4            // SIGILL
        mov      x1, sp
        mov      x2, #0
        mov      w3, #8            // sizeof(sigset_t)
        mov      w8, #134          // SYS_rt_sigaction
        svc      #0
        add      sp, sp, #32

        // A forward-only copy of 0 bytes: cpyfp/cpyfm/cpyfe [x0]!, [x1]!, x2!
        adr      x0, buffer
        add      x1, x0, #64
        mov      x2, #0
        .inst    0x19010440
        .inst    0x19410440
        .inst    0x19810440

        // A copy of 0 bytes: cpyp/cpym/cpye [x0]!, [x1]!, x2!
        adr      x0, buffer
        add      x1, x0, #64
        mov      x2, #0
        .inst    0x1d010440
        .inst    0x1d410440
        .inst    0x1d810440

        // A set of 0 bytes at address 0: setp/setm/sete [x0]!, x2!, x3
        mov      x0, #0
        mov      x2, #0
        mov      x3, #0
        .inst    0x19c30440
        .inst    0x19c34440
        .inst    0x19c38440

        // A forward-only copy of 0 bytes to the stolen register's app value:
        // cpyfp/cpyfm/cpyfe [x28]!, [x1]!, x2!
        adr      x28, buffer
        add      x1, x28, #64
        mov      x2, #0
        .inst    0x1901045c
        .inst    0x1941045c
        .inst    0x1981045c

        // Exit.
        mov      w0, #2            // stderr
        adr      x1, helloworld
        mov      w2, #14           // sizeof(helloworld)
        mov      w8, #64           // SYS_write
        svc      #0
        mov      w0, #0            // status
        mov      w8, #94           // SYS_exit_group
        svc      #0

        // The SIGILL handler: step over the instruction.  The pc is at offset
        // 440 in the ucontext: 176 for uc_mcontext, then fault_address,
        // regs[31] and sp.
handler:
        ldr      x9, [x2, #440]
        add      x9, x9, #4
        str      x9, [x2, #440]
        ret

restorer:
        mov      w8, #139          // SYS_rt_sigreturn
        svc      #0

        .align   6
buffer:
        .zero    128

helloworld:
        .ascii   "Hello, world!\n"

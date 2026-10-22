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

/* For client.a64_emit_decoded: runs GCSPUSHM X0 (a SYS alias that needs FEAT_GCS,
 * and GCS enabled, and raises SIGILL otherwise) once.  The client changes the word
 * to BR X28 after DR decodes it and before DR emits its block.  The SIGILL handler
 * skips it.
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

        // The block after the syscall holds GCSPUSHM X0.
        mov      x0, #0
        .inst    0xd50b7700

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

helloworld:
        .ascii   "Hello, world!\n"

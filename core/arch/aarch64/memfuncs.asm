/* **********************************************************
 * Copyright (c) 2019-2020 Google, Inc. All rights reserved.
 * Copyright (c) 2016 ARM Limited. All rights reserved.
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
 * * Neither the name of ARM Limited nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL ARM LIMITED OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * memfuncs.asm: Contains our custom memcpy and memset routines.
 *
 * See the long comment at the top of x86/memfuncs.asm.
 */

#include "../asm_defines.asm"
START_FILE
#ifdef UNIX

/* Private memcpy: 16 bytes per iteration with ldp/stp, then 8, 4, 2 and 1-byte
 * tails picked by the bits of the remaining count. General registers only, so
 * the application's SIMD state is untouched, and position-independent with no
 * calls, since it runs before DR relocates itself. Unaligned accesses are fine
 * on normal memory. Never reads or writes outside [src, src+n) and [dst, dst+n).
 * Copies strictly forwards, loading each chunk before storing it: d_r_memmove
 * and lib/memmove.c call this for overlapping dst < src.
 */
        DECLARE_FUNC(memcpy)
GLOBAL_LABEL(memcpy:)
        mov      x3, ARG1
        cmp      ARG3, #16
        b.lo     2f
1:      ldp      x4, x5, [ARG2], #16
        stp      x4, x5, [x3], #16
        sub      ARG3, ARG3, #16
        cmp      ARG3, #16
        b.hs     1b
2:      tbz      ARG3, #3, 3f
        ldr      x4, [ARG2], #8
        str      x4, [x3], #8
3:      tbz      ARG3, #2, 4f
        ldr      w4, [ARG2], #4
        str      w4, [x3], #4
4:      tbz      ARG3, #1, 5f
        ldrh     w4, [ARG2], #2
        strh     w4, [x3], #2
5:      tbz      ARG3, #0, 6f
        ldrb     w4, [ARG2]
        strb     w4, [x3]
6:      ret
        END_FUNC(memcpy)

/* Private memset: the low byte of the value replicated into a doubleword, then
 * the same loop and tails as memcpy, with the same constraints.
 */
        DECLARE_FUNC(memset)
GLOBAL_LABEL(memset:)
        mov      x3, ARG1
        and      x4, ARG2, #0xff
        orr      x4, x4, x4, lsl #8
        orr      x4, x4, x4, lsl #16
        orr      x4, x4, x4, lsl #32
        cmp      ARG3, #16
        b.lo     2f
1:      stp      x4, x4, [x3], #16
        sub      ARG3, ARG3, #16
        cmp      ARG3, #16
        b.hs     1b
2:      tbz      ARG3, #3, 3f
        str      x4, [x3], #8
3:      tbz      ARG3, #2, 4f
        str      w4, [x3], #4
4:      tbz      ARG3, #1, 5f
        strh     w4, [x3], #2
5:      tbz      ARG3, #0, 6f
        strb     w4, [x3]
6:      ret
        END_FUNC(memset)

/* See x86.asm notes about needing these to avoid gcc invoking *_chk */
.global __memcpy_chk
HIDDEN(__memcpy_chk)
WEAK(__memcpy_chk)
.set __memcpy_chk,GLOBAL_REF(memcpy)

.global __memset_chk
HIDDEN(__memset_chk)
WEAK(__memset_chk)
.set __memset_chk,GLOBAL_REF(memset)

#endif /* UNIX */

END_FILE

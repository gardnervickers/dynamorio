/* **********************************************************
 * Copyright (c) 2026 Google, Inc.  All rights reserved.
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

/* An rseq sequence in anonymous read-only code, as a JIT that keeps its code
 * read-only (W^X) might have one, with a fault in its instrumented run.  DR
 * translates the fault (to the abort handler) by recreating the block, which must
 * come out with the sequence's start and endpoint marks, as built.  Without them
 * mangle_rseq() asserts in debug, and in release reports "DR_NOTE_REG_BARRIER must
 * not be deleted".  linux.rseq_anon runs with -no_hw_cache_consistency, under which
 * DR keeps a copy of the code of a block from outside any module to translate from
 * (a recreation from the copy lost the marks); linux.rseq_anon_hwcc without it (a
 * recreation from the app's code did not stop at the endpoint).
 */

#include "tools.h"
#ifndef LINUX
#    error Only Linux is supported.
#endif
#ifndef AARCH64
#    error Only AArch64 is supported.
#endif
#include "../../core/unix/include/syscall.h"
#ifndef HAVE_RSEQ
#    error The linux/rseq header is required.
#endif
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 35))
#    include <sys/rseq.h>
#else
#    define RSEQ_SIG 0xd503201f /* nop */
#endif
#include <linux/rseq.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#undef NDEBUG
#include <assert.h>

#define EXPANDSTR(x) #x
#define STRINGIFY(x) EXPANDSTR(x)

/* The anonymous page we copy the code to.  DR reads a module's rseq descriptors from
 * its file (applying its relocations), when the app first registers rseq, so the
 * descriptor cannot be filled in at run time: it is static, for code at a fixed
 * address, outside any module.
 */
#define ANON_BASE 0x600000000

/* The code we copy to ANON_BASE (position-independent).
 *   x0 = &rseq_cs of our struct rseq, x1 = the descriptor,
 *   x2 = &ptr (what the sequence loads through), x3 = &out.
 * The sequence is [anon_cs_start, anon_cs_end): it loads *ptr, faulting while ptr
 * is NULL, and commits *ptr + 1 to out.  Its abort handler retries.
 */
/* Hidden, so that we reach these local labels pc-relatively: through the GOT, a
 * PIE's references to them would all resolve to the start of .text.
 */
#define HIDDEN __attribute__((visibility("hidden")))
extern char anon_tmpl_start[] HIDDEN, anon_tmpl_cs_start[] HIDDEN,
    anon_tmpl_fault[] HIDDEN, anon_tmpl_cs_end[] HIDDEN, anon_tmpl_abort[] HIDDEN,
    anon_tmpl_end[] HIDDEN;
/* clang-format off */
__asm__(".text\n\t"
        ".balign 4\n\t"
        "anon_tmpl_start:\n\t"
        "1:\n\t"
        "str x1, [x0]\n\t"
        "anon_tmpl_cs_start:\n\t"
        "ldr x4, [x2]\n\t"
        "anon_tmpl_fault:\n\t"
        "ldr x5, [x4]\n\t"
        "add x5, x5, #1\n\t"
        "str x5, [x3]\n\t"
        "anon_tmpl_cs_end:\n\t"
        "str xzr, [x0]\n\t"
        "ret\n\t"
        ".long " STRINGIFY(RSEQ_SIG) "\n\t"
        "anon_tmpl_abort:\n\t"
        "b 1b\n\t"
        "anon_tmpl_end:\n\t"
        /* The sequence's descriptor (struct rseq_cs), for the copy at ANON_BASE. */
        ".pushsection __rseq_cs, \"aw\"\n\t"
        ".balign 32\n\t"
        "anon_cs:\n\t"
        ".long 0, 0\n\t"
        ".quad " STRINGIFY(ANON_BASE) " + (anon_tmpl_cs_start - anon_tmpl_start)\n\t"
        ".quad anon_tmpl_cs_end - anon_tmpl_cs_start\n\t"
        ".quad " STRINGIFY(ANON_BASE) " + (anon_tmpl_abort - anon_tmpl_start)\n\t"
        ".popsection\n\t"
        ".pushsection __rseq_cs_ptr_array, \"aw\"\n\t"
        ".balign 8\n\t"
        ".quad anon_cs\n\t"
        ".popsection\n\t");
/* clang-format on */
extern struct rseq_cs anon_cs HIDDEN;

/* See linux.rseq for the alignment (i#8159). */
static __thread volatile struct rseq rseq_tls __attribute__((aligned(64)));

static uint64_t valid_val = 41;
static uint64_t *volatile load_ptr;
static uint64_t out;
static byte *fault_pc, *abort_pc;
static volatile int faults, bad_faults;
/* -under_dr: the test runs under DR, which must recognize the sequence. */
static bool under_dr;

static void
handler(int sig, siginfo_t *info, ucontext_t *ucxt)
{
    byte *pc = (byte *)ucxt->uc_mcontext.pc;
    /* DR aborts the sequence on a fault in its instrumented run (which it recognizes as
     * rseq code by the descriptor): the frame is at the abort handler.  If DR did not
     * recognize the sequence the frame would be at the faulting load.
     * Linux aborts it too on a signal in the sequence, but 6.19 on arm64 does not:
     * its partial conversion to generic entry broke the rseq abort on signal delivery
     * (a fix was proposed on linux-arm-kernel in April 2026).  So natively, and only
     * then, we accept the faulting load (we abort the sequence ourselves either way,
     * to go on).
     */
    if (pc == fault_pc) {
        if (under_dr)
            bad_faults++;
        ucxt->uc_mcontext.pc = (uintptr_t)abort_pc;
    } else if (pc != abort_pc)
        bad_faults++;
    if (sig != SIGSEGV || info->si_addr != NULL)
        bad_faults++;
    faults++;
    load_ptr = &valid_val;
}

int
main(int argc, const char *argv[])
{
    under_dr = argc > 1 && strcmp(argv[1], "-under_dr") == 0;
    const size_t size = getpagesize();
    size_t len = anon_tmpl_end - anon_tmpl_start;
    byte *code = mmap((void *)ANON_BASE, size, PROT_READ | PROT_WRITE,
                      MAP_ANON | MAP_PRIVATE | MAP_FIXED_NOREPLACE, -1, 0);
    if (code != (byte *)ANON_BASE) {
        print("cannot map the code at " STRINGIFY(ANON_BASE) ": errno=%d\n", errno);
        return 1;
    }
    memcpy(code, anon_tmpl_start, len);
    __builtin___clear_cache((char *)code, (char *)code + len);
    int res = mprotect(code, size, PROT_READ | PROT_EXEC);
    assert(res == 0);
    fault_pc = code + (anon_tmpl_fault - anon_tmpl_start);
    abort_pc = code + (anon_tmpl_abort - anon_tmpl_start);
    assert(anon_cs.start_ip == (uintptr_t)(code + (anon_tmpl_cs_start - anon_tmpl_start)));
    assert(anon_cs.abort_ip == (uintptr_t)abort_pc);

    rseq_tls.cpu_id = RSEQ_CPU_ID_UNINITIALIZED;
    res = syscall(SYS_rseq, &rseq_tls, sizeof(rseq_tls), 0, RSEQ_SIG);
    if (res != 0) {
        /* The kernel lacks rseq (ENOSYS), or glibc registered its own (EBUSY), which
         * the test's environment turns off.
         */
        print("rseq registration failed: errno=%d\n", errno);
        return 1;
    }
    intercept_signal(SIGSEGV, handler, false);

    void (*seq)(volatile uint64_t *, struct rseq_cs *, uint64_t *volatile *, uint64_t *) =
        (void (*)(volatile uint64_t *, struct rseq_cs *, uint64_t *volatile *,
                  uint64_t *))code;
    for (int i = 0; i < 3; i++) {
        load_ptr = NULL;
        out = 0;
        seq((volatile uint64_t *)&rseq_tls.rseq_cs, &anon_cs, &load_ptr, &out);
        assert(out == valid_val + 1);
    }
    if (faults != 3 || bad_faults != 0)
        print("faults %d (expected 3), at the wrong pc %d\n", faults, bad_faults);
    print("All done\n");
    return 0;
}

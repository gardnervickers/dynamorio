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

/* A fault in a block built from JIT code that the app has since patched but not
 * yet had us flush (no IC IVAU yet), for code that is not writable when the block
 * is built:
 *   wx:    the page is RX, made RW for the patch and RX again (a W^X JIT);
 *   mprot: the page is RX, made RWX for the patch;
 *   alias: the page is an RX mapping of a memfd, patched through a second, RW
 *          mapping (a double-mapped JIT);
 *   rwx:   the page stays RWX (the control).
 * Each round a caller C calls X, "nop; movz x6, #1; ldr x7, [x1, #8]; movz x0, #1;
 * ret", which we run (so it is built) and then patch to "b Z" at its nop, where Z is
 * "movz x6, #3; ldr x7, [x1, #16]; movz x0, #3; ret".  We then call C with x1 = NULL.
 * Running either the old code or the new is legal before the IC IVAU, so the fault
 * must be at X's load with x6 = 1 or at Z's load with x6 = 3.  Without
 * -hw_cache_consistency DR translates the fault in a block built from the old code:
 * from the new code it got pc 0 (release) or asserted (debug) for all but rwx, until
 * it kept a copy of the code of blocks from outside any module (-xl8_code_copy).
 */

#include "tools.h" /* defines _GNU_SOURCE, for memfd_create */
#ifndef LINUX
#    error Only Linux is supported.
#endif
#ifndef AARCH64
#    error Only AArch64 is supported.
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define ROUNDS 8

#define A64_NOP 0xd503201fu
#define A64_RET 0xd65f03c0u
#define A64_STP_FP_LR 0xa9bf7bfdu /* stp x29, x30, [sp, #-16]! */
#define A64_LDP_FP_LR 0xa8c17bfdu /* ldp x29, x30, [sp], #16 */

static volatile uint64_t fault_pc, fault_x6;
static volatile int faults;
static uint64_t x_load, z_load;

static uint32_t
movz(int rd, int imm)
{
    return 0xd2800000u | (imm << 5) | rd;
}

static uint32_t
ldr_x7_x1(int off)
{
    return 0xf9400000u | ((off / 8) << 10) | (1 << 5) | 7;
}

static uint32_t
branch(uint32_t opcode, byte *from, byte *to)
{
    return opcode | (uint32_t)(((to - from) / 4) & 0x3ffffff);
}

static void
handler(int sig, siginfo_t *info, ucontext_t *ucxt)
{
    fault_pc = ucxt->uc_mcontext.pc;
    fault_x6 = ucxt->uc_mcontext.regs[6];
    faults++;
    if (fault_pc == x_load || fault_pc == z_load)
        ucxt->uc_mcontext.pc += 4;
    else {
        /* A wrong pc: return to C with x0 = -1. */
        ucxt->uc_mcontext.regs[0] = (uint64_t)-1;
        ucxt->uc_mcontext.pc = ucxt->uc_mcontext.regs[30];
    }
}

static void
map_fixed(byte *addr, size_t size, int prot, int flags, int fd)
{
    if (mmap(addr, size, prot, flags | MAP_FIXED, fd, 0) != addr) {
        print("mmap failed\n");
        exit(1);
    }
}

static void
protect(byte *addr, size_t size, int prot)
{
    if (mprotect(addr, size, prot) != 0) {
        print("mprotect failed\n");
        exit(1);
    }
}

static int
run_class(const char *cls)
{
    const size_t pg = getpagesize();
    bool wx = strcmp(cls, "wx") == 0, mprot = strcmp(cls, "mprot") == 0;
    bool alias = strcmp(cls, "alias") == 0, rwx = strcmp(cls, "rwx") == 0;
    int bad = 0;
    for (int r = 0; r < ROUNDS; r++) {
        /* One reservation, so C's bl reaches X: C, X and Z are a page apart. */
        byte *res = mmap(NULL, 6 * pg, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (res == MAP_FAILED) {
            print("mmap failed\n");
            exit(1);
        }
        byte *c_pg = res + pg, *x_pg = res + 3 * pg, *z_pg = res + 5 * pg;
        byte *x_write_pg = x_pg;
        int fd = -1;
        const int rwx_prot = PROT_READ | PROT_WRITE | PROT_EXEC;
        const int anon = MAP_PRIVATE | MAP_ANONYMOUS;
        map_fixed(c_pg, pg, rwx_prot, anon, -1);
        map_fixed(z_pg, pg, rwx_prot, anon, -1);
        if (alias) {
            fd = memfd_create("a64_code_copy_wx", MFD_CLOEXEC);
            if (fd < 0 || ftruncate(fd, pg) != 0) {
                print("memfd failed\n");
                exit(1);
            }
            x_write_pg = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (x_write_pg == MAP_FAILED) {
                print("mmap failed\n");
                exit(1);
            }
            map_fixed(x_pg, pg, PROT_READ | PROT_EXEC, MAP_SHARED, fd);
        } else
            map_fixed(x_pg, pg, rwx_prot, anon, -1);
        /* Vary X's address within its page across rounds. */
        size_t x_off = 64 * (r % 8);
        byte *x_code = x_pg + x_off;
        uint32_t *x = (uint32_t *)(x_write_pg + x_off);
        uint32_t *z = (uint32_t *)z_pg, *c = (uint32_t *)c_pg;
        x[0] = A64_NOP;
        x[1] = movz(6, 1);
        x[2] = ldr_x7_x1(8);
        x[3] = movz(0, 1);
        x[4] = A64_RET;
        z[0] = movz(6, 3);
        z[1] = ldr_x7_x1(16);
        z[2] = movz(0, 3);
        z[3] = A64_RET;
        c[0] = A64_STP_FP_LR;
        c[1] = branch(0x94000000u /* bl */, c_pg + 4, x_code);
        c[2] = A64_LDP_FP_LR;
        c[3] = A64_RET;
        x_load = (uint64_t)(x_code + 8);
        z_load = (uint64_t)(z_pg + 4);
        __builtin___clear_cache((char *)c_pg, (char *)c_pg + pg);
        __builtin___clear_cache((char *)x_code, (char *)x_code + 20);
        __builtin___clear_cache((char *)z_pg, (char *)z_pg + pg);
        protect(c_pg, pg, PROT_READ | PROT_EXEC);
        protect(z_pg, pg, PROT_READ | PROT_EXEC);
        if (!rwx && !alias)
            protect(x_pg, pg, PROT_READ | PROT_EXEC);

        uint64_t data[4] = { 1, 2, 3, 4 };
        uint64_t (*call_c)(uint64_t, uint64_t *) = (uint64_t(*)(uint64_t, uint64_t *))c_pg;
        for (int i = 0; i < 3; i++) {
            if (call_c(0, data) != 1) {
                print("%s round %d: wrong result before the patch\n", cls, r);
                bad++;
            }
        }

        /* Patch X's nop to "b Z", with no IC IVAU yet. */
        if (wx)
            protect(x_pg, pg, PROT_READ | PROT_WRITE);
        else if (mprot)
            protect(x_pg, pg, rwx_prot);
        __atomic_store_n(&x[0], branch(0x14000000u /* b */, x_code, z_pg),
                         __ATOMIC_RELAXED);
        if (wx)
            protect(x_pg, pg, PROT_READ | PROT_EXEC);

        faults = 0;
        uint64_t ret = call_c(0, NULL);
        bool old_code = fault_pc == x_load && fault_x6 == 1 && ret == 1;
        bool new_code = fault_pc == z_load && fault_x6 == 3 && ret == 3;
        if (faults != 1 || !(old_code || new_code)) {
            print("%s round %d: %d faults, the last at X%+ld (x6=%d), returned %d\n", cls,
                  r, faults, (long)(fault_pc - (uint64_t)x_code), (int)fault_x6, (int)ret);
            bad++;
        }

        __builtin___clear_cache((char *)x_code, (char *)x_code + 4);
        munmap(c_pg, pg);
        munmap(x_pg, pg);
        munmap(z_pg, pg);
        munmap(res, 6 * pg);
        if (alias) {
            munmap(x_write_pg, pg);
            close(fd);
        }
    }
    print("%s: %d bad\n", cls, bad);
    return bad;
}

int
main(int argc, const char *argv[])
{
    intercept_signal(SIGSEGV, handler, false);
    run_class("rwx");
    run_class("wx");
    run_class("mprot");
    run_class("alias");
    print("All done\n");
    return 0;
}

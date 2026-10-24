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

/* Shared mechanics for the AArch64 differential property tests: see
 * a64_prop_support.h.
 */

#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#ifndef A64P_EXTERNAL_DR
#    include "dr_api.h"
#endif

#include <elf.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include "a64_prop_support.h"

#ifndef HWCAP_DIT
#    define HWCAP_DIT (1 << 24)
#endif
#ifndef HWCAP_FLAGM
#    define HWCAP_FLAGM (1 << 27)
#endif
#ifndef HWCAP_SB
#    define HWCAP_SB (1 << 29)
#endif
#ifndef HWCAP_PACA
#    define HWCAP_PACA (1 << 30)
#endif
#ifndef HWCAP_PACG
#    define HWCAP_PACG (1UL << 31)
#endif
#ifndef HWCAP2_FRINT
#    define HWCAP2_FRINT (1 << 8)
#endif
#ifndef HWCAP2_I8MM
#    define HWCAP2_I8MM (1 << 13)
#endif
#ifndef HWCAP2_BF16
#    define HWCAP2_BF16 (1 << 14)
#endif
#ifndef HWCAP2_AFP
#    define HWCAP2_AFP (1 << 20)
#endif

/* The generator's CPU features (declared in a64_dr_prop_gen.h). */
feat_t feat;
int gen_dczva_ok;
/* The calling thread's generator layout slot (a64_dr_prop_gen.h). */
__thread uint64_t a64g_code_base = A64G_CODE_BASE0;
__thread uint64_t a64g_data_base = A64G_DATA_BASE0;

/***************************************************************************
 * Variants.
 */
const variant_t a64p_variants[] = {
    { "default", "", 0, 0, 0, 0 },
    { "altstack", "", 1, 0, 0, 0 },
    { "nocas", "-no_ldstex2cas", 0, 0, 1, 0 },
    { "steal27", "-steal_reg 27", 0, 0, 1, 0 },
    { "steal19", "-steal_reg 19", 0, 0, 1, 0 },
    { "maxbb3", "-max_bb_instrs 3", 0, 0, 0, 0 },
    { "notraces", "-disable_traces", 0, 0, 0, 0 },
    { "smc_rwx", "", 0, 1, 0, 0 },
    { "smc_mprot", "", 0, 2, 0, 0 },
    { "smc_fakectr", "-fake_ctr_dic", 0, 3, 1, 1 },
    { "sandbox", "-sandbox_writable", 0, 1, 0, 0 },
    { "nohwcc", "-no_hw_cache_consistency", 0, 1, 1, 0 },
    { "reset", "-enable_reset -reset_every_nth_pending 1", 0, 0, 1, 0 },
};
const int a64p_num_variants = (int)(sizeof(a64p_variants) / sizeof(a64p_variants[0]));

/* Whether the comma-separated list contains name exactly. */
static int
list_has(const char *list, const char *name)
{
    size_t len = strlen(name);
    for (const char *p = list; p != NULL && *p != '\0';) {
        const char *e = strchr(p, ',');
        size_t n = e == NULL ? strlen(p) : (size_t)(e - p);
        if (n == len && strncmp(p, name, n) == 0)
            return 1;
        p = e == NULL ? NULL : e + 1;
    }
    return 0;
}

int
a64p_variant_selected(const char *vlist, const variant_t *v)
{
    return vlist == NULL || list_has(vlist, v->name);
}

const char *
a64p_unknown_variant(const char *vlist)
{
    static char buf[64];
    for (const char *p = vlist; p != NULL;) {
        const char *e = strchr(p, ',');
        size_t n = e == NULL ? strlen(p) : (size_t)(e - p);
        int found = 0;
        for (int i = 0; i < a64p_num_variants && !found; i++) {
            found = strlen(a64p_variants[i].name) == n &&
                strncmp(p, a64p_variants[i].name, n) == 0;
        }
        if (!found) {
            snprintf(buf, sizeof(buf), "%.*s", (int)(n < 60 ? n : 60), p);
            return buf;
        }
        p = e == NULL ? NULL : e + 1;
    }
    return NULL;
}

/***************************************************************************
 * Workers.
 */
static __thread a64p_worker_t *a64p_cur;

uint64_t a64p_fault_pstate_ignore = 0;
void (*a64p_on_masked_pstate)(int i, fault_rec_t *n, fault_rec_t *d);
void (*a64p_fault_hook)(a64p_worker_t *w, int n, ucontext_t *uc);

void
a64p_worker_init_slot(a64p_worker_t *w, int slot)
{
    if (slot < 0 || slot >= A64G_MAX_SLOTS) {
        fprintf(stderr, "ERROR: layout slot %d out of range\n", slot);
        exit(2);
    }
    memset(w, 0, sizeof(*w));
    w->alog = malloc(sizeof(arec_t) * MAXA);
    w->xres = w->vres = -1;
    w->code_mapped_mode = -1;
    w->slot = slot;
    w->code_base = a64g_slot_code_base(slot);
    w->data_base = a64g_slot_data_base(slot);
    /* HARN_ADDR's offset from DATA_BASE, for w's slot. */
    w->harn = (harn_t *)(uintptr_t)(w->data_base + (HARN_ADDR - DATA_BASE));
}

void
a64p_worker_init(a64p_worker_t *w)
{
    a64p_worker_init_slot(w, 0);
}

void
a64p_worker_bind(a64p_worker_t *w)
{
    a64p_cur = w;
    if (w != NULL) {
        a64g_code_base = w->code_base;
        a64g_data_base = w->data_base;
    }
}

/***************************************************************************
 * Host-side entry trampoline.  The block's own entry stub loads every
 * register from harn->in; its exit stub stores them to harn->out and returns
 * to label 1 below with the host SP from harn->host_sp.
 */
__asm__(".text\n"
        ".global run_code\n"
        ".type run_code, %function\n"
        ".p2align 2\n"
        "run_code:\n"
        "  hint #34\n"   /* bti c */
        "  mov x4, x2\n" /* run */
        "  stp x29, x30, [sp, #-176]!\n"
        "  mov x29, sp\n"
        "  stp x19, x20, [sp, #16]\n"
        "  stp x21, x22, [sp, #32]\n"
        "  stp x23, x24, [sp, #48]\n"
        "  stp x25, x26, [sp, #64]\n"
        "  stp x27, x28, [sp, #80]\n"
        "  stp d8, d9, [sp, #96]\n"
        "  stp d10, d11, [sp, #112]\n"
        "  stp d12, d13, [sp, #128]\n"
        "  stp d14, d15, [sp, #144]\n"
        "  mrs x2, fpcr\n"
        "  str x2, [sp, #160]\n"
        "  mrs x2, fpsr\n"
        "  str x2, [sp, #168]\n"
        "  mov x3, sp\n"
        "  str x3, [x1, #1600]\n"
        "  adr x3, 1f\n"
        "  str x3, [x1, #1608]\n"
        /* run_id = run, last before entering the block. */
        "  add x3, x1, #1616\n"
        "  stlr x4, [x3]\n"
        "  br x0\n"
        "1:\n"
        /* x1 is &harn->host_sp (exit stub): run_id = -1. */
        "  mov x2, #-1\n"
        "  add x3, x1, #16\n"
        "  stlr x2, [x3]\n"
        "  ldr x2, [sp, #160]\n"
        "  msr fpcr, x2\n"
        "  ldr x2, [sp, #168]\n"
        "  msr fpsr, x2\n"
        "  ldp x19, x20, [sp, #16]\n"
        "  ldp x21, x22, [sp, #32]\n"
        "  ldp x23, x24, [sp, #48]\n"
        "  ldp x25, x26, [sp, #64]\n"
        "  ldp x27, x28, [sp, #80]\n"
        "  ldp d8, d9, [sp, #96]\n"
        "  ldp d10, d11, [sp, #112]\n"
        "  ldp d12, d13, [sp, #128]\n"
        "  ldp d14, d15, [sp, #144]\n"
        "  ldp x29, x30, [sp], #176\n"
        "  ret\n"
        ".global run_code_end\n"
        "run_code_end:\n"
        ".size run_code, .-run_code\n");

/***************************************************************************
 * Signal frame parsing and hashing.
 */
struct a64p_rec_head *
a64p_find_rec(ucontext_t *uc, uint32_t magic)
{
    uint8_t *p = (uint8_t *)uc->uc_mcontext.__reserved;
    uint8_t *end = p + sizeof(uc->uc_mcontext.__reserved);
    for (int n = 0; n < 64 && p + sizeof(struct a64p_rec_head) <= end; n++) {
        struct a64p_rec_head *h = (struct a64p_rec_head *)p;
        if (h->magic == 0)
            break;
        if (h->magic == magic)
            return h;
        if (h->magic == EXTRA_MAGIC_) {
            struct a64p_extra_rec *e = (struct a64p_extra_rec *)h;
            p = (uint8_t *)(uintptr_t)e->datap;
            end = p + e->size;
            continue;
        }
        if (h->size == 0)
            break;
        p += h->size;
    }
    return NULL;
}

uint64_t
a64p_hash_bytes(const void *p, size_t n, uint64_t h)
{
    const uint64_t *w = (const uint64_t *)p;
    for (size_t i = 0; i < n / 8; i++) {
        h ^= w[i];
        h *= 0x100000001b3ULL;
        h ^= h >> 29;
    }
    return h;
}

uint64_t
a64p_vhash(const __uint128_t *v, int vres)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (int i = 0; i < 32; i++) {
        if (i == vres)
            continue;
        h = a64p_hash_bytes(&v[i], 16, h);
    }
    return h;
}

/***************************************************************************
 * Signal handlers.
 */
static void
sync_handler(int sig, siginfo_t *si, void *ucv)
{
    a64p_worker_t *w = a64p_cur;
    ucontext_t *uc = (ucontext_t *)ucv;
    uint64_t pc = uc->uc_mcontext.pc;
    if (w == NULL || !w->in_block ||
        (pc >= w->code_base && pc < w->code_hi &&
         !(pc >= w->blk_lo && pc < w->exit_pc))) {
        /* A genuine crash outside the generated block: re-raise with the default. */
        char buf[160];
        int len = snprintf(buf, sizeof(buf),
                           "a64_dr_prop: unexpected signal %d at pc 0x%llx addr 0x%llx "
                           "(in_block %d)\n",
                           sig, (unsigned long long)pc, (unsigned long long)si->si_addr,
                           w == NULL ? -1 : w->in_block);
        if (write(2, buf, len) < 0) {
            /* Nothing we can do. */
        }
        signal(sig, SIG_DFL);
        return;
    }
    int n = w->nf++;
    if (n < MAXF) {
        fault_rec_t *f = &w->flog[n];
        memset(f, 0, sizeof(*f));
        f->signo = sig;
        f->code = si->si_code;
        f->addr = (uint64_t)si->si_addr;
        f->pc = pc;
        f->sp = uc->uc_mcontext.sp;
        f->pstate = uc->uc_mcontext.pstate;
        f->fault_address = uc->uc_mcontext.fault_address;
        memcpy(f->x, uc->uc_mcontext.regs, sizeof(f->x));
        struct a64p_fpsimd_rec *fp =
            (struct a64p_fpsimd_rec *)a64p_find_rec(uc, FPSIMD_MAGIC_);
        if (fp != NULL) {
            f->has_fp = 1;
            f->fpsr = fp->fpsr;
            f->fpcr = fp->fpcr;
            memcpy(f->v, fp->v, sizeof(f->v));
        }
        struct a64p_esr_rec *er = (struct a64p_esr_rec *)a64p_find_rec(uc, ESR_MAGIC_);
        if (er != NULL) {
            f->has_esr = 1;
            f->esr = er->esr;
        }
    }
    if (a64p_fault_hook != NULL)
        a64p_fault_hook(w, n, uc);
    if (pc >= w->blk_lo && pc < w->exit_pc && n < MAXF_RUN)
        uc->uc_mcontext.pc = pc + 4;
    else
        uc->uc_mcontext.pc = w->exit_pc; /* wild branch or too many faults */
}

static void
async_handler(int sig, siginfo_t *si, void *ucv)
{
    a64p_worker_t *w = a64p_cur;
    ucontext_t *uc = (ucontext_t *)ucv;
    if (w == NULL || !w->async_on || w->na >= MAXA)
        return;
    arec_t *r = &w->alog[w->na];
    r->sig = sig;
    r->run = a64p_run_id(w);
    r->pc = uc->uc_mcontext.pc;
    r->sp = uc->uc_mcontext.sp;
    r->pstate = uc->uc_mcontext.pstate;
    memcpy(r->x, uc->uc_mcontext.regs, sizeof(r->x));
    struct a64p_fpsimd_rec *fp =
        (struct a64p_fpsimd_rec *)a64p_find_rec(uc, FPSIMD_MAGIC_);
    if (fp != NULL) {
        r->fpsr = fp->fpsr;
        r->fpcr = fp->fpcr;
        r->vhash = a64p_vhash(fp->v, w->vres);
        if (w->vres >= 0)
            r->vres_lo = (uint64_t)fp->v[w->vres];
    } else
        r->vhash = 0;
    r->dhash = a64p_hash_bytes((void *)D_ADDR, D_SIZE, 0xcbf29ce484222325ULL);
    r->applied = 0;
    if (w->in_block && r->pc >= w->blk_lo && r->pc <= w->exit_pc && w->xres >= 0) {
        /* Change state the block never reads: it must survive the sigreturn. */
        uint64_t delta = 0x10001ULL * (uint64_t)(w->na + 1);
        uc->uc_mcontext.regs[w->xres] += delta;
        if (fp != NULL && w->vres >= 0)
            *(uint64_t *)&fp->v[w->vres] += delta;
        r->applied = 1;
        w->delta_sum += delta;
    }
    w->na++;
}

void
a64p_install_handlers(a64p_worker_t *w, int altstack)
{
    struct sigaction sa;
    a64p_worker_bind(w);
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sync_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | (altstack ? SA_ONSTACK : 0);
    sigemptyset(&sa.sa_mask);
    if (altstack) {
        if (w->altstk.ss_sp == NULL) {
            w->altstk.ss_size = 256 * 1024;
            w->altstk.ss_sp = malloc(w->altstk.ss_size);
        }
        w->altstk.ss_flags = 0;
        sigaltstack(&w->altstk, NULL);
    }
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sa.sa_sigaction = async_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | (altstack ? SA_ONSTACK : 0);
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGRTMIN + 2, &sa, NULL);
}

/***************************************************************************
 * Memory and code installation.
 */
int
a64p_init_features(void)
{
    unsigned long h1 = getauxval(AT_HWCAP), h2 = getauxval(AT_HWCAP2);
    feat.lse = (h1 & HWCAP_ATOMICS) != 0;
    feat.pauth = (h1 & HWCAP_PACA) != 0;
    feat.pacg = (h1 & HWCAP_PACG) != 0;
    feat.dit = (h1 & HWCAP_DIT) != 0;
    feat.fp16 = (h1 & HWCAP_FPHP) != 0 && (h1 & HWCAP_ASIMDHP) != 0;
    feat.jscvt = (h1 & HWCAP_JSCVT) != 0;
    feat.fcma = (h1 & HWCAP_FCMA) != 0;
    feat.lrcpc = (h1 & HWCAP_LRCPC) != 0;
    feat.dotprod = (h1 & HWCAP_ASIMDDP) != 0;
    feat.rdm = (h1 & HWCAP_ASIMDRDM) != 0;
    feat.flagm = (h1 & HWCAP_FLAGM) != 0;
    feat.flagm2 = (h2 & HWCAP2_FLAGM2) != 0;
    feat.frint = (h2 & HWCAP2_FRINT) != 0;
    feat.i8mm = (h2 & HWCAP2_I8MM) != 0;
    feat.bf16 = (h2 & HWCAP2_BF16) != 0;
    feat.aes = (h1 & HWCAP_AES) != 0;
    feat.crc32 = (h1 & HWCAP_CRC32) != 0;
    feat.sb = (h1 & HWCAP_SB) != 0;
    feat.afp = (h2 & HWCAP2_AFP) != 0;
    feat.sha2 = (h1 & HWCAP_SHA2) != 0;
    uint64_t dczid;
    __asm__ volatile("mrs %0, dczid_el0" : "=r"(dczid));
    int dczva_ok = !(dczid & 16) && (4ULL << (dczid & 15)) == 64;
    gen_dczva_ok = dczva_ok;
    return dczva_ok;
}

/* Every protection change matters to an oracle (the guard page is the fault
 * oracle; code protection decides how DR sees the code): never ignore one.
 */
static void
xmprotect(uint64_t addr, uint64_t size, int prot)
{
    if (mprotect((void *)addr, size, prot) != 0) {
        fprintf(stderr, "ERROR: mprotect(0x%llx, 0x%llx, %d) failed (page size %ld)\n",
                (unsigned long long)addr, (unsigned long long)size, prot,
                sysconf(_SC_PAGESIZE));
        exit(2);
    }
}

void
a64p_setup_maps(void)
{
    void *p = mmap((void *)DATA_BASE, DATA_MAP_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p != (void *)DATA_BASE) {
        fprintf(stderr, "ERROR: cannot map data at 0x%llx\n",
                (unsigned long long)DATA_BASE);
        exit(2);
    }
    xmprotect(GUARD_ADDR, GUARD_SIZE, PROT_NONE);
    ((harn_t *)HARN_ADDR)->run_id = -1;
}

void
a64p_sync_icache(uint64_t start, uint64_t len, int honour_dic)
{
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uint64_t dline = 4ULL << ((ctr >> 16) & 15), iline = 4ULL << (ctr & 15);
    if (!honour_dic || !(ctr & (1ULL << 28))) {
        for (uint64_t a = start & ~(dline - 1); a < start + len; a += dline)
            __asm__ volatile("dc cvau, %0" : : "r"(a) : "memory");
    }
    __asm__ volatile("dsb ish" : : : "memory");
    if (!honour_dic || !(ctr & (1ULL << 29))) {
        for (uint64_t a = start & ~(iline - 1); a < start + len; a += iline)
            __asm__ volatile("ic ivau, %0" : : "r"(a) : "memory");
        __asm__ volatile("dsb ish" : : : "memory");
    }
    __asm__ volatile("isb" : : : "memory");
}

void
a64p_install_code(a64p_worker_t *w, block_t *b, int mode)
{
    size_t len = (size_t)b->a.n * 4;
    if (mode == 0 || w->code_mapped_mode != mode) {
        munmap((void *)CODE_BASE, CODE_SIZE);
        int prot =
            mode == 1 ? PROT_READ | PROT_WRITE | PROT_EXEC : PROT_READ | PROT_WRITE;
        void *p = mmap((void *)CODE_BASE, CODE_SIZE, prot,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (p != (void *)CODE_BASE) {
            fprintf(stderr, "ERROR: cannot map code at 0x%llx\n",
                    (unsigned long long)CODE_BASE);
            exit(2);
        }
        w->code_mapped_mode = mode;
        if (mode == 2 || mode == 3)
            xmprotect(CODE_BASE, CODE_SIZE, PROT_READ | PROT_EXEC);
    }
    if (mode == 2 || mode == 3)
        xmprotect(CODE_BASE, CODE_SIZE, PROT_READ | PROT_WRITE);
    memcpy((void *)CODE_BASE, b->a.w, len);
    if (mode == 0)
        xmprotect(CODE_BASE, CODE_SIZE, PROT_READ | PROT_EXEC);
    else if (mode == 2 || mode == 3)
        xmprotect(CODE_BASE, CODE_SIZE, PROT_READ | PROT_EXEC);
    if (mode == 0)
        __builtin___clear_cache((char *)CODE_BASE, (char *)CODE_BASE + len);
    else
        a64p_sync_icache(CODE_BASE, len, mode == 3);
    w->code_hi = CODE_BASE + len;
}

void
a64p_prepare_run(a64p_worker_t *w, block_t *b)
{
    harn_t *h = w->harn;
    memcpy((void *)D_ADDR, b->d, D_SIZE);
    memcpy((void *)STK_CMP_LO, b->stk, STK_CMP);
    h->in = b->in;
    memset(&h->out, 0xee, sizeof(h->out));
    w->blk_lo = pc_of(b->block_start);
    w->exit_pc = pc_of(b->exit_start);
    w->blk_hi = w->exit_pc;
    w->code_hi = CODE_BASE + (uint64_t)b->a.n * 4;
    w->nf = 0;
}

static void
finish_run(void)
{
    if (feat.dit)
        __asm__ volatile(".inst 0xd503405f" ::: "memory"); /* msr dit, #0 */
}

_Static_assert(offsetof(harn_t, host_sp) == 1600, "run_code uses this offset");
_Static_assert(offsetof(harn_t, run_id) == 1616, "run_code uses this offset");

void
a64p_run_block_id(a64p_worker_t *w, block_t *b, result_t *res, int run)
{
    harn_t *h = w->harn;
    a64p_prepare_run(w, b);
    w->in_block = 1;
    run_code(CODE_BASE, h, run);
    w->in_block = 0;
    finish_run();
    res->out = h->out;
    memcpy(res->d, (void *)D_ADDR, D_SIZE);
    memcpy(res->stk, (void *)STK_CMP_LO, STK_CMP);
    res->nf = w->nf;
    memcpy(res->f, w->flog, sizeof(res->f));
}

void
a64p_run_block(a64p_worker_t *w, block_t *b, result_t *res)
{
    a64p_run_block_id(w, b, res, 0);
}

int
a64p_make_block(block_t *b, const gen_opts_t *o, uint64_t seed)
{
    for (int attempt = 0; attempt < 8; attempt++) {
        /* Retries use a derived seed so the mapping stays deterministic. */
        if (gen_block(b, seed + attempt * 0x100000000ULL, o))
            return 1;
    }
    return 0;
}

/***************************************************************************
 * Comparison and reporting.
 */
int
a64p_cmp_fault(FILE *o, int i, fault_rec_t *n, fault_rec_t *d)
{
    int bad = 0;
#define FCMP(field, fmt, type)                                                        \
    do {                                                                              \
        if (n->field != d->field) {                                                   \
            fprintf(o, "    fault[%d] %-14s native " fmt "  dr " fmt "\n", i, #field, \
                    (type)n->field, (type)d->field);                                  \
            bad++;                                                                    \
        }                                                                             \
    } while (0)
    FCMP(signo, "%d", int);
    FCMP(code, "%d", int);
    FCMP(addr, "0x%llx", unsigned long long);
    FCMP(pc, "0x%llx", unsigned long long);
    FCMP(sp, "0x%llx", unsigned long long);
    /* Bits in a64p_fault_pstate_ignore are the test's named known deviations:
     * report each masked difference to it rather than dropping it.
     */
    if (((n->pstate ^ d->pstate) & ~a64p_fault_pstate_ignore) != 0) {
        fprintf(o, "    fault[%d] pstate         native 0x%llx  dr 0x%llx\n", i,
                (unsigned long long)n->pstate, (unsigned long long)d->pstate);
        bad++;
    } else if (n->pstate != d->pstate && a64p_on_masked_pstate != NULL)
        a64p_on_masked_pstate(i, n, d);
    /* For BRK the kernel leaves the previous fault's FAR and ESR in the frame. */
    if (n->signo != SIGTRAP) {
        FCMP(fault_address, "0x%llx", unsigned long long);
        FCMP(has_esr, "%d", int);
        FCMP(esr, "0x%llx", unsigned long long);
    }
    FCMP(has_fp, "%d", int);
    FCMP(fpsr, "0x%x", unsigned int);
    FCMP(fpcr, "0x%x", unsigned int);
    for (int r = 0; r < 31; r++) {
        if (n->x[r] != d->x[r]) {
            fprintf(o, "    fault[%d] x%-13d native 0x%llx  dr 0x%llx\n", i, r,
                    (unsigned long long)n->x[r], (unsigned long long)d->x[r]);
            bad++;
        }
    }
    for (int r = 0; r < 32; r++) {
        if (n->v[r] != d->v[r]) {
            fprintf(
                o, "    fault[%d] v%-13d native 0x%016llx%016llx  dr 0x%016llx%016llx\n",
                i, r, (unsigned long long)(n->v[r] >> 64), (unsigned long long)n->v[r],
                (unsigned long long)(d->v[r] >> 64), (unsigned long long)d->v[r]);
            bad++;
        }
    }
#undef FCMP
    return bad;
}

int
a64p_cmp_state(FILE *o, const char *what, cpu_state_t *n, cpu_state_t *d, int xres,
               uint64_t xadj, int vres, uint64_t vadj)
{
    int bad = 0;
    for (int r = 0; r < 31; r++) {
        uint64_t exp = n->x[r] + (r == xres ? xadj : 0);
        if (exp != d->x[r]) {
            fprintf(o, "    %s x%-3d native 0x%016llx  dr 0x%016llx\n", what, r,
                    (unsigned long long)exp, (unsigned long long)d->x[r]);
            bad++;
        }
    }
#define SCMP(f)                                                                  \
    do {                                                                         \
        if (n->f != d->f) {                                                      \
            fprintf(o, "    %s %-4s native 0x%016llx  dr 0x%016llx\n", what, #f, \
                    (unsigned long long)n->f, (unsigned long long)d->f);         \
            bad++;                                                               \
        }                                                                        \
    } while (0)
    SCMP(sp);
    SCMP(nzcv);
    SCMP(fpsr);
    SCMP(fpcr);
#undef SCMP
    for (int r = 0; r < 32; r++) {
        __uint128_t exp = n->v[r] + (r == vres ? (__uint128_t)vadj : 0);
        if (r == vres)
            exp = (n->v[r] & ~(__uint128_t)~0ULL) | (uint64_t)((uint64_t)n->v[r] + vadj);
        if (exp != d->v[r]) {
            fprintf(o, "    %s v%-3d native 0x%016llx%016llx  dr 0x%016llx%016llx\n",
                    what, r, (unsigned long long)(exp >> 64), (unsigned long long)exp,
                    (unsigned long long)(d->v[r] >> 64), (unsigned long long)d->v[r]);
            bad++;
        }
    }
    return bad;
}

int
a64p_cmp_mem(FILE *o, block_t *b, result_t *n, result_t *d)
{
    int bad = 0;
    for (uint64_t i = 0; i < D_SIZE; i++) {
        if (n->d[i] != d->d[i]) {
            if (bad < 16) {
                fprintf(o, "    mem D+0x%03llx (0x%llx) native 0x%02x  dr 0x%02x\n",
                        (unsigned long long)i, (unsigned long long)(D_ADDR + i), n->d[i],
                        d->d[i]);
            }
            bad++;
        }
    }
    for (uint64_t i = 0; i < STK_CMP; i++) {
        if (b->sinit_final[i] && n->stk[i] != d->stk[i]) {
            if (bad < 16) {
                fprintf(o, "    mem stack 0x%llx native 0x%02x  dr 0x%02x\n",
                        (unsigned long long)(STK_CMP_LO + i), n->stk[i], d->stk[i]);
            }
            bad++;
        }
    }
    if (bad > 16)
        fprintf(o, "    ... %d differing bytes in total\n", bad);
    return bad;
}

int
a64p_cmp_results(FILE *o, block_t *b, result_t *n, result_t *d)
{
    int bad = a64p_cmp_state(o, "final", &n->out, &d->out, -1, 0, -1, 0);
    bad += a64p_cmp_mem(o, b, n, d);
    if (n->nf != d->nf) {
        fprintf(o, "    fault count native %d  dr %d\n", n->nf, d->nf);
        bad++;
    }
    if (d->nf > MAXF) {
        fprintf(o, "    %d faults: more than the %d a run can record\n", d->nf, MAXF);
        bad++;
    }
    for (int i = 0; i < n->nf && i < d->nf && i < MAXF; i++)
        bad += a64p_cmp_fault(o, i, &n->f[i], &d->f[i]);
    return bad;
}

void
a64p_print_faults(FILE *o, const char *who, result_t *r)
{
    for (int i = 0; i < r->nf && i < MAXF; i++) {
        fprintf(o,
                "    %s fault[%d]: sig %d code %d addr 0x%llx pc 0x%llx esr 0x%llx(%d) "
                "far 0x%llx\n",
                who, i, r->f[i].signo, r->f[i].code, (unsigned long long)r->f[i].addr,
                (unsigned long long)r->f[i].pc, (unsigned long long)r->f[i].esr,
                r->f[i].has_esr, (unsigned long long)r->f[i].fault_address);
    }
}

int
a64p_check_planned(block_t *b, result_t *r)
{
    if (r->nf > MAXF) {
        fprintf(stderr, "  %d faults: more than the %d a run can record\n", r->nf, MAXF);
        return 0;
    }
    for (int i = 0; i < r->nf; i++) {
        uint64_t pc = r->f[i].pc;
        if (pc >= pc_of(b->block_start) && pc < pc_of(b->exit_start)) {
            int idx = (int)((pc - CODE_BASE) / 4);
            if (!b->a.fault_ok[idx]) {
                fprintf(stderr, "  unplanned fault %d (sig %d) at 0x%llx: %s\n", i,
                        r->f[i].signo, (unsigned long long)pc, b->a.txt[idx]);
                for (int k = idx - 8 < b->block_start ? b->block_start : idx - 8;
                     k <= idx; k++)
                    fprintf(stderr, "      %llx: %s\n", (unsigned long long)pc_of(k),
                            b->a.txt[k]);
                return 0;
            }
        } else if (!b->wild_branch) {
            fprintf(stderr, "  unplanned fault %d (sig %d) outside the block at 0x%llx\n",
                    i, r->f[i].signo, (unsigned long long)pc);
            return 0;
        }
    }
    return 1;
}

/***************************************************************************
 * Counts and replay records.
 */
void
a64p_counts_print(FILE *o, const char *label, const a64p_counts_t *c)
{
    fprintf(o,
            "%s: generated %ld, accepted %ld, executed %ld, checked %ld, suppressed %ld, "
            "inconclusive %ld\n",
            label, c->generated, c->accepted, c->executed, c->checked, c->suppressed,
            c->inconclusive);
}

int
a64p_floor(const char *label, const char *what, long have, long floor)
{
    if (have >= floor)
        return 0;
    fprintf(stderr, "COVERAGE FAIL [%s]: %s %ld, below the floor of %ld\n", label, what,
            have, floor);
    return 1;
}

static void
print_hex(FILE *o, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        fprintf(o, "%02x", p[i]);
}

void
a64p_print_replay_data(FILE *f, block_t *b)
{
    fprintf(f, "d ");
    print_hex(f, b->d, D_SIZE);
    fprintf(f, "\nstk ");
    print_hex(f, b->stk, STK_CMP);
    fprintf(f, "\n");
}

void
a64p_print_replay(FILE *o, const char *prog, const char *mode, const variant_t *v,
                  block_t *b)
{
    const char *base = getenv("DYNAMORIO_OPTIONS");
    fprintf(o,
            "A64P-REPLAY v1 prog=%s mode=%s variant=%s seed=%llu dr_ops=\"%s%s%s\" "
            "page=%ld hwcap=0x%lx hwcap2=0x%lx\n",
            prog, mode, v == NULL ? "native" : v->name, (unsigned long long)b->seed,
            base == NULL ? "" : base, base == NULL ? "" : " ", v == NULL ? "" : v->dr_ops,
            sysconf(_SC_PAGESIZE), getauxval(AT_HWCAP), getauxval(AT_HWCAP2));
    fprintf(o, "A64P-REPLAY words n=%d block=%d exit=%d xres=%d vres=%d:", b->a.n,
            b->block_start, b->exit_start, b->xres, b->vres);
    for (int i = 0; i < b->a.n; i++)
        fprintf(o, " %08x", b->a.w[i]);
    fprintf(o, "\nA64P-REPLAY in:");
    for (int i = 0; i < 31; i++)
        fprintf(o, " %llx", (unsigned long long)b->in.x[i]);
    fprintf(o, " sp=%llx nzcv=%llx fpsr=%llx fpcr=%llx", (unsigned long long)b->in.sp,
            (unsigned long long)b->in.nzcv, (unsigned long long)b->in.fpsr,
            (unsigned long long)b->in.fpcr);
    for (int i = 0; i < 32; i++) {
        fprintf(o, " v%d=%016llx%016llx", i, (unsigned long long)(b->in.v[i] >> 64),
                (unsigned long long)b->in.v[i]);
    }
    fprintf(o, "\nA64P-REPLAY mem: d hash 0x%llx, stack hash 0x%llx",
            (unsigned long long)a64p_hash_bytes(b->d, D_SIZE, 0xcbf29ce484222325ULL),
            (unsigned long long)a64p_hash_bytes(b->stk, STK_CMP, 0xcbf29ce484222325ULL));
    const char *dir = getenv("A64P_REPLAY_DIR");
    if (dir != NULL) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s-%s-%s-%llu.replay", dir, prog, mode,
                 v == NULL ? "native" : v->name, (unsigned long long)b->seed);
        FILE *f = fopen(path, "w");
        if (f != NULL) {
            a64p_print_replay_data(f, b);
            fclose(f);
            fprintf(o, " (contents in %s)", path);
        }
    }
    fprintf(o, "\n");
}

/***************************************************************************
 * Native single-step tracing with ptrace.
 */
struct user_regs_ {
    uint64_t regs[31], sp, pc, pstate;
};
struct user_fp_ {
    __uint128_t vregs[32];
    uint32_t fpsr, fpcr, res[2];
};

int
a64p_trace_block(a64p_worker_t *w, block_t *b, trace_t *t)
{
    return a64p_trace_run(w, b, t, 0);
}

int
a64p_trace_run(a64p_worker_t *w, block_t *b, trace_t *t, int flags)
{
    t->n = 0;
    pid_t pid = fork();
    if (pid == 0) {
        a64p_prepare_run(w, b);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        w->in_block = 1;
        run_code(CODE_BASE, w->harn, 0);
        _exit(0);
    }
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFSTOPPED(st))
        return -1;
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
    uint64_t lo = pc_of(b->block_start), hi = pc_of(b->exit_start);
    if (flags & A64P_TRACE_WHOLE_RUN) {
        lo = CODE_BASE;
        hi = CODE_BASE + 4ULL * b->a.n; /* exclusive here */
    }
    int sig = 0, ok = -1;
    long nsteps = 0;
    uint64_t skip_bp = 0;
    long skip_orig = 0;
    for (;;) {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, (void *)(long)sig) != 0)
            break;
        sig = 0;
        if (waitpid(pid, &st, 0) != pid)
            break;
        if (WIFEXITED(st) || WIFSIGNALED(st))
            break;
        if (WSTOPSIG(st) != SIGTRAP) {
            sig = WSTOPSIG(st);
            if (t->n > 0 && t->steps[t->n - 1].sig == 0) {
                /* A signal raised by the step just recorded (its pc is still the
                 * instruction's): note it on that step.
                 */
                struct user_regs_ sregs;
                struct iovec siov = { &sregs, sizeof(sregs) };
                if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &siov) == 0 &&
                    sregs.pc == t->steps[t->n - 1].pc)
                    t->steps[t->n - 1].sig = sig;
            }
            continue;
        }
        siginfo_t si;
        if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0 && si.si_code == TRAP_BRKPT) {
            if (skip_bp != 0) {
                /* Our breakpoint after an exclusive loop: restore and go on. */
                ptrace(PTRACE_POKEDATA, pid, (void *)skip_bp, (void *)skip_orig);
                skip_bp = 0;
            } else {
                sig = SIGTRAP; /* a BRK in the block: deliver it */
                continue;
            }
        }
        if (++nsteps > 4000000)
            break;
        struct user_regs_ regs;
        struct iovec iov = { &regs, sizeof(regs) };
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0)
            break;
        if (flags & A64P_TRACE_WHOLE_RUN) {
            if (regs.pc < lo || regs.pc >= hi) {
                if (t->n > 0 && a64p_pc_in_trampoline(regs.pc)) {
                    /* Back in the trampoline after the exit stub's ret.  (Other
                     * pcs outside the code are signal handlers: skipped.)
                     */
                    ok = t->n;
                    break;
                }
                continue;
            }
        } else if (regs.pc < lo || regs.pc > hi)
            continue;
        int idx = (int)((regs.pc - CODE_BASE) / 4);
        if (b->a.excl_skip[idx] != 0 && skip_bp == 0 && (flags & A64P_TRACE_EXCL_HEAD)) {
            /* Record the loop head (the state before the exclusive load) too:
             * the consumer sees the head followed directly by the instruction
             * after the loop.
             */
            if (t->n >= t->cap) {
                ok = -1;
                break;
            }
            tstep_t *s = &t->steps[t->n++];
            memset(s, 0, sizeof(*s));
            s->pc = regs.pc;
            s->sp = regs.sp;
            s->pstate = regs.pstate;
            memcpy(s->x, regs.regs, sizeof(s->x));
        }
        if (b->a.excl_skip[idx] != 0 && skip_bp == 0) {
            /* Single-stepping an exclusive loop never succeeds: run to its end.
             * The steps inside the loop are not recorded.
             */
            skip_bp = pc_of(b->a.excl_skip[idx]) & ~7ULL;
            errno = 0;
            skip_orig = ptrace(PTRACE_PEEKDATA, pid, (void *)skip_bp, 0);
            if (errno != 0)
                break;
            uint64_t patched = (uint64_t)skip_orig;
            int shift = (pc_of(b->a.excl_skip[idx]) & 4) ? 32 : 0;
            patched =
                (patched & ~(0xffffffffULL << shift)) | ((uint64_t)0xd4200000u << shift);
            ptrace(PTRACE_POKEDATA, pid, (void *)skip_bp, (void *)patched);
            if (ptrace(PTRACE_CONT, pid, 0, 0) != 0)
                break;
            /* Signals other than our breakpoint must not happen in the loop. */
            if (waitpid(pid, &st, 0) != pid || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP)
                break;
            ptrace(PTRACE_POKEDATA, pid, (void *)skip_bp, (void *)skip_orig);
            skip_bp = 0;
            /* Now stopped at the breakpoint, i.e. the instruction after the loop:
             * record it as a step below.
             */
            struct iovec iov3 = { &regs, sizeof(regs) };
            if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov3) != 0)
                break;
        }
        /* The kernel reports a second stop at the same pc after a sigreturn and
         * for an emulated MRS of an ID register: blocks never branch to self.
         */
        if (t->n > 0 && t->steps[t->n - 1].pc == regs.pc)
            continue;
        if (t->n >= t->cap) {
            ok = -1;
            break;
        }
        tstep_t *s = &t->steps[t->n++];
        s->pc = regs.pc;
        s->sp = regs.sp;
        s->pstate = regs.pstate;
        s->sig = 0;
        memcpy(s->x, regs.regs, sizeof(s->x));
        struct user_fp_ fp;
        struct iovec iov2 = { &fp, sizeof(fp) };
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRFPREG, &iov2) != 0)
            break;
        s->fpsr = fp.fpsr;
        s->fpcr = fp.fpcr;
        s->vhash = a64p_vhash(fp.vregs, b->vres);
        s->dhash = 0;
        if (t->want_dhash) {
            static uint8_t dbuf[D_SIZE];
            struct iovec l = { dbuf, D_SIZE }, r = { (void *)D_ADDR, D_SIZE };
            if (process_vm_readv(pid, &l, 1, &r, 1, 0) != (ssize_t)D_SIZE)
                break;
            s->dhash = a64p_hash_bytes(dbuf, D_SIZE, 0xcbf29ce484222325ULL);
        }
        if (!(flags & A64P_TRACE_WHOLE_RUN) && regs.pc == hi) {
            ok = t->n;
            break;
        }
    }
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    return ok;
}

/***************************************************************************
 * Asynchronous signal sources.
 */
const char *
a64p_sigsrc_name(int src)
{
    return src == 0 ? "itimer" : src == 1 ? "posix-timer" : "tgkill-thread";
}

void
a64p_sigsrc_init(a64p_sigsrc_t *s, a64p_worker_t *w)
{
    memset(s, 0, sizeof(*s));
    s->w = w;
    s->period_scale = 1;
    s->helper_spin_max = 20000;
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = SIGRTMIN + 2;
    s->main_tid = (pid_t)syscall(SYS_gettid);
    sev._sigev_un._tid = s->main_tid;
    s->posix_timer_ok = timer_create(CLOCK_MONOTONIC, &sev, &s->posix_timer) == 0;
}

/* Sends one SIGUSR1 per block run, after a random spin once the run has
 * started, so that most signals land inside the block.
 */
static void *
helper_thread(void *arg)
{
    a64p_sigsrc_t *s = (a64p_sigsrc_t *)arg;
    a64p_worker_t *w = s->w;
    rng_t r = { s->helper_seed };
    int last = -1;
    __atomic_store_n(&s->helper_ready, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&s->helper_on, __ATOMIC_ACQUIRE)) {
        int run = a64p_run_id(w);
        if (run < 0 || run == last) {
            sched_yield();
            continue;
        }
        last = run;
        for (volatile int i = (int)rn(&r, (uint32_t)s->helper_spin_max); i > 0; i--)
            ;
        if (__atomic_load_n(&s->helper_on, __ATOMIC_ACQUIRE))
            syscall(SYS_tgkill, getpid(), s->main_tid, SIGUSR1);
    }
    return NULL;
}

int
a64p_sigsrc_arm(a64p_sigsrc_t *s, int src, rng_t *r)
{
    long first = (long)(1 + rn(r, 50)) * s->period_scale;
    long period = (long)(15 + rn(r, 80)) * s->period_scale;
    if (src == 0) {
        struct itimerval it;
        it.it_value.tv_sec = 0;
        it.it_value.tv_usec = first;
        it.it_interval.tv_sec = 0;
        it.it_interval.tv_usec = period;
        if (setitimer(ITIMER_REAL, &it, NULL) != 0) {
            perror("ERROR: setitimer");
            return 0;
        }
    } else if (src == 1) {
        struct itimerspec its;
        its.it_value.tv_sec = 0;
        its.it_value.tv_nsec = first * 1000;
        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = period * 1000;
        if (!s->posix_timer_ok || timer_settime(s->posix_timer, 0, &its, NULL) != 0) {
            fprintf(stderr, "ERROR: POSIX timer unavailable (timer_create ok=%d)\n",
                    s->posix_timer_ok);
            return 0;
        }
    } else {
        __atomic_store_n(&s->helper_on, 1, __ATOMIC_RELEASE);
        __atomic_store_n(&s->helper_ready, 0, __ATOMIC_RELEASE);
        s->helper_seed = rnext(r);
        if (pthread_create(&s->helper, NULL, helper_thread, s) != 0) {
            fprintf(stderr, "ERROR: cannot create the signal helper thread\n");
            s->helper_on = 0;
            return 0;
        }
        /* Thread creation under DR can take longer than a whole batch of runs:
         * wait until the helper is polling.
         */
        for (int i = 0; !__atomic_load_n(&s->helper_ready, __ATOMIC_ACQUIRE); i++) {
            if (i > 100000) {
                fprintf(stderr, "ERROR: the signal helper thread did not start\n");
                return 0;
            }
            sched_yield();
        }
    }
    return 1;
}

void
a64p_sigsrc_disarm(a64p_sigsrc_t *s, int src)
{
    if (src == 0) {
        struct itimerval it;
        memset(&it, 0, sizeof(it));
        setitimer(ITIMER_REAL, &it, NULL);
    } else if (src == 1) {
        struct itimerspec its;
        memset(&its, 0, sizeof(its));
        if (s->posix_timer_ok)
            timer_settime(s->posix_timer, 0, &its, NULL);
    } else {
        __atomic_store_n(&s->helper_on, 0, __ATOMIC_RELEASE);
        pthread_join(s->helper, NULL);
    }
}

static uint64_t
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void
a64p_sigsrc_calibrate(a64p_sigsrc_t *s, block_t *b)
{
    result_t *tmp = malloc(sizeof(*tmp));
    uint64_t t0 = now_ns();
    for (int i = 0; i < 20; i++)
        a64p_run_block(s->w, b, tmp);
    uint64_t per_run = (now_ns() - t0) / 20;
    t0 = now_ns();
    for (volatile int i = 1000000; i > 0; i--)
        ;
    uint64_t per_1m = now_ns() - t0;
    uint64_t spins = per_1m == 0 ? 1000 : per_run * 1000000ULL / per_1m;
    s->helper_spin_max = (int)(spins < 100 ? 100 : spins > 10000000 ? 10000000 : spins);
    free(tmp);
}

/***************************************************************************
 * DR child processes.
 */
progress_t *a64p_prog;
static const char *a64p_prog_name = "a64_dr_prop";

void
a64p_progress_init(const char *prog_name)
{
    a64p_prog_name = prog_name;
    a64p_prog =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

void
a64p_start_dr(const char *dr_ops)
{
#ifdef A64P_EXTERNAL_DR
    /* Built without DR, to run under drrun: there is no DR to start. */
    fprintf(stderr, "ERROR: this build cannot start DR (options %s)\n", dr_ops);
    _exit(3);
#else
    char buf[1024];
    const char *base = getenv("DYNAMORIO_OPTIONS");
    snprintf(buf, sizeof(buf), "%s %s", base == NULL ? "" : base, dr_ops);
    setenv("DYNAMORIO_OPTIONS", buf, 1);
    if (dr_app_setup_and_start() != 0) {
        fprintf(stderr, "ERROR: dr_app_setup_and_start failed\n");
        _exit(3);
    }
    if (!dr_app_running_under_dynamorio()) {
        fprintf(stderr, "ERROR: not running under DR\n");
        _exit(3);
    }
#endif
}

void
a64p_stop_dr(void)
{
#ifndef A64P_EXTERNAL_DR
    dr_app_stop_and_cleanup();
#endif
}

int
a64p_in_child(const char *mode, const variant_t *v, int (*fn)(void *), void *arg)
{
    progress_t *prog = a64p_prog;
    fflush(stdout);
    fflush(stderr);
    memset(prog, 0, sizeof(*prog));
    prog->block = -1;
    pid_t pid = fork();
    if (pid == 0) {
        int r = fn(arg);
        snprintf(prog->phase, sizeof(prog->phase), "done");
        fflush(stdout);
        fflush(stderr);
        _exit(r > 250 ? 250 : r);
    }
    int st;
    waitpid(pid, &st, 0);
    if (WIFEXITED(st) && strcmp(prog->phase, "done") == 0)
        return WEXITSTATUS(st);
    if (WIFEXITED(st)) {
        fprintf(stderr,
                "FAIL [%s] variant=%s: child exited early (status %d) in block %d (seed "
                "%llu) "
                "run %d phase '%s'\n  repro: %s %s -seed %llu -n 1 -variants %s "
                "-v\n",
                mode, v->name, WEXITSTATUS(st), prog->block,
                (unsigned long long)prog->seed, prog->run, prog->phase, a64p_prog_name,
                mode, (unsigned long long)prog->seed, v->name);
        return 1;
    }
    fprintf(stderr,
            "FAIL [%s] variant=%s: child died with signal %d in block %d (seed %llu) run "
            "%d phase '%s'\n  repro: %s %s -seed %llu -n 1 -variants %s -v\n",
            mode, v->name, WIFSIGNALED(st) ? WTERMSIG(st) : -1, prog->block,
            (unsigned long long)prog->seed, prog->run, prog->phase, a64p_prog_name, mode,
            (unsigned long long)prog->seed, v->name);
    return 1;
}

/***************************************************************************
 * Additions for the signal ABI property.
 */
static uint64_t
now_ns_mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int
a64p_in_child_timeout(const char *mode, const variant_t *v, int (*fn)(void *), void *arg,
                      int timeout_s)
{
    progress_t *prog = a64p_prog;
    fflush(stdout);
    fflush(stderr);
    memset(prog, 0, sizeof(*prog));
    prog->block = -1;
    pid_t pid = fork();
    if (pid == 0) {
        int r = fn(arg);
        snprintf(prog->phase, sizeof(prog->phase), "done");
        fflush(stdout);
        fflush(stderr);
        _exit(r > 250 ? 250 : r);
    }
    int st = 0;
    uint64_t deadline = now_ns_mono() + (uint64_t)timeout_s * 1000000000ULL;
    for (;;) {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid)
            break;
        if (w < 0 && errno != EINTR) {
            fprintf(stderr, "FAIL [%s] variant=%s: waitpid failed\n", mode, v->name);
            return 1;
        }
        if (now_ns_mono() > deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
            fprintf(stderr,
                    "FAIL [%s] variant=%s: HANG: child still running after %d s in case "
                    "%d (seed %llu) run %d phase '%s'\n  repro: %s %s -seed %llu -only "
                    "%d -variants %s -v\n",
                    mode, v->name, timeout_s, prog->block, (unsigned long long)prog->seed,
                    prog->run, prog->phase, a64p_prog_name, mode,
                    (unsigned long long)prog->seed, prog->block, v->name);
            return 1;
        }
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    if (WIFEXITED(st) && strcmp(prog->phase, "done") == 0)
        return WEXITSTATUS(st);
    fprintf(stderr,
            "FAIL [%s] variant=%s: child %s %d in case %d (seed %llu) run %d phase "
            "'%s'\n  repro: %s %s -seed %llu -only %d -variants %s -v\n",
            mode, v->name,
            WIFEXITED(st) ? "exited early with status" : "died with signal",
            WIFEXITED(st)         ? WEXITSTATUS(st)
                : WIFSIGNALED(st) ? WTERMSIG(st)
                                  : -1,
            prog->block, (unsigned long long)prog->seed, prog->run, prog->phase,
            a64p_prog_name, mode, (unsigned long long)prog->seed, prog->block, v->name);
    return 1;
}

#define SVE_MAGIC_ 0x53564501
#define ZA_MAGIC_ 0x54366345
#define ZT_MAGIC_ 0x5a544e01
#define TPIDR2_MAGIC_ 0x54504902
#define FPMR_MAGIC_ 0x46504d52
#define POE_MAGIC_ 0x504f4530
#define GCS_MAGIC_ 0x47435300

/* Walks one record list of limit bytes at base; extra (if not NULL) receives
 * an EXTRA record.  Returns 0 or writes an error.
 */
static int
check_record_list(const uint8_t *base, size_t limit, int top, uint64_t *layout,
                  uint32_t *seen, int *sve_vl, int *za_vl,
                  const struct a64p_extra_rec **extra, char *err, size_t errlen)
{
    size_t off = 0;
    for (int n = 0;; n++) {
        if (off + sizeof(struct a64p_rec_head) > limit) {
            snprintf(err, errlen, "%s list not terminated within %zu bytes",
                     top ? "__reserved" : "extra", limit);
            return 1;
        }
        const struct a64p_rec_head *h = (const struct a64p_rec_head *)(base + off);
        uint32_t magic = h->magic, size = h->size;
        *layout = (*layout ^ magic) * 0x100000001b3ULL;
        *layout = (*layout ^ size) * 0x100000001b3ULL;
        if (magic == 0) {
            if (size != 0) {
                snprintf(err, errlen, "terminator at +%zu has size %u", off, size);
                return 1;
            }
            return 0;
        }
        if (top && n == 0 && magic != FPSIMD_MAGIC_) {
            snprintf(err, errlen, "first record is 0x%x, not FPSIMD", magic);
            return 1;
        }
        if (size < 16 || size % 16 != 0 || size > limit - off) {
            snprintf(err, errlen, "record 0x%x at +%zu has bad size %u (limit %zu)",
                     magic, off, size, limit);
            return 1;
        }
        int bit = -1;
        uint32_t need = 0, exact = 1;
        switch (magic) {
        case FPSIMD_MAGIC_:
            bit = 0;
            need = sizeof(struct a64p_fpsimd_rec);
            break;
        case ESR_MAGIC_:
            bit = 1;
            need = 16;
            break;
        case EXTRA_MAGIC_:
            bit = 2;
            need = 32;
            if (!top) {
                snprintf(err, errlen, "EXTRA record inside the extra space");
                return 1;
            }
            *extra = (const struct a64p_extra_rec *)h;
            break;
        case SVE_MAGIC_: {
            bit = 3;
            uint16_t vl = *(const uint16_t *)(base + off + 8);
            uint16_t flags = *(const uint16_t *)(base + off + 10);
            *sve_vl = vl;
            *layout = (*layout ^ ((uint64_t)vl << 16 | flags)) * 0x100000001b3ULL;
            if (vl % 16 != 0 || vl > 256 || (flags & ~1u) != 0) {
                snprintf(err, errlen, "SVE record vl %u flags 0x%x", vl, flags);
                return 1;
            }
            uint32_t vq = vl / 16;
            /* Header only, or the full register data for vl. */
            uint32_t full = 16 + vq * 16 * 32 + vq * 2 * 16 + vq * 2;
            if (size != 16 && size < full) {
                snprintf(err, errlen,
                         "SVE record size %u: neither 16 nor >= %u for vl %u", size, full,
                         vl);
                return 1;
            }
            exact = 0;
            break;
        }
        case ZA_MAGIC_: {
            bit = 4;
            uint16_t vl = *(const uint16_t *)(base + off + 8);
            *za_vl = vl;
            *layout = (*layout ^ vl) * 0x100000001b3ULL;
            uint32_t vq = vl / 16;
            if (vl % 16 != 0 || vl > 256 || (size != 16 && size < 16 + vl * vl)) {
                snprintf(err, errlen, "ZA record vl %u size %u (vq %u)", vl, size, vq);
                return 1;
            }
            exact = 0;
            break;
        }
        case ZT_MAGIC_: {
            bit = 5;
            uint16_t nregs = *(const uint16_t *)(base + off + 8);
            if (nregs == 0 || size != 16 + 64u * nregs) {
                snprintf(err, errlen, "ZT record nregs %u size %u", nregs, size);
                return 1;
            }
            exact = 0;
            break;
        }
        case TPIDR2_MAGIC_:
            bit = 6;
            need = 16;
            break;
        case FPMR_MAGIC_:
            bit = 7;
            need = 16;
            break;
        case POE_MAGIC_:
            bit = 8;
            need = 16;
            break;
        case GCS_MAGIC_:
            bit = 9;
            need = 32;
            break;
        default:
            snprintf(err, errlen, "unknown record magic 0x%x size %u at +%zu", magic,
                     size, off);
            return 1;
        }
        if (exact && size != need) {
            snprintf(err, errlen, "record 0x%x size %u, expected %u", magic, size, need);
            return 1;
        }
        if (*seen & (1u << bit)) {
            snprintf(err, errlen, "duplicate record 0x%x", magic);
            return 1;
        }
        *seen |= 1u << bit;
        off += size;
    }
}

int
a64p_check_frame_records(const ucontext_t *uc, uint64_t *layout, int *sve_vl, int *za_vl,
                         char *err, size_t errlen)
{
    const uint8_t *base = (const uint8_t *)uc->uc_mcontext.__reserved;
    uint32_t seen = 0;
    const struct a64p_extra_rec *extra = NULL;
    *layout = 0xcbf29ce484222325ULL;
    *sve_vl = *za_vl = -1;
    err[0] = '\0';
    if (((uintptr_t)uc & 15) != 0 || ((uintptr_t)base & 15) != 0) {
        snprintf(err, errlen, "ucontext %p / __reserved %p not 16-byte aligned", uc,
                 base);
        return 1;
    }
    if (check_record_list(base, sizeof(uc->uc_mcontext.__reserved), 1, layout, &seen,
                          sve_vl, za_vl, &extra, err, errlen))
        return 1;
    if (extra != NULL) {
        const uint8_t *p = (const uint8_t *)(uintptr_t)extra->datap;
        if (((uintptr_t)p & 15) != 0 || extra->size < 16) {
            snprintf(err, errlen, "EXTRA datap %p size %u", p, extra->size);
            return 1;
        }
        if (check_record_list(p, extra->size, 0, layout, &seen, sve_vl, za_vl, &extra,
                              err, errlen))
            return 1;
    }
    return 0;
}

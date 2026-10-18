/* **********************************************************
 * Copyright (c) 2017-2020 Google, Inc.  All rights reserved.
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

/***************************************************************************
 * signal_linux_aarch64.c - signal code for arm64 Linux
 */

#include "signal_private.h" /* pulls in globals.h for us, in right order */

#ifndef LINUX
#    error Linux-only
#endif

#ifndef AARCH64
#    error AArch64-only
#endif

#include "arch.h"

void
save_fpstate(dcontext_t *dcontext, sigframe_rt_t *frame)
{
    ASSERT_NOT_IMPLEMENTED(false); /* FIXME i#1569 */
}

void
sigcontext_set_app_pstate(sigcontext_t *sc)
{
    /* We sample only DIT: we may be in a signal handler, where TCO is not the
     * app's (see PSTATE_APP_STATE_BITS), and reading SSBS needs FEAT_SSBS.
     */
#ifndef DR_HOST_NOT_TARGET
    if (proc_has_feature(FEATURE_DIT)) {
        reg_t dit;
        asm volatile("mrs %0, s3_3_c4_c2_5" : "=r"(dit)); /* mrs %0, dit */
        sc->pstate = PSTATE_WITH_BITS_OF(sc->pstate, dit, PSTATE_DIT_BIT);
    }
#endif
}

void
sigcontext_copy_app_pstate(sigcontext_t *sc, reg_t pstate)
{
    sc->pstate = PSTATE_WITH_BITS_OF(sc->pstate, pstate, PSTATE_APP_STATE_BITS);
}

/* Returns the context record at offset in the record list at base (limit bytes
 * long), or NULL at the terminating record or if the list is malformed: a
 * record must have a nonzero size that keeps it inside the list.  The kernel
 * builds these lists, but a corrupt or hostile frame must not make us loop
 * forever or read past it.
 */
static inline struct _aarch64_ctx *
sigcontext_record_at(byte *base, size_t offset, size_t limit)
{
    if (offset > limit || limit - offset < sizeof(struct _aarch64_ctx))
        return NULL;
    struct _aarch64_ctx *head = (struct _aarch64_ctx *)(base + offset);
    if (head->magic == 0)
        return NULL;
    if (head->size < sizeof(*head) || head->size > limit - offset) {
        SYSLOG_INTERNAL_WARNING("Malformed signal context record: magic 0x%x size %u",
                                head->magic, head->size);
        return NULL;
    }
    return head;
}

#ifdef DEBUG
/* Representation of quadwords (128 bits) as 2 doublewords. */
typedef union {
    __uint128_t as_128;
    struct {
        uint64 lo;
        uint64 hi;
    } as_2x64;
} reinterpret128_2x64_t;

void
dump_sigcontext(dcontext_t *dcontext, sigcontext_t *sc)
{
#    ifdef DR_HOST_NOT_TARGET
    ASSERT_NOT_REACHED();
#    endif
    LOG(THREAD, LOG_ASYNCH, 1, "\tSignal context:\n");
    int i;
    for (i = 0; i <= DR_REG_X30 - DR_REG_X0; i++)
        LOG(THREAD, LOG_ASYNCH, 1, "\tx%-2d    = " PFX "\n", i, sc->regs[i]);
    LOG(THREAD, LOG_ASYNCH, 1, "\tsp     = " PFX "\n", sc->sp);
    LOG(THREAD, LOG_ASYNCH, 1, "\tpc     = " PFX "\n", sc->pc);
    LOG(THREAD, LOG_ASYNCH, 1, "\tpstate = " PFX "\n", sc->pstate);
    LOG(THREAD, LOG_ASYNCH, 1, "\n");

    struct _aarch64_ctx *head = (struct _aarch64_ctx *)sc->__reserved;
    ASSERT(head->magic == FPSIMD_MAGIC);
    ASSERT(head->size == sizeof(struct fpsimd_context));

    struct fpsimd_context *fpsimd = (struct fpsimd_context *)sc->__reserved;
    LOG(THREAD, LOG_ASYNCH, 2, "\tfpsr 0x%x\n", fpsimd->fpsr);
    LOG(THREAD, LOG_ASYNCH, 2, "\tfpcr 0x%x\n", fpsimd->fpcr);
    reinterpret128_2x64_t vreg;
    for (i = 0; i < MCXT_NUM_SIMD_SVE_SLOTS; i++) {
        vreg.as_128 = fpsimd->vregs[i];
        LOG(THREAD, LOG_ASYNCH, 2, "\tq%-2d  0x%016lx %016lx\n", i, vreg.as_2x64.hi,
            vreg.as_2x64.lo);
    }
    LOG(THREAD, LOG_ASYNCH, 2, "\n");

#    ifndef DR_HOST_NOT_TARGET
    if (proc_has_feature(FEATURE_SVE)) {
        size_t offset = sizeof(struct fpsimd_context);
        struct _aarch64_ctx *next_head;
        while ((next_head = sigcontext_record_at(sc->__reserved, offset,
                                                 sizeof(sc->__reserved))) != NULL) {
            switch (next_head->magic) {
            case ESR_MAGIC: break;
            case EXTRA_MAGIC: break;
            case SVE_MAGIC: {
                const struct sve_context *sve = (struct sve_context *)(next_head);
                LOG(THREAD, LOG_ASYNCH, 2, "\tSVE vector length %d bytes\n", sve->vl);
                const unsigned int quads_per_vector = sve_vecquad_from_veclen(sve->vl);
                /* Only a record with live state has register data to show. */
                if (sve->head.size < SVE_SIG_CONTEXT_SIZE(quads_per_vector)) {
                    LOG(THREAD, LOG_ASYNCH, 2, "\tno SVE register data\n\n");
                    break;
                }
                /* The size and offset macros below are used to access register
                 * state from memory. These are defined in the kernel's
                 * sigcontext.h. For scalable vectors, we typically deal in
                 * units of bytes and quadwords (128 bits). All scalable
                 * vectors are mutiples of 128 bits. For the purposes of signal
                 * context handling, these are the simplest and most consistent
                 * units for calculating sizes and offsets in order to access
                 * scalable register state in memory.
                 */
                LOG(THREAD, LOG_ASYNCH, 2, "\tQuadwords (128 bits) per vector %d\n\n",
                    quads_per_vector);
                LOG(THREAD, LOG_ASYNCH, 2, "\tSVE_SIG_ZREG_SIZE %d\n",
                    SVE_SIG_ZREG_SIZE(quads_per_vector));
                LOG(THREAD, LOG_ASYNCH, 2, "\tSVE_SIG_PREG_SIZE %d\n",
                    SVE_SIG_PREG_SIZE(quads_per_vector));
                LOG(THREAD, LOG_ASYNCH, 2, "\tSVE_SIG_FFR_SIZE  %d\n",
                    SVE_SIG_FFR_SIZE(quads_per_vector));
                LOG(THREAD, LOG_ASYNCH, 2, "\tsve->head.size %d\n\n", sve->head.size);
                LOG(THREAD, LOG_ASYNCH, 2, "\tSVE_SIG_ZREGS_OFFSET %d\n",
                    SVE_SIG_ZREGS_OFFSET);
                LOG(THREAD, LOG_ASYNCH, 2, "\tSVE_SIG_PREGS_OFFSET %d\n",
                    SVE_SIG_PREGS_OFFSET(quads_per_vector));
                LOG(THREAD, LOG_ASYNCH, 2, "\tSVE_SIG_FFR_OFFSET   %d\n\n",
                    SVE_SIG_FFR_OFFSET(quads_per_vector));

                int boff; /* Byte offset for each doubleword in a vector. */
                for (i = 0; i < MCXT_NUM_SIMD_SVE_SLOTS; i++) {
                    LOG(THREAD, LOG_ASYNCH, 2, "\tz%-2d  0x", i);
                    for (boff = ((quads_per_vector * 2) - 1); boff >= 0; boff--) {
                        /* We access data in the scalable vector using the kernel's
                         * SVE_SIG_ZREG_OFFSET macro which gives the byte offset into a
                         * vector based on units of 128 bits (quadwords). In this loop we
                         * offset from the start of struct sve_context. We log the data
                         * as 64 bit ints, so 2 per quadword (2 x 64 bits -> 128 bits).
                         *
                         * For example, for a 256 bit vector (2 quadwords (2 x 128 bits),
                         * 4 doublewords (4 x 64 bits)), the byte offset (boff) for each
                         * scalable vector register is:
                         * boff=3  z.u64[3] = sve + SVE_SIG_ZREG_OFFSET + 24
                         * boff=2  z.u64[2] = sve + SVE_SIG_ZREG_OFFSET + 16
                         * boff=1  z.u64[1] = sve + SVE_SIG_ZREG_OFFSET + 8
                         * boff=0  z.u64[0] = sve + SVE_SIG_ZREG_OFFSET
                         *
                         * Note that at present we support little endian only.
                         * All major Linux arm64 kernel distributions are
                         * little-endian.
                         */
                        /* Not stored in a dr_simd_t: the vector may be longer. */
                        const uint64 dword = *((uint64 *)((
                            ((byte *)sve) + (SVE_SIG_ZREG_OFFSET(quads_per_vector, i)) +
                            (boff * 8))));
                        LOG(THREAD, LOG_ASYNCH, 2, "%016lx ", dword);
                    }
                    LOG(THREAD, LOG_ASYNCH, 2, "\n");
                }
                LOG(THREAD, LOG_ASYNCH, 2, "\n");
                /* We access data in predicate and first-fault registers using
                 * the kernel's SVE_SIG_PREG_OFFSET and SVE_SIG_FFR_OFFSET
                 * macros. SVE predicate and FFR registers are an 1/8th the
                 * size of SVE vector registers (1 bit per byte) and are logged
                 * as 32 bit ints.
                 */
                dr_simd_t p;
                for (i = 0; i < MCXT_NUM_SVEP_SLOTS; i++) {
                    p.u32[i] = *((uint32 *)((byte *)sve +
                                            SVE_SIG_PREG_OFFSET(quads_per_vector, i)));
                    LOG(THREAD, LOG_ASYNCH, 2, "\tp%-2d  0x%08lx\n", i, p.u32[i]);
                }
                LOG(THREAD, LOG_ASYNCH, 2, "\n");
                LOG(THREAD, LOG_ASYNCH, 2, "\tFFR  0x%08lx\n\n",
                    *((uint32 *)((byte *)sve + SVE_SIG_FFR_OFFSET(quads_per_vector))));
                break;
            }
            default:
                SYSLOG_INTERNAL_WARNING("%s %d Unknown section found in signal context "
                                        "with magic number 0x%x",
                                        __func__, __LINE__, next_head->magic);
                break;
            }
            offset += next_head->size;
        }
    }
#    endif
}
#endif /* DEBUG */

/* Representation of quadword (128 bits) as 4 words, used for SIMD. */
typedef union {
    __uint128_t as_128;
    struct {
        uint32 lowest;
        uint32 lo;
        uint32 hi;
        uint32 highest;
    } as_4x32;
} reinterpret128_4x32_t;

void
sigcontext_to_mcontext_simd(priv_mcontext_t *mc, sig_full_cxt_t *sc_full)
{
#ifdef DR_HOST_NOT_TARGET
    ASSERT_NOT_REACHED();
#endif
    struct fpsimd_context *fpc = (struct fpsimd_context *)sc_full->fp_simd_state;
    if (fpc == NULL)
        return;
    ASSERT(fpc->head.magic == FPSIMD_MAGIC);
    ASSERT(fpc->head.size == sizeof(struct fpsimd_context));
    mc->fpsr = fpc->fpsr;
    mc->fpcr = fpc->fpcr;
    ASSERT((sizeof(mc->simd->q) * MCXT_NUM_SIMD_SVE_SLOTS) == sizeof(fpc->vregs));
    int i;
    for (i = 0; i < MCXT_NUM_SIMD_SVE_SLOTS; i++) {
        memcpy(&mc->simd[i].q, &fpc->vregs[i], sizeof(mc->simd->q));
    }

#ifndef DR_HOST_NOT_TARGET
    if (proc_has_feature(FEATURE_SVE)) {
        size_t offset = sizeof(struct fpsimd_context);
        /* fpsimd_context is always the first section. After that the esr_context,
         * extra_context and sve_context sections can be in any order.
         */
        struct _aarch64_ctx *next_head;
        while ((next_head = sigcontext_record_at(sc_full->sc->__reserved, offset,
                                                 sizeof(sc_full->sc->__reserved))) !=
               NULL) {
            ASSERT(next_head->magic == ESR_MAGIC || next_head->magic == SVE_MAGIC ||
                   next_head->magic == EXTRA_MAGIC);
            switch (next_head->magic) {
            case ESR_MAGIC: break;
            case EXTRA_MAGIC: break;
            case SVE_MAGIC: {
                const struct sve_context *sve = (struct sve_context *)(next_head);
                /* A record with another vector length (e.g. SME's streaming
                 * vector length) holds state DR doesn't track.
                 */
                if (sve->vl != proc_get_vector_length_bytes())
                    break;
                const unsigned int quads_per_vector = sve_vecquad_from_veclen(sve->vl);
                /* The record only has register data if the kernel considers the
                 * SVE state live; and dr_mcontext_t holds at most 512-bit
                 * vectors, so copy no more than its slots hold.
                 */
                const size_t zsize =
                    MIN(SVE_SIG_ZREG_SIZE(quads_per_vector), sizeof(mc->simd[0]));
                const size_t psize =
                    MIN(SVE_SIG_PREG_SIZE(quads_per_vector), sizeof(mc->svep[0]));
                const size_t ffrsize =
                    MIN(SVE_SIG_FFR_SIZE(quads_per_vector), sizeof(mc->ffr));
                if (sve->head.size >= SVE_SIG_CONTEXT_SIZE(quads_per_vector)) {
                    for (i = 0; i < MCXT_NUM_SIMD_SVE_SLOTS; i++) {
                        /* SVE specifies that AArch64's SIMD&FP registers
                         * (V0-V31) which hold FP scalars and NEON 128-bit
                         * vectors overlay the bottom 128 bits of the SVE
                         * registers (Z0-Z31). For backward compatibility
                         * reasons, bits 0->127 of Z0-Z31 are always restored
                         * from the corresponding members of fpsimd_context's
                         * vregs and not from sve_context.
                         */
                        memcpy(&mc->simd[i].u32,
                               (byte *)sve + SVE_SIG_ZREG_OFFSET(quads_per_vector, i),
                               zsize);
                        memcpy(&mc->simd[i].q, &fpc->vregs[i], sizeof(mc->simd->q));
                    }
                    for (i = 0; i < MCXT_NUM_SVEP_SLOTS; i++) {
                        memcpy(&mc->svep[i].u16,
                               (byte *)sve + SVE_SIG_PREG_OFFSET(quads_per_vector, i),
                               psize);
                    }
                    memcpy(&mc->ffr, (byte *)sve + SVE_SIG_FFR_OFFSET(quads_per_vector),
                           ffrsize);
                }
                break;
            }
            default:
                SYSLOG_INTERNAL_WARNING("%s %d Unhandled section with magic number 0x%x",
                                        __func__, __LINE__, next_head->magic);
            }
            offset += next_head->size;
        }
    }
#endif
}

void
mcontext_to_sigcontext_simd(sig_full_cxt_t *sc_full, priv_mcontext_t *mc)
{
#ifdef DR_HOST_NOT_TARGET
    ASSERT_NOT_REACHED();
#else
#    define GET_RECORD_AT_OFFSET(byte_offset) \
        (void *)((byte *)sc_full->fp_simd_state + byte_offset)

    /* sig_full_initialize() will have set the fp_simd_state pointer in the
     * user level machine context's (uc_mcontext) to __reserved.
     */
    size_t offset = 0;
    struct _aarch64_ctx *next_head = GET_RECORD_AT_OFFSET(offset);

    /* Make sure sc_full->fp_simd_state is not NULL. */
    if (next_head == NULL) {
        return;
    }
    /* The records live in sigcontext's __reserved area. */
    const size_t limit = sizeof(sc_full->sc->__reserved) -
        ((byte *)sc_full->fp_simd_state - (byte *)sc_full->sc->__reserved);

    struct fpsimd_context *fpsimd = NULL;
    struct sve_context *sve = NULL;
    /* An EXTRA record must stay directly followed by the terminator and then
     * its data: we neither add nor move records around it.
     */
    bool has_extra = false;

    const struct _aarch64_ctx null_ctx = { 0 };

    /* Search for the context records we are interested in. */
    struct _aarch64_ctx *record;
    while ((record = sigcontext_record_at(sc_full->fp_simd_state, offset, limit)) !=
           NULL) {
        switch (record->magic) {
        case FPSIMD_MAGIC: fpsimd = (void *)record; break;
        case SVE_MAGIC: sve = (void *)record; break;
        case EXTRA_MAGIC: has_extra = true; break;
        default: break;
        }
        offset += record->size;
    }
    /* Stopped at the terminator, or at a malformed list: leave the latter alone. */
    if (limit - offset < sizeof(struct _aarch64_ctx) ||
        ((struct _aarch64_ctx *)GET_RECORD_AT_OFFSET(offset))->magic != 0)
        return;
    next_head = GET_RECORD_AT_OFFSET(offset);

    struct _aarch64_ctx *terminator_record = next_head;
    ASSERT(terminator_record->magic == 0);

    /* A header-only SVE record means that the scalable registers were not live
     * when the kernel delivered this signal.  Do not turn that into a full
     * record: the private mcontext has no defined P/FFR values to restore, and
     * a full record would make those values live on sigreturn.  The same applies
     * when the kernel supplied no SVE record.  Keep full records (including
     * their vector length and streaming mode) for genuinely live state.
     */
    const bool sve_tracked = proc_has_feature(FEATURE_SVE) && sve != NULL &&
        sve->vl == proc_get_vector_length_bytes() &&
        sve->head.size >= SVE_SIG_CONTEXT_SIZE(sve_vecquad_from_veclen(sve->vl));

    if (fpsimd == NULL) {
        if (has_extra ||
            limit - offset < sizeof(struct fpsimd_context) + sizeof(*terminator_record))
            return;
        fpsimd = (struct fpsimd_context *)terminator_record;
        fpsimd->head.magic = FPSIMD_MAGIC;
        fpsimd->head.size = sizeof(struct fpsimd_context);

        offset += fpsimd->head.size;
        terminator_record = GET_RECORD_AT_OFFSET(offset);
        *terminator_record = null_ctx;
    }

    fpsimd->fpsr = mc->fpsr;
    fpsimd->fpcr = mc->fpcr;
    ASSERT(sizeof(fpsimd->vregs) == (sizeof(mc->simd->q) * MCXT_NUM_SIMD_SVE_SLOTS));
    int i;
    for (i = 0; i < MCXT_NUM_SIMD_SVE_SLOTS; i++) {
        memcpy(&fpsimd->vregs[i], &mc->simd[i].u32[0], sizeof(fpsimd->vregs[i]));
    }

    if (sve_tracked) {
        const uint quads_per_vector = sve_vecquad_from_veclen(sve->vl);
        ASSERT(sve->head.size >= SVE_SIG_CONTEXT_SIZE(quads_per_vector));
        /* dr_mcontext_t holds at most 512-bit vectors: write no more than its
         * slots hold, leaving any higher bits in the record as they are.
         */
        const size_t zsize = MIN(sve->vl, sizeof(mc->simd[0]));
        const size_t psize = MIN(sve->vl / 8, sizeof(mc->svep[0]));
        const size_t ffrsize = MIN(sve->vl / 8, sizeof(mc->ffr));

        for (uint i = 0; i < MCXT_NUM_SIMD_SVE_SLOTS; i++) {
            memcpy((byte *)sve + SVE_SIG_ZREG_OFFSET(quads_per_vector, i),
                   &mc->simd[i].u32, zsize);
        }
        for (uint i = 0; i < MCXT_NUM_SVEP_SLOTS; i++) {
            memcpy((byte *)sve + SVE_SIG_PREG_OFFSET(quads_per_vector, i),
                   &mc->svep[i].u16, psize);
        }
        memcpy((byte *)sve + SVE_SIG_FFR_OFFSET(quads_per_vector), &mc->ffr, ffrsize);
    }
#endif
}

size_t
signal_frame_extra_size(bool include_alignment)
{
    return 0;
}

void
signal_arch_init(void)
{
    /* Nothing. */
}

/* The kernel's limit on a signal frame's size, EXTRA data included. */
#define SIGFRAME_MAXSZ (64 * 1024)

/* Returns frame's EXTRA record if it has a well-formed one, with in *data_off
 * the offset from frame at which the kernel puts the data: the first 16-byte
 * aligned address after the terminator that follows the record, which may be
 * inside __reserved.  The kernel rejects any other datap at rt_sigreturn, so
 * we require it unless the frame is queued (pending), where datap points to a
 * buffer of ours or is 0 if there was none.
 */
static struct extra_context *
frame_extra_record(sigframe_rt_t *frame, bool pending, size_t *data_off)
{
    sigcontext_t *sc = &frame->uc.uc_mcontext;
    size_t offset = 0;
    struct _aarch64_ctx *record;
    while ((record = sigcontext_record_at(sc->__reserved, offset,
                                          sizeof(sc->__reserved))) != NULL) {
        if (record->magic == EXTRA_MAGIC) {
            struct extra_context *extra = (struct extra_context *)record;
            byte *data = (byte *)record + record->size +
                ALIGN_FORWARD(sizeof(struct _aarch64_ctx), 16);
            if (record->size < sizeof(*extra) ||
                data > (byte *)sc->__reserved + sizeof(sc->__reserved) ||
                !ALIGNED(extra->size, 16) ||
                data + extra->size > (byte *)frame + SIGFRAME_MAXSZ ||
                (pending ? extra->datap == 0 : extra->datap != (uint64)data))
                return NULL;
            *data_off = data - (byte *)frame;
            return extra;
        }
        offset += record->size;
    }
    return NULL;
}

size_t
signal_frame_extra_used(sigframe_rt_t *frame, bool pending)
{
    size_t data_off;
    struct extra_context *extra = frame_extra_record(frame, pending, &data_off);
    if (extra == NULL || data_off + extra->size <= sizeof(*frame))
        return 0;
    return data_off + extra->size - sizeof(*frame);
}

void
signal_frame_extra_copy(sigframe_rt_t *dst, sigframe_rt_t *src, bool src_pending)
{
    size_t data_off;
    struct extra_context *extra = frame_extra_record(src, src_pending, &data_off);
    if (extra == NULL)
        return;
    struct extra_context *dst_extra =
        (struct extra_context *)((byte *)dst + ((byte *)extra - (byte *)src));
    byte *data = (byte *)dst + data_off;
    if ((uint64)data != extra->datap)
        memmove(data, (byte *)extra->datap, extra->size);
    dst_extra->datap = (uint64)data;
}

/* A buffer for the EXTRA data of a queued frame.  The buffers belong to the
 * thread; one is in use while a queued frame's EXTRA record points to it.
 * They are only added at a safe point (signal_extra_bufs_grow()) and only read
 * from our signal handler, which cannot allocate.
 */
typedef struct _extra_buf_t {
    struct _extra_buf_t *next;
    size_t size;
    byte data[];
} extra_buf_t;

static bool
extra_buf_in_use(thread_sig_info_t *info, extra_buf_t *buf)
{
    for (int sig = 1; sig <= MAX_SIGNUM; sig++) {
        for (sigpending_t *p = info->sigpending[sig]; p != NULL; p = p->next) {
            size_t data_off;
            struct extra_context *extra =
                frame_extra_record(&p->rt_frame, true, &data_off);
            if (extra != NULL && extra->datap == (uint64)buf->data)
                return true;
        }
    }
    return false;
}

static extra_buf_t *
extra_buf_find(thread_sig_info_t *info, size_t size)
{
    for (extra_buf_t *buf = info->extra_bufs; buf != NULL; buf = buf->next) {
        if (buf->size >= size && !extra_buf_in_use(info, buf))
            return buf;
    }
    return NULL;
}

bool
signal_frame_extra_fits(thread_sig_info_t *info, sigframe_rt_t *frame)
{
    size_t data_off;
    struct extra_context *extra = frame_extra_record(frame, false, &data_off);
    if (extra == NULL || extra_buf_find(info, extra->size) != NULL)
        return true;
    if (extra->size > info->extra_want)
        info->extra_want = extra->size;
    return false;
}

void
signal_frame_extra_to_pending(thread_sig_info_t *info, sigframe_rt_t *dst,
                              sigframe_rt_t *src)
{
    size_t data_off;
    struct extra_context *extra = frame_extra_record(src, false, &data_off);
    if (extra == NULL)
        return;
    struct extra_context *dst_extra =
        (struct extra_context *)((byte *)dst + ((byte *)extra - (byte *)src));
    extra_buf_t *buf = extra_buf_find(info, extra->size);
    if (buf == NULL) {
        /* Delivered without its SVE/SME state the frame fails at rt_sigreturn,
         * as it would have before we handled EXTRA records at all.
         */
        SYSLOG_INTERNAL_WARNING_ONCE("No buffer for a queued signal frame's "
                                     "%u-byte EXTRA data",
                                     extra->size);
        dst_extra->datap = 0;
        return;
    }
    memcpy(buf->data, (byte *)extra->datap, extra->size);
    dst_extra->datap = (uint64)buf->data;
}

void
signal_extra_bufs_grow(dcontext_t *dcontext, thread_sig_info_t *info)
{
    size_t want = info->extra_want;
    if (want == 0)
        return;
    info->extra_want = 0;
    /* Replace the free buffers too small for it.  One buffer per frame we can
     * queue is the most we need.
     */
    uint count = 0;
    for (extra_buf_t **prev = &info->extra_bufs; *prev != NULL;) {
        extra_buf_t *buf = *prev;
        if (buf->size < want && !extra_buf_in_use(info, buf)) {
            *prev = buf->next;
            heap_free(dcontext, buf, sizeof(*buf) + buf->size HEAPACCT(ACCT_OTHER));
        } else {
            prev = &buf->next;
            count++;
        }
    }
    if (count >= DYNAMO_OPTION(max_pending_signals))
        return;
    extra_buf_t *buf = heap_alloc(dcontext, sizeof(*buf) + want HEAPACCT(ACCT_OTHER));
    buf->size = want;
    buf->next = info->extra_bufs;
    /* A single store publishes it to our signal handler. */
    info->extra_bufs = buf;
}

void
signal_extra_bufs_exit(dcontext_t *dcontext, thread_sig_info_t *info)
{
    while (info->extra_bufs != NULL) {
        extra_buf_t *buf = info->extra_bufs;
        info->extra_bufs = buf->next;
        heap_free(dcontext, buf, sizeof(*buf) + buf->size HEAPACCT(ACCT_OTHER));
    }
}

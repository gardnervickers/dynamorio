/* *******************************************************************************
 * Copyright (c) 2019-2023 Google, Inc.  All rights reserved.
 * *******************************************************************************/

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
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/**************************************************************************************
 * Restartable sequence ("rseq") support (i#2350).
 * This is a kernel feature which provides cpu-atomic regions: if a thread
 * is pre-empted within an rseq region, an abort handler is invoked.
 * The feature is difficult to handle under binary instrumentation.
 * We rely on the app following certain conventions, including containing a
 * section holding a table of all rseq sequences.
 */

#include "../globals.h"
#include "../module_shared.h"
#include "module_private.h"
#include "os_private.h"
#include "rseq_linux.h"
#include "../fragment.h"
#include "decode.h"
#include "instr_create_shared.h"
#include "instrument.h"
#include <stddef.h>
#include "include/syscall.h"
#include <errno.h>

#define ABS(x) ((x) < 0 ? -(x) : (x))

/* The linux/rseq.h header made a source-breaking change in torvalds/linux@bfdf4e6
 * which broke our build.  To avoid future issues we use our own definitions.
 * Binary breakage is unlikely without long periods of deprecation so this is
 * not adding undue risk.
 * If these structures were used in other files we would put a header in
 * core/unix/include alongside similar headers.
 */
struct rseq_cs {
    uint version;
    uint flags;
    uint64 start_ip;
    uint64 post_commit_offset;
    uint64 abort_ip;
} __attribute__((aligned(4 * sizeof(uint64))));
struct rseq {
    uint cpu_id_start;
    uint cpu_id;
    uint64 rseq_cs;
    uint flags;
} __attribute__((aligned(4 * sizeof(uint64))));
#define RSEQ_FLAG_UNREGISTER 1

vm_area_vector_t *d_r_rseq_areas;
DECLARE_CXTSWPROT_VAR(static mutex_t rseq_trigger_lock,
                      INIT_LOCK_FREE(rseq_trigger_lock));
static volatile bool rseq_enabled;

/* The struct rseq registered by glibc is present in the struct pthread.
 * As of glibc 2.35, it is present at the following offset from the app
 * lib seg base. We check these offsets first and then fall back to a
 * wider search. The linux.rseq test helps detect changes in these
 * offsets in future glibc versions.  glibc 2.41+ instead places it in static TLS
 * (at a positive offset on AArch64), at an offset that depends on the program, so
 * there we rely on the search.
 */
#ifdef X86
#    ifdef X64
#        define GLIBC_RSEQ_OFFSET 2464
#    else
#        define GLIBC_RSEQ_OFFSET 1312
#    endif
#else
/* This was verified on AArch64, but not on AArch32.
 * XXX: To improve struct rseq offset detection on AArch32, find the offset
 * on an AArch32 machine running glibc 2.35+ and add here.
 */
#    define GLIBC_RSEQ_OFFSET -32
#endif

/* We require all threads to use the same TLS offset to point at struct rseq. */
static int rseq_tls_offset;

/* The signature is registered per thread, but we require all registrations
 * to be the same.
 */
static int rseq_signature;

typedef struct _rseq_region_t {
    app_pc start;
    app_pc end;
    app_pc handler;
    app_pc final_instr_pc;
    /* We need to preserve input registers for targeting "start" instead of "handler"
     * for our 2nd invocation, if they're written in the rseq region.  We only support
     * GPR inputs.  We document that we do not support any other inputs (no flags, no
     * SIMD registers).
     */
    bool reg_written[DR_NUM_GPR_REGS];
} rseq_region_t;

/* We need to store potentially multiple rseq_cs per fragment when clients
 * make multiple copies of the app code (e.g., drbbdup).
 */
typedef struct _rseq_cs_record_t {
    struct rseq_cs rcs;
    void *alloc_ptr;
    struct _rseq_cs_record_t *next;
} rseq_cs_record_t;

/* We need to store an rseq_cs_record_t per fragment_t.  To avoid the cost of adding a
 * pointer field to every fragment_t, and the complexity of another subclass like
 * trace_t, we store them externally in a hashtable.  The FRAG_HAS_RSEQ_ENDPOINT flag
 * avoids the hashtable lookup on every fragment.
 */
static generic_table_t *rseq_cs_table;
#define INIT_RSEQ_CS_TABLE_SIZE 5

/* vmvector callbacks */
static void
rseq_area_free(void *data)
{
    HEAP_TYPE_FREE(GLOBAL_DCONTEXT, data, rseq_region_t, ACCT_VMAREAS, PROTECTED);
}

static void *
rseq_area_dup(void *data)
{
    rseq_region_t *src = (rseq_region_t *)data;
    rseq_region_t *dst =
        HEAP_TYPE_ALLOC(GLOBAL_DCONTEXT, rseq_region_t, ACCT_VMAREAS, PROTECTED);
    ASSERT(src != NULL);
    *dst = *src;
    return dst;
}

static inline size_t
rseq_cs_alloc_size(void)
{
    return sizeof(rseq_cs_record_t) + __alignof(struct rseq_cs);
}

static void
rseq_cs_free(dcontext_t *dcontext, void *data)
{
    rseq_cs_record_t *record = (rseq_cs_record_t *)data;
    do {
        void *tofree = record->alloc_ptr;
        record = record->next;
        global_heap_free(tofree, rseq_cs_alloc_size() HEAPACCT(ACCT_OTHER));
    } while (record != NULL);
}

void
d_r_rseq_init(void)
{
    VMVECTOR_ALLOC_VECTOR(d_r_rseq_areas, GLOBAL_DCONTEXT,
                          VECTOR_SHARED | VECTOR_NEVER_MERGE, rseq_areas);
    vmvector_set_callbacks(d_r_rseq_areas, rseq_area_free, rseq_area_dup, NULL, NULL);

    rseq_cs_table = generic_hash_create(GLOBAL_DCONTEXT, INIT_RSEQ_CS_TABLE_SIZE, 80,
                                        HASHTABLE_SHARED | HASHTABLE_PERSISTENT,
                                        rseq_cs_free _IF_DEBUG("rseq_cs table"));
    /* Enable rseq pre-attach for things like dr_prepopulate_cache(). */
    if (rseq_is_registered_for_current_thread())
        rseq_locate_rseq_regions();
}

void
d_r_rseq_exit(void)
{
    generic_hash_destroy(GLOBAL_DCONTEXT, rseq_cs_table);
    vmvector_delete_vector(GLOBAL_DCONTEXT, d_r_rseq_areas);
    DELETE_LOCK(rseq_trigger_lock);
}

void
rseq_thread_attach(dcontext_t *dcontext)
{
    rseq_region_t *info;
    if (!vmvector_lookup_data(d_r_rseq_areas, dcontext->next_tag, NULL, NULL,
                              (void **)&info))
        return;
    /* The thread missed the save of its state on rseq entry.  We could try to save here
     * so the restore on rseq exit won't read incorrect values, but it's simpler and
     * less error-prone to send it to the abort handler, like we do on detach or other
     * translation points.
     */
    dcontext->next_tag = info->handler;
}

bool
rseq_get_region_info(app_pc pc, app_pc *start DR_PARAM_OUT, app_pc *end DR_PARAM_OUT,
                     app_pc *handler DR_PARAM_OUT, bool **reg_written DR_PARAM_OUT,
                     int *reg_written_size DR_PARAM_OUT)
{
    rseq_region_t *info;
    if (!vmvector_lookup_data(d_r_rseq_areas, pc, start, end, (void **)&info))
        return false;
    if (handler != NULL)
        *handler = info->handler;
    if (reg_written != NULL)
        *reg_written = info->reg_written;
    if (reg_written_size != NULL)
        *reg_written_size = sizeof(info->reg_written) / sizeof(info->reg_written[0]);
    return true;
}

bool
rseq_set_final_instr_pc(app_pc start, app_pc final_instr_pc)
{
    rseq_region_t *info;
    if (!vmvector_lookup_data(d_r_rseq_areas, start, NULL, NULL, (void **)&info))
        return false;
    if (final_instr_pc < start || final_instr_pc >= info->end)
        return false;
    info->final_instr_pc = final_instr_pc;
    return true;
}

int
rseq_get_tls_ptr_offset(void)
{
    /* This read is assumed to be atomic. */
    ASSERT(rseq_tls_offset != 0);
    return rseq_tls_offset + offsetof(struct rseq, rseq_cs);
}

static void
rseq_clear_tls_ptr(dcontext_t *dcontext)
{
    ASSERT(rseq_tls_offset != 0);
    byte *base = get_app_segment_base(LIB_SEG_TLS);
    struct rseq *app_rseq = (struct rseq *)(base + rseq_tls_offset);
    /* We're directly writing this in the cache, so we do not bother with safe_read
     * or safe_write here either.  We already cannot handle rseq adversarial cases.
     */
    if (is_dynamo_address((byte *)(ptr_uint_t)app_rseq->rseq_cs))
        app_rseq->rseq_cs = 0;
}

int
rseq_get_signature(void)
{
    /* This is only called after rseq is initialized and the signature determined. */
    ASSERT(rseq_enabled);
    return rseq_signature;
}

byte *
rseq_get_rseq_cs_alloc(byte **rseq_cs_aligned DR_PARAM_OUT)
{
    byte *rseq_cs_alloc = global_heap_alloc(rseq_cs_alloc_size() HEAPACCT(ACCT_OTHER));
    *rseq_cs_aligned = (byte *)ALIGN_FORWARD(rseq_cs_alloc, __alignof(struct rseq_cs));
    return rseq_cs_alloc;
}

void
rseq_record_rseq_cs(byte *rseq_cs_alloc, fragment_t *f, cache_pc start, cache_pc end,
                    cache_pc abort)
{
    rseq_cs_record_t *record =
        (rseq_cs_record_t *)ALIGN_FORWARD(rseq_cs_alloc, __alignof(struct rseq_cs));
    record->alloc_ptr = rseq_cs_alloc;
    record->next = NULL;
    struct rseq_cs *target = &record->rcs;
    target->version = 0;
    target->flags = 0;
    target->start_ip = (ptr_uint_t)start;
    target->post_commit_offset = (ptr_uint_t)(end - start);
    target->abort_ip = (ptr_uint_t)abort;
    TABLE_RWLOCK(rseq_cs_table, write, lock);
    rseq_cs_record_t *existing =
        generic_hash_lookup(GLOBAL_DCONTEXT, rseq_cs_table, (ptr_uint_t)f);
    if (existing != NULL) {
        while (existing->next != NULL)
            existing = existing->next;
        existing->next = record;
    } else {
        generic_hash_add(GLOBAL_DCONTEXT, rseq_cs_table, (ptr_uint_t)f, record);
    }
    TABLE_RWLOCK(rseq_cs_table, write, unlock);
}

void
rseq_remove_fragment(dcontext_t *dcontext, fragment_t *f)
{
    if (!rseq_enabled)
        return;
    /* Avoid freeing a live rseq_cs for a thread-private fragment deletion. */
    rseq_clear_tls_ptr(dcontext);
    TABLE_RWLOCK(rseq_cs_table, write, lock);
    generic_hash_remove(GLOBAL_DCONTEXT, rseq_cs_table, (ptr_uint_t)f);
    TABLE_RWLOCK(rseq_cs_table, write, unlock);
}

void
rseq_shared_fragment_flushtime_update(dcontext_t *dcontext)
{
    if (!rseq_enabled)
        return;
    /* Avoid freeing a live rseq_cs for thread-shared fragment deletion.
     * We clear the pointer on completion of the native rseq execution, but it's
     * not easy to clear it on midpoint exits.  We instead clear prior to
     * rseq_cs being freed: for thread-private in rseq_remove_fragment() and for
     * thread-shared each thread should come here prior to deletion.
     */
    rseq_clear_tls_ptr(dcontext);
}

bool
rseq_is_registered_for_current_thread(void)
{
    /* Unfortunately there's no way to query the current rseq struct.
     * For 64-bit we can pass a kernel address and look for EFAULT
     * vs EINVAL, but there is no kernel address for 32-bit.
     * So we try to perform a legitimate registration.
     */
    struct rseq test_rseq = {};
    int res = dynamorio_syscall(SYS_rseq, 4, &test_rseq, sizeof(test_rseq), 0, 0);
    if (res == -EINVAL) /* Our struct != registered struct. */
        return true;
    if (res == -ENOSYS)
        return false;
    /* If seccomp blocks SYS_rseq we'll get -EPERM.  SYS_rseq also returns -EPERM
     * if &test_rseq == the app's struct but the signature is different, but that
     * seems so unlikely that we just assume -EPERM implies seccomp.
     */
    if (res == -EPERM)
        return false;
    ASSERT(res == 0); /* If not, the struct size or sthg changed! */
    if (dynamorio_syscall(SYS_rseq, 4, &test_rseq, sizeof(test_rseq),
                          RSEQ_FLAG_UNREGISTER, 0) != 0) {
        ASSERT_NOT_REACHED();
    }
    return false;
}

static void
rseq_analyze_instructions(rseq_region_t *info)
{
    /* We analyze the instructions inside [start,end) looking for register state that we
     * need to preserve for our restart.  We do not want to blindly spill and restore
     * 16+ registers for every sequence (too much overhead).
     */
    instr_t instr;
    instr_init(GLOBAL_DCONTEXT, &instr);
    app_pc pc = info->start;
    int i;
    memset(info->reg_written, 0, sizeof(info->reg_written));
    while (pc < info->end) {
        instr_reset(GLOBAL_DCONTEXT, &instr);
        app_pc next_pc = decode(GLOBAL_DCONTEXT, pc, &instr);
        if (next_pc == NULL) {
            REPORT_FATAL_ERROR_AND_EXIT(RSEQ_BEHAVIOR_UNSUPPORTED, 3,
                                        get_application_name(), get_application_pid(),
                                        "Rseq sequence contains invalid instructions");
            ASSERT_NOT_REACHED();
        }
        if (instr_is_syscall(&instr)
            /* Allow a syscall for our test in debug build. */
            IF_DEBUG(
                &&!check_filter("api.rseq;linux.rseq;linux.rseq_table;linux.rseq_noarray;"
                                "linux.rseq_glibc_lld;linux.rseq_glibc_relr;"
                                "linux.rseq_flatmap",
                                get_short_name(get_application_name())))) {
            REPORT_FATAL_ERROR_AND_EXIT(RSEQ_BEHAVIOR_UNSUPPORTED, 3,
                                        get_application_name(), get_application_pid(),
                                        "Rseq sequence contains a system call");
            ASSERT_NOT_REACHED();
        }
        if (instr_is_call(&instr)) {
            REPORT_FATAL_ERROR_AND_EXIT(RSEQ_BEHAVIOR_UNSUPPORTED, 3,
                                        get_application_name(), get_application_pid(),
                                        "Rseq sequence contains a call");
            ASSERT_NOT_REACHED();
        }
        /* We potentially need to preserve any register written anywhere inside
         * the sequence.  We can't limit ourselves to registers clearly live on
         * input, since code *after* the sequence could read them.  We do disallow
         * callouts to helper functions to simplify our lives.
         *
         * We only preserve GPR's, for simplicity, and because they are far more likely
         * as inputs than flags or SIMD registers.  We'd like to verify that only GPR's
         * are used, but A) we can't easily check values read *after* the sequence (the
         * handler could set up state read afterward and sometimes clobbered inside), B)
         * we do want to support SIMD and flags writes in the sequence, and C) even
         * checking for values read in the sequence would want new interfaces like
         * DR_REG_START_SIMD or register iterators for reasonable code.
         */
        for (i = 0; i < DR_NUM_GPR_REGS; i++) {
            if (info->reg_written[i])
                continue;
            reg_id_t reg = DR_REG_START_GPR + (reg_id_t)i;
            if (instr_writes_to_reg(&instr, reg, DR_QUERY_DEFAULT)) {
                LOG(GLOBAL, LOG_LOADER, 3,
                    "Rseq region @" PFX " writes register %s at " PFX "\n", info->start,
                    reg_names[reg], pc);
                info->reg_written[i] = true;
            }
        }
        pc = next_pc;
    }
    instr_free(GLOBAL_DCONTEXT, &instr);
}

static void
rseq_process_entry(module_area_t *ma, const struct rseq_cs *entry)
{
    LOG(GLOBAL, LOG_LOADER, 2,
        "Found rseq region: ver=%u; flags=%u; start=" PFX "; end=" PFX "; abort=" PFX
        "\n",
        entry->version, entry->flags, (ptr_uint_t)entry->start_ip,
        (ptr_uint_t)(entry->start_ip + entry->post_commit_offset),
        (ptr_uint_t)entry->abort_ip);
    rseq_region_t *info =
        HEAP_TYPE_ALLOC(GLOBAL_DCONTEXT, rseq_region_t, ACCT_VMAREAS, PROTECTED);
    info->start = (app_pc)(ptr_uint_t)entry->start_ip;
    info->end = info->start + entry->post_commit_offset;
    info->handler = (app_pc)(ptr_uint_t)entry->abort_ip;
    info->final_instr_pc = NULL; /* Only set later at block building time. */
    int signature;
    if (!d_r_safe_read(info->handler - sizeof(signature), sizeof(signature),
                       &signature)) {
        REPORT_FATAL_ERROR_AND_EXIT(RSEQ_BEHAVIOR_UNSUPPORTED, 3, get_application_name(),
                                    get_application_pid(),
                                    "Rseq signature is unreadable");
        ASSERT_NOT_REACHED();
    }
    if (signature != rseq_signature) {
        if (rseq_signature == 0) {
            SELF_UNPROTECT_DATASEC(DATASEC_RARELY_PROT);
            ATOMIC_4BYTE_WRITE(&rseq_signature, signature, false);
            SELF_PROTECT_DATASEC(DATASEC_RARELY_PROT);
            LOG(GLOBAL, LOG_LOADER, 2, "Rseq signature is 0x%08x\n", rseq_signature);
        } else {
            LOG(GLOBAL, LOG_LOADER, 1,
                "Rseq signature 0x%08x at " PFX " in %s differs from 0x%08x\n", signature,
                info->handler - sizeof(signature),
                GET_MODULE_NAME(&ma->names) == NULL ? "(null)"
                                                    : GET_MODULE_NAME(&ma->names),
                rseq_signature);
            REPORT_FATAL_ERROR_AND_EXIT(RSEQ_BEHAVIOR_UNSUPPORTED, 3,
                                        get_application_name(), get_application_pid(),
                                        "Rseq signatures are not all identical");
            ASSERT_NOT_REACHED();
        }
    }
    rseq_analyze_instructions(info);
    vmvector_add(d_r_rseq_areas, info->start, info->end, (void *)info);
    RSTATS_INC(num_rseq_regions);
    /* Check the start pc.  We don't take the effort to check for non-tags or
     * interior pc's.
     */
    if (fragment_lookup(GLOBAL_DCONTEXT, info->start) != NULL) {
        /* We rely on the app not running rseq code for non-rseq purposes (since we
         * can't easily tell the difference; plus we avoid a flush for lazy rseq
         * activation).
         */
        REPORT_FATAL_ERROR_AND_EXIT(
            RSEQ_BEHAVIOR_UNSUPPORTED, 3, get_application_name(), get_application_pid(),
            "Rseq sequences must not be used for non-rseq purposes");
        ASSERT_NOT_REACHED();
    }
}

/* Reading rseq tables.
 *
 * A module's rseq tables (the __rseq_cs_ptr_array pointers and the start_ip and
 * abort_ip of each struct rseq_cs) hold link-time addresses which the loader
 * relocates.  Whether it has done so when we look depends on when the app first
 * registers rseq, which we cannot reliably tell: glibc 2.35+ registers each thread
 * from ld.so before it relocates anything, while an app's own registration usually
 * comes later.  (glibc 2.41+ also moved its struct rseq into static TLS, so its TLS
 * offset no longer distinguishes the two.)  The in-memory words are not enough to
 * relocate them ourselves either: RELA relocations need not leave anything in
 * place (lld writes zero), and the loader may be part-way through.
 *
 * We therefore read the tables' original contents from the module's file and apply
 * its dynamic relocations (RELA, REL and RELR) ourselves.  This gives the run-time
 * values whatever the loader has done so far.
 */

/* SHT_RELR is missing from older system headers. */
#ifndef SHT_RELR
#    define SHT_RELR 19
#endif

typedef struct _rseq_elf_file_t {
    module_area_t *ma;
    file_t fd;
    /* Run-time address minus link-time address. */
    ssize_t load_offs;
    ELF_SECTION_HEADER_TYPE *sec_hdr;
    uint num_sections;
} rseq_elf_file_t;

/* A pointer-sized word of an rseq table at a link-time address. */
typedef struct _rseq_word_t {
    ptr_uint_t vaddr;
    ptr_uint_t original; /* The contents of the file. */
    ptr_uint_t value;    /* The run-time value. */
} rseq_word_t;

static bool
rseq_read_file_offset(rseq_elf_file_t *elf, uint64 offset, void *buf, size_t size)
{
    if (!os_seek(elf->fd, (int64)offset, SEEK_SET))
        return false;
    byte *cur = (byte *)buf;
    while (size > 0) {
        ssize_t got = os_read(elf->fd, cur, size);
        if (got <= 0)
            return false;
        cur += got;
        size -= got;
    }
    return true;
}

/* Reads the original contents of [vaddr, vaddr + size) from the module's file. */
static bool
rseq_read_file(rseq_elf_file_t *elf, ptr_uint_t vaddr, void *buf, size_t size)
{
    for (uint i = 0; i < elf->num_sections; i++) {
        ELF_SECTION_HEADER_TYPE *sec = &elf->sec_hdr[i];
        /* TLS sections' addresses overlap the sections after them. */
        if (!TESTANY(SHF_ALLOC, sec->sh_flags) || TESTANY(SHF_TLS, sec->sh_flags) ||
            vaddr < sec->sh_addr || vaddr - sec->sh_addr >= sec->sh_size ||
            size > sec->sh_size - (vaddr - sec->sh_addr))
            continue;
        if (sec->sh_type == SHT_NOBITS) {
            memset(buf, 0, size);
            return true;
        }
        return rseq_read_file_offset(elf, sec->sh_offset + (vaddr - sec->sh_addr), buf,
                                     size);
    }
    return false;
}

/* Returns the index in order[], which sorts words[] by vaddr, of the first word at
 * or after vaddr.
 */
static uint
rseq_find_word(rseq_word_t *words, uint *order, uint num_words, ptr_uint_t vaddr)
{
    uint lo = 0, hi = num_words;
    while (lo < hi) {
        uint mid = lo + (hi - lo) / 2;
        if (words[order[mid]].vaddr < vaddr)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

/* Applies one dynamic relocation at link-time address where to the words there.
 * REL and RELR relocations (!has_addend) take their addend from the original
 * contents.
 */
static bool
rseq_apply_relocation(rseq_elf_file_t *elf, rseq_word_t *words, uint *order,
                      uint num_words, ptr_uint_t where, uint type, uint sym_index,
                      ELF_SECTION_HEADER_TYPE *symtab, bool has_addend, ptr_int_t addend,
                      const char **error DR_PARAM_OUT)
{
    for (uint i = rseq_find_word(words, order, num_words, where);
         i < num_words && words[order[i]].vaddr == where; i++) {
        rseq_word_t *word = &words[order[i]];
        ptr_uint_t base = has_addend ? (ptr_uint_t)addend : word->original;
        if (type == ELF_R_RELATIVE) {
            word->value = elf->load_offs + base;
        } else if (type == ELF_R_DIRECT) {
            ELF_SYM_TYPE sym;
            if (symtab == NULL || symtab->sh_type != SHT_DYNSYM ||
                sym_index >= symtab->sh_size / sizeof(sym) ||
                !rseq_read_file_offset(elf, symtab->sh_offset + sym_index * sizeof(sym),
                                       &sym, sizeof(sym))) {
                *error = "Rseq table relocation symbol is unreadable";
                return false;
            }
            if (sym.st_shndx == SHN_UNDEF) {
                *error = "Rseq table refers to another module";
                return false;
            }
            word->value =
                (sym.st_shndx == SHN_ABS ? 0 : elf->load_offs) + sym.st_value + base;
        } else if (type != ELF_R_NONE) {
            *error = "Rseq table has an unsupported relocation";
            return false;
        }
        LOG(GLOBAL, LOG_LOADER, 3,
            "Rseq table word @" PFX ": reloc type %u, " PFX " => " PFX "\n", where, type,
            word->original, word->value);
    }
    return true;
}

/* Computes the run-time value of each of words[], given its vaddr, from the
 * module's file and its dynamic relocations.
 */
static bool
rseq_relocate_words(rseq_elf_file_t *elf, rseq_word_t *words, uint num_words,
                    const char **error DR_PARAM_OUT)
{
    *error = NULL;
    if (num_words == 0)
        return true;
    for (uint i = 0; i < num_words; i++) {
        if (!rseq_read_file(elf, words[i].vaddr, &words[i].original,
                            sizeof(words[i].original))) {
            *error = "Rseq table is not in the module's file";
            return false;
        }
        words[i].value = words[i].original;
    }
    /* Sort an index for lookups.  The tables are small, so insertion sort it is. */
    uint *order =
        HEAP_ARRAY_ALLOC(GLOBAL_DCONTEXT, uint, num_words, ACCT_OTHER, PROTECTED);
    for (uint i = 0; i < num_words; i++) {
        uint j = i;
        for (; j > 0 && words[order[j - 1]].vaddr > words[i].vaddr; j--)
            order[j] = order[j - 1];
        order[j] = i;
    }
    ptr_uint_t min_vaddr = words[order[0]].vaddr;
    ptr_uint_t max_vaddr = words[order[num_words - 1]].vaddr;
    bool ok = true;
    for (uint s = 0; ok && s < elf->num_sections; s++) {
        ELF_SECTION_HEADER_TYPE *sec = &elf->sec_hdr[s];
        size_t entry_size;
        /* Relocation sections without SHF_ALLOC are static relocations, as kept by
         * --emit-relocs (BOLT-processed binaries have them), which the loader does
         * not apply.
         */
        if (!TESTANY(SHF_ALLOC, sec->sh_flags) || sec->sh_size == 0)
            continue;
        if (sec->sh_type == SHT_RELA)
            entry_size = sizeof(ELF_RELA_TYPE);
        else if (sec->sh_type == SHT_REL)
            entry_size = sizeof(ELF_REL_TYPE);
        else if (sec->sh_type == SHT_RELR)
            entry_size = sizeof(ELF_WORD);
        else
            continue;
        if (sec->sh_entsize != entry_size) {
            *error = "Rseq module has malformed relocations";
            ok = false;
            break;
        }
        uint64 map_offs = ALIGN_BACKWARD(sec->sh_offset, PAGE_SIZE);
        size_t map_size =
            ALIGN_FORWARD(sec->sh_offset + sec->sh_size, PAGE_SIZE) - map_offs;
        byte *map = os_map_file(elf->fd, &map_size, map_offs, NULL, MEMPROT_READ,
                                MAP_FILE_COPY_ON_WRITE);
        if (map == NULL) {
            *error = "Rseq module's relocations are unreadable";
            ok = false;
            break;
        }
        byte *data = map + (sec->sh_offset - map_offs);
        size_t count = sec->sh_size / entry_size;
        ELF_SECTION_HEADER_TYPE *symtab =
            sec->sh_link < elf->num_sections ? &elf->sec_hdr[sec->sh_link] : NULL;
        LOG(GLOBAL, LOG_LOADER, 3, "Scanning %zu relocations of type %u\n", count,
            sec->sh_type);
        ptr_uint_t relr_where = 0;
        for (size_t i = 0; ok && i < count; i++) {
            if (sec->sh_type == SHT_RELA) {
                ELF_RELA_TYPE *rela = &((ELF_RELA_TYPE *)data)[i];
                if (rela->r_offset < min_vaddr || rela->r_offset > max_vaddr)
                    continue;
                ok = rseq_apply_relocation(elf, words, order, num_words, rela->r_offset,
                                           (uint)ELF_R_TYPE(rela->r_info),
                                           (uint)ELF_R_SYM(rela->r_info), symtab, true,
                                           (ptr_int_t)rela->r_addend, error);
            } else if (sec->sh_type == SHT_REL) {
                ELF_REL_TYPE *rel = &((ELF_REL_TYPE *)data)[i];
                if (rel->r_offset < min_vaddr || rel->r_offset > max_vaddr)
                    continue;
                ok = rseq_apply_relocation(elf, words, order, num_words, rel->r_offset,
                                           (uint)ELF_R_TYPE(rel->r_info),
                                           (uint)ELF_R_SYM(rel->r_info), symtab, false, 0,
                                           error);
            } else {
                /* RELR: an address, then bitmaps of the words after it (see
                 * module_relocate_relr()).  Each is a relative relocation.
                 */
                ELF_WORD entry = ((ELF_WORD *)data)[i];
                if (!TESTANY(1, entry)) {
                    relr_where = (ptr_uint_t)entry;
                    if (relr_where >= min_vaddr && relr_where <= max_vaddr) {
                        ok = rseq_apply_relocation(elf, words, order, num_words,
                                                   relr_where, ELF_R_RELATIVE, 0, NULL,
                                                   false, 0, error);
                    }
                    relr_where += sizeof(ELF_ADDR);
                } else {
                    ptr_uint_t where = relr_where;
                    for (ELF_WORD bitmap = entry >> 1; ok && bitmap != 0;
                         bitmap >>= 1, where += sizeof(ELF_ADDR)) {
                        if (TESTANY(1, bitmap) && where >= min_vaddr &&
                            where <= max_vaddr) {
                            ok = rseq_apply_relocation(elf, words, order, num_words,
                                                       where, ELF_R_RELATIVE, 0, NULL,
                                                       false, 0, error);
                        }
                    }
                    relr_where += (CHAR_BIT * sizeof(ELF_WORD) - 1) * sizeof(ELF_ADDR);
                }
            }
        }
        os_unmap_file(map, map_size);
    }
    HEAP_ARRAY_FREE(GLOBAL_DCONTEXT, order, uint, num_words, ACCT_OTHER, PROTECTED);
    return ok;
}

static void
rseq_report_table_error(const char *error)
{
    REPORT_FATAL_ERROR_AND_EXIT(RSEQ_BEHAVIOR_UNSUPPORTED, 3, get_application_name(),
                                get_application_pid(), error);
    ASSERT_NOT_REACHED();
}

/* Processes the struct rseq_cs entries at the given link-time addresses. */
static void
rseq_process_entries(rseq_elf_file_t *elf, ptr_uint_t *entries, uint num_entries)
{
    if (num_entries == 0)
        return;
    const char *error;
    uint num_words = 2 * num_entries;
    rseq_word_t *words =
        HEAP_ARRAY_ALLOC(GLOBAL_DCONTEXT, rseq_word_t, num_words, ACCT_OTHER, PROTECTED);
    for (uint i = 0; i < num_entries; i++) {
        words[2 * i].vaddr = entries[i] + offsetof(struct rseq_cs, start_ip);
        words[2 * i + 1].vaddr = entries[i] + offsetof(struct rseq_cs, abort_ip);
    }
    if (!rseq_relocate_words(elf, words, num_words, &error))
        rseq_report_table_error(error);
    for (uint i = 0; i < num_entries; i++) {
        struct rseq_cs entry;
        if (!rseq_read_file(elf, entries[i], &entry, sizeof(entry)))
            rseq_report_table_error("Rseq table is not in the module's file");
        entry.start_ip = words[2 * i].value;
        entry.abort_ip = words[2 * i + 1].value;
        rseq_process_entry(elf->ma, &entry);
    }
    HEAP_ARRAY_FREE(GLOBAL_DCONTEXT, words, rseq_word_t, num_words, ACCT_OTHER,
                    PROTECTED);
}

static void
rseq_process_elf_sections(rseq_elf_file_t *elf, const char *strtab, size_t strtab_size)
{
    module_area_t *ma = elf->ma;
    ELF_SECTION_HEADER_TYPE *array_sec = NULL, *cs_sec = NULL;
    for (uint i = 0; i < elf->num_sections; i++) {
        ELF_SECTION_HEADER_TYPE *sec = &elf->sec_hdr[i];
        if (sec->sh_name >= strtab_size)
            continue;
        const char *name = strtab + sec->sh_name;
#define RSEQ_PTR_ARRAY_SEC_NAME "__rseq_cs_ptr_array"
#define RSEQ_SEC_NAME "__rseq_cs"
#define RSEQ_OLD_SEC_NAME "__rseq_table"
        if (array_sec == NULL && strcmp(name, RSEQ_PTR_ARRAY_SEC_NAME) == 0)
            array_sec = sec;
        else if (cs_sec == NULL &&
                 (strcmp(name, RSEQ_SEC_NAME) == 0 ||
                  strcmp(name, RSEQ_OLD_SEC_NAME) == 0))
            cs_sec = sec;
    }
    uint num_entries = 0;
    ptr_uint_t *entries = NULL;
    if (array_sec != NULL) {
        /* We require that the table is loaded.  If not, bail, but unlike failing to
         * find section headers, make this a fatal error: better to notify the user
         * than try to run the rseq w/o proper handling.
         */
        app_pc array = (app_pc)(array_sec->sh_addr + elf->load_offs);
        if (array < ma->start || array > ma->end ||
            array_sec->sh_size > (size_t)(ma->end - array)) {
            rseq_report_table_error(RSEQ_PTR_ARRAY_SEC_NAME
                                    " is not in a loaded segment");
        }
        num_entries = (uint)(array_sec->sh_size / sizeof(ELF_ADDR));
        if (num_entries == 0)
            return;
        const char *error;
        rseq_word_t *words = HEAP_ARRAY_ALLOC(GLOBAL_DCONTEXT, rseq_word_t, num_entries,
                                              ACCT_OTHER, PROTECTED);
        for (uint i = 0; i < num_entries; i++)
            words[i].vaddr = array_sec->sh_addr + i * sizeof(ELF_ADDR);
        if (!rseq_relocate_words(elf, words, num_entries, &error))
            rseq_report_table_error(error);
        entries = HEAP_ARRAY_ALLOC(GLOBAL_DCONTEXT, ptr_uint_t, num_entries, ACCT_OTHER,
                                   PROTECTED);
        for (uint i = 0; i < num_entries; i++) {
            app_pc entry = (app_pc)words[i].value;
            if (entry < ma->start || entry > ma->end ||
                sizeof(struct rseq_cs) > (size_t)(ma->end - entry)) {
                LOG(GLOBAL, LOG_LOADER, 1,
                    "Rseq array entry %u @" PFX " is " PFX " (file " PFX ")\n", i,
                    words[i].vaddr, words[i].value, words[i].original);
                rseq_report_table_error(RSEQ_PTR_ARRAY_SEC_NAME
                                        "'s entries are not in a loaded segment");
            }
            entries[i] = words[i].value - elf->load_offs;
        }
        HEAP_ARRAY_FREE(GLOBAL_DCONTEXT, words, rseq_word_t, num_entries, ACCT_OTHER,
                        PROTECTED);
    } else if (cs_sec != NULL) {
        /* There may be padding at the start of the section, so ensure we skip over
         * it.  The load offset is page-aligned, so the link-time and run-time
         * alignments agree.
         */
#define RSEQ_CS_ALIGNMENT (4 * sizeof(__u64))
        ptr_uint_t first = ALIGN_FORWARD(cs_sec->sh_addr, RSEQ_CS_ALIGNMENT);
        ptr_uint_t end = cs_sec->sh_addr + cs_sec->sh_size;
        if (first >= end)
            return;
        /* We require that the table is loaded.  If not, bail. */
        if ((app_pc)(first + elf->load_offs) < ma->start ||
            (app_pc)(end + elf->load_offs) > ma->end)
            rseq_report_table_error(RSEQ_SEC_NAME " is not in a loaded segment");
        num_entries = (uint)((end - first) / sizeof(struct rseq_cs));
        if (num_entries == 0)
            return;
        entries = HEAP_ARRAY_ALLOC(GLOBAL_DCONTEXT, ptr_uint_t, num_entries, ACCT_OTHER,
                                   PROTECTED);
        for (uint i = 0; i < num_entries; i++)
            entries[i] = first + i * sizeof(struct rseq_cs);
    } else
        return;
    rseq_process_entries(elf, entries, num_entries);
    HEAP_ARRAY_FREE(GLOBAL_DCONTEXT, entries, ptr_uint_t, num_entries, ACCT_OTHER,
                    PROTECTED);
}

/* Returns whether successfully searched for rseq data (not whether found rseq data).
 * The module must be fully mapped (its first segment's initial mapping over its
 * whole extent replaced by the loader's per-segment mappings), as we read its code
 * for the signatures and register analysis; see rseq_module_init().
 */
static bool
rseq_process_module(module_area_t *ma)
{
    bool res = false;
    ASSERT(is_elf_so_header(ma->start, ma->end - ma->start));
    ELF_HEADER_TYPE *elf_hdr = (ELF_HEADER_TYPE *)ma->start;
    ASSERT(elf_hdr->e_shentsize == sizeof(ELF_SECTION_HEADER_TYPE));
    int fd = INVALID_FILE;
    byte *sec_map = NULL, *str_map = NULL;
    size_t sec_size = 0, str_size = 0;
    ELF_SECTION_HEADER_TYPE *sec_hdr = NULL;
    char *strtab;
    /* The section headers are not mapped in: they are typically at the end of the
     * file.  We read them, and the tables' contents and relocations, from the file.
     * For this reason, we delay calling this function until we see the app use rseq.
     */
    if (ma->full_path == NULL || elf_hdr->e_shnum == 0 ||
        elf_hdr->e_shstrndx >= elf_hdr->e_shnum ||
        elf_hdr->e_shentsize != sizeof(ELF_SECTION_HEADER_TYPE))
        goto rseq_process_module_cleanup;
    fd = os_open(ma->full_path, OS_OPEN_READ);
    if (fd == INVALID_FILE)
        goto rseq_process_module_cleanup;
    off_t offs = ALIGN_BACKWARD(elf_hdr->e_shoff, PAGE_SIZE);
    sec_size = ALIGN_FORWARD(elf_hdr->e_shoff + elf_hdr->e_shnum * elf_hdr->e_shentsize,
                             PAGE_SIZE) -
        offs;
    sec_map =
        os_map_file(fd, &sec_size, offs, NULL, MEMPROT_READ, MAP_FILE_COPY_ON_WRITE);
    if (sec_map == NULL) {
        sec_size = 0;
        goto rseq_process_module_cleanup;
    }
    sec_hdr = (ELF_SECTION_HEADER_TYPE *)(sec_map + elf_hdr->e_shoff - offs);
    /* We also need the section header string table. */
    offs = ALIGN_BACKWARD(sec_hdr[elf_hdr->e_shstrndx].sh_offset, PAGE_SIZE);
    str_size = ALIGN_FORWARD(sec_hdr[elf_hdr->e_shstrndx].sh_offset +
                                 sec_hdr[elf_hdr->e_shstrndx].sh_size,
                             PAGE_SIZE) -
        offs;
    str_map =
        os_map_file(fd, &str_size, offs, NULL, MEMPROT_READ, MAP_FILE_COPY_ON_WRITE);
    if (str_map == NULL) {
        str_size = 0;
        goto rseq_process_module_cleanup;
    }
    strtab = (char *)(str_map + sec_hdr[elf_hdr->e_shstrndx].sh_offset - offs);
    rseq_elf_file_t elf = { ma, fd, ma->start - ma->os_data.base_address, sec_hdr,
                            elf_hdr->e_shnum };
    rseq_process_elf_sections(&elf, strtab, sec_hdr[elf_hdr->e_shstrndx].sh_size);
    res = true;
rseq_process_module_cleanup:
    if (str_size != 0)
        os_unmap_file(str_map, str_size);
    if (sec_size != 0)
        os_unmap_file(sec_map, sec_size);
    if (fd != INVALID_FILE)
        os_close(fd);
    DODEBUG({
        if (!res) {
            const char *name = GET_MODULE_NAME(&ma->names);
            if (name == NULL)
                name = "(null)";
            LOG(GLOBAL, LOG_INTERP | LOG_VMAREAS, 2,
                "%s: error looking for rseq table in %s\n", __FUNCTION__, name);
            if (strstr(name, "linux-vdso.so") == NULL) {
                SYSLOG_INTERNAL_WARNING_ONCE(
                    "Failed to identify whether a module has an rseq table");
            }
        }
    });
    return res;
}

static bool
try_struct_rseq(void *try_addr)
{
    static const int RSEQ_RARE_SIGNATURE = 42;
    /* The kernel requires the unregister length to match the registration
     * length. glibc can register the extended area advertised by the kernel,
     * while sizeof(struct rseq) remains the original 32 bytes. Probe the
     * original and current extended lengths at each candidate TLS address.
     */
    static const uint lengths[] = { sizeof(struct rseq), 40, 64 };
    int res = -EINVAL;
    uint length = 0;
    for (uint i = 0; i < BUFFER_SIZE_ELEMENTS(lengths); ++i) {
        length = lengths[i];
        res = dynamorio_syscall(SYS_rseq, 4, try_addr, length,
                                RSEQ_FLAG_UNREGISTER, RSEQ_RARE_SIGNATURE);
        LOG(GLOBAL, LOG_LOADER, 3, "Tried rseq @ " PFX " len %u => %d\n", try_addr,
            length, res);
        if (res != -EINVAL)
            break;
    }
    if (res == -EINVAL) /* Our struct != registered struct. */
        return false;
    /* We expect -EPERM on a signature mismatch.  On the small chance the app
     * actually used 42 for its signature we'll have to re-register it.
     */
    if (res == 0) {
        int res = dynamorio_syscall(SYS_rseq, 4, try_addr, length, 0,
                                    RSEQ_RARE_SIGNATURE);
        ASSERT(res == 0);
        res = -EPERM;
    }
    if (res == -EPERM) {
        /* Found it! */
        return true;
    }
    return false;
}

/* Glibc exports the exact process-wide offset of its rseq area.  This used to
 * point inside struct pthread, but newer glibc places the area in a separate
 * extra-TLS block which is not necessarily in the memory interval containing
 * the thread pointer.  Prefer the exported ABI over the bounded fallback scan.
 * Still probe the resulting address: an application can replace glibc's
 * registration with its own static-TLS area.
 */
static int
rseq_locate_glibc_tls_offset(byte *seg_base)
{
    int offset = 0;
    module_iterator_t *iter = module_iterator_start();
    while (module_iterator_hasnext(iter)) {
        module_area_t *ma = module_iterator_next(iter);
        app_pc symbol = get_proc_address_from_os_data(
            &ma->os_data, ma->start - ma->os_data.base_address, "__rseq_offset", NULL);
        ptrdiff_t exported_offset;
        if (symbol != NULL &&
            d_r_safe_read(symbol, sizeof(exported_offset), &exported_offset) &&
            exported_offset >= INT_MIN && exported_offset <= INT_MAX &&
            exported_offset != 0 && try_struct_rseq(seg_base + exported_offset)) {
            offset = (int)exported_offset;
            LOG(GLOBAL, LOG_LOADER, 2,
                "Found glibc struct rseq from __rseq_offset @ " PFX
                " for thread => %s:%s0x%x\n",
                seg_base + offset, get_register_name(LIB_SEG_TLS),
                (offset < 0 ? "-" : ""), ABS(offset));
            break;
        }
    }
    module_iterator_stop(iter);
    return offset;
}

/* If we did not observe the app invoke SYS_rseq (because we attached mid-run)
 * we must search for its TLS location.
 */
static int
rseq_locate_tls_offset(void)
{
    /* We assume (and document) that the loader's static TLS is used, so every thread
     * has a consistent %fs:-offs address.  Unfortunately, using a local copy of the
     * rseq code for our non-instrumented execution requires us to locate the app's
     * struct using heuristics, because the system call was poorly designed and will not
     * let us replace the app's. Alternatives of no local copy have worse problems.
     */
    /* We simply search all possible aligned slots.  Typically there
     * are <64 possible slots.
     */
    int offset = 0;
    byte *addr = get_app_segment_base(LIB_SEG_TLS);
    if (addr > 0) {
        offset = rseq_locate_glibc_tls_offset(addr);
        if (offset != 0)
            return offset;
        byte *try_glibc_addr = addr + GLIBC_RSEQ_OFFSET;
        if (try_struct_rseq(try_glibc_addr)) {
            LOG(GLOBAL, LOG_LOADER, 2,
                "Found glibc struct rseq @ " PFX " for thread => %s:%s0x%x\n",
                try_glibc_addr, get_register_name(LIB_SEG_TLS),
                (GLIBC_RSEQ_OFFSET < 0 ? "-" : ""), ABS(GLIBC_RSEQ_OFFSET));
            return GLIBC_RSEQ_OFFSET;
        }
    }
    /* Either the app's glibc does not have rseq support (old glibc or disabled by app)
     * or the offset of glibc's struct rseq has changed. We do a wider search now.
     */
    byte *seg_bottom;
    size_t seg_size;
    if (addr > 0 && get_memory_info(addr, &seg_bottom, &seg_size, NULL)) {
        LOG(GLOBAL, LOG_LOADER, 3, "rseq within static TLS " PFX " - " PFX "\n",
            seg_bottom, addr);
        /* struct rseq_cs is aligned to 32. */
        int alignment = __alignof(struct rseq_cs);
        int i;
        /* When rseq support is enabled in glibc 2.35+, the glibc-registered struct rseq
         * is present in the struct pthread, which is at a positive offset from the
         * app library segment base on x86, and negative on aarchxx. However, in the
         * absence of rseq support from glibc, the app manually registers its own
         * struct rseq which is present in static TLS, which is at a negative offset
         * from the app library segment base on x86, and positive on aarchxx.
         */
        ASSERT(seg_bottom <= addr && addr < seg_bottom + seg_size);
        for (i = (seg_bottom - addr) / alignment;
             addr + i * alignment < seg_bottom + seg_size; ++i) {
            byte *try_addr = addr + i * alignment;
            ASSERT(seg_bottom <= try_addr &&
                   try_addr < seg_bottom + seg_size); /* For loop guarantees this. */
            /* Our strategy is to check all of the aligned addresses to find the
             * registered one.  Our caller is not supposed to call here until the app
             * has registered the current thread (either manually or using glibc).
             */
            if (try_struct_rseq(try_addr)) {
                LOG(GLOBAL, LOG_LOADER, 2,
                    "Found struct rseq @ " PFX " for thread => %s:%s0x%x\n", try_addr,
                    get_register_name(LIB_SEG_TLS), (i < 0 ? "-" : ""),
                    ABS(i) * alignment);
                offset = i * alignment;
                break;
            }
        }
    }
    return offset;
}

void
rseq_process_syscall(dcontext_t *dcontext)
{
    byte *seg_base = get_app_segment_base(LIB_SEG_TLS);
    byte *app_addr = (byte *)dcontext->sys_param0;
    bool constant_offset = false;
    if (rseq_tls_offset == 0) {
        SELF_UNPROTECT_DATASEC(DATASEC_RARELY_PROT);
        int offset = app_addr - seg_base;
        /* To handle races here, we use an atomic_exchange. */
        int prior = atomic_exchange_int(&rseq_tls_offset, offset);
        SELF_PROTECT_DATASEC(DATASEC_RARELY_PROT);
        constant_offset = (prior == 0 || prior == offset);
        LOG(GLOBAL, LOG_LOADER, 2,
            "Observed struct rseq at syscall @ " PFX " for thread => %s:%s0x%x\n",
            app_addr, get_register_name(LIB_SEG_TLS), (rseq_tls_offset < 0 ? "-" : ""),
            ABS(rseq_tls_offset));
    } else
        constant_offset = (seg_base + rseq_tls_offset == app_addr);
    if (!constant_offset) {
        REPORT_FATAL_ERROR_AND_EXIT(RSEQ_BEHAVIOR_UNSUPPORTED, 3, get_application_name(),
                                    get_application_pid(),
                                    "struct rseq is not always at the same offset");
        ASSERT_NOT_REACHED();
    }
    /* This may be glibc's registration from ld.so, before it relocates any module:
     * rseq_process_module() does not depend on whether it has.
     */
    rseq_locate_rseq_regions();
}

/* Restartable sequence region identification.
 *
 * To avoid extra overhead going to disk to read section headers, we delay looking
 * for rseq data until the app invokes an rseq syscall (or on attach we see a thread
 * that has rseq set up).  We document that we do not handle the app using rseq
 * regions for non-rseq purposes, so we do not need to flush the cache here.
 * Since we also identify the rseq_cs address here, this should be called *after*
 * the app has registered the current thread for rseq.
 */
void
rseq_locate_rseq_regions(void)
{
    if (rseq_enabled)
        return;
    /* This is a global operation, but the trigger could be hit by two threads at once,
     * thus requiring synchronization.
     */
    d_r_mutex_lock(&rseq_trigger_lock);
    if (rseq_enabled) {
        d_r_mutex_unlock(&rseq_trigger_lock);
        return;
    }

    int offset = 0;
    if (rseq_tls_offset == 0) {
        /* Identify the TLS offset of this thread's struct rseq. */
        offset = rseq_locate_tls_offset();
        if (offset == 0) {
            REPORT_FATAL_ERROR_AND_EXIT(
                RSEQ_BEHAVIOR_UNSUPPORTED, 3, get_application_name(),
                get_application_pid(),
                "struct rseq is not in static thread-local storage");
            ASSERT_NOT_REACHED();
        }
    }

    SELF_UNPROTECT_DATASEC(DATASEC_RARELY_PROT);
    bool new_value = true;
    ATOMIC_1BYTE_WRITE(&rseq_enabled, new_value, false);
    if (rseq_tls_offset == 0)
        ATOMIC_4BYTE_WRITE(&rseq_tls_offset, offset, false);
    SELF_PROTECT_DATASEC(DATASEC_RARELY_PROT);

    module_iterator_t *iter = module_iterator_start();
    while (module_iterator_hasnext(iter)) {
        module_area_t *ma = module_iterator_next(iter);
        /* Deferred modules are processed when they first execute. */
        if (!TESTANY(MODULE_RSEQ_DEFERRED, ma->flags))
            rseq_process_module(ma);
    }
    module_iterator_stop(iter);
    d_r_mutex_unlock(&rseq_trigger_lock);
}

void
rseq_module_init(module_area_t *ma, bool at_map)
{
    ASSERT(os_get_module_info_write_locked());
    if (at_map) {
        /* At its first mapping a module is not ready to read: the loader maps the
         * file over the module's whole extent and then maps each later segment over
         * that from its own file offset, so only the first segment is in place yet.
         * The same mapping also arises when the app maps an ELF file whole to read it
         * as data, as libunwind does with its own executable to print a backtrace;
         * such a mapping never becomes a module.  We defer until the module first
         * executes (rseq_module_executed()), by which time it has been mapped, and
         * before any of its rseq regions can run.
         */
        ma->flags |= MODULE_RSEQ_DEFERRED;
        return;
    }
    if (rseq_enabled)
        rseq_process_module(ma);
}

void
rseq_module_executed(app_pc pc)
{
    os_get_module_info_lock();
    module_area_t *ma = module_pc_lookup(pc);
    bool deferred = ma != NULL && TESTANY(MODULE_RSEQ_DEFERRED, ma->flags);
    os_get_module_info_unlock();
    if (!deferred)
        return;
    /* The trigger lock orders this against rseq_locate_rseq_regions(), which skips
     * deferred modules: each module is processed once, by whichever comes second.
     */
    d_r_mutex_lock(&rseq_trigger_lock);
    os_get_module_info_write_lock();
    ma = module_pc_lookup(pc);
    if (ma != NULL && TESTANY(MODULE_RSEQ_DEFERRED, ma->flags)) {
        ma->flags &= ~MODULE_RSEQ_DEFERRED;
        LOG(GLOBAL, LOG_LOADER, 2, "%s: %s first executes at " PFX "\n", __FUNCTION__,
            GET_MODULE_NAME(&ma->names) == NULL ? "(null)" : GET_MODULE_NAME(&ma->names),
            pc);
        if (rseq_enabled)
            rseq_process_module(ma);
    }
    os_get_module_info_write_unlock();
    d_r_mutex_unlock(&rseq_trigger_lock);
}

void
rseq_process_native_abort(dcontext_t *dcontext)
{
    /* Raise a transfer event. */
    LOG(THREAD, LOG_INTERP | LOG_VMAREAS, 2, "Abort triggered in rseq native code\n");
    /* We do not know the precise interruption point but we try to present something
     * reasonable.
     */
    rseq_region_t *info = NULL;
    priv_mcontext_t *source_mc = NULL;
    if (dcontext->last_fragment != NULL &&
        vmvector_lookup_data(d_r_rseq_areas, dcontext->last_fragment->tag, NULL, NULL,
                             (void **)&info)) {
        /* An artifact of our run-twice solution is that clients have already seen
         * the whole sequence when any abort anywhere in the native execution occurs.
         * We leave it up to the client to roll back at least the final instr.
         * Since we don't know the interrupted PC (the kernel doesn't tell us), we
         * do what the kernel does and present the abort handler as the PC.
         * We similarly use the target context for the rest of the context.
         */
        source_mc = HEAP_TYPE_ALLOC(dcontext, priv_mcontext_t, ACCT_CLIENT, PROTECTED);
        *source_mc = *get_mcontext(dcontext);
        source_mc->pc = info->handler;
    }
    get_mcontext(dcontext)->pc = dcontext->next_tag;
    if (instrument_kernel_xfer(dcontext, DR_XFER_RSEQ_ABORT, osc_empty, NULL, source_mc,
                               dcontext->next_tag, get_mcontext(dcontext)->xsp, osc_empty,
                               get_mcontext(dcontext), 0)) {
        dcontext->next_tag = canonicalize_pc_target(dcontext, get_mcontext(dcontext)->pc);
    }
    if (source_mc != NULL)
        HEAP_TYPE_FREE(dcontext, source_mc, priv_mcontext_t, ACCT_CLIENT, PROTECTED);
    /* Make sure we do not raise a duplicate abort if we had a pending signal that
     * caused the abort.  (It might be better to instead suppress this abort-exit
     * event and present the signal as causing the abort but that is more complex
     * to implement so we pretend the signal came in after the abort.)
     * XXX: We saw a double abort and assume it is from some signal+abort
     * combination but we failed to reproduce it in our linux.rseq tests cases
     * so we do not have proof that this is solving anything here.
     */
    translate_clear_last_direct_translation(dcontext);
}

void
rseq_insert_start_label(dcontext_t *dcontext, app_pc tag, instrlist_t *ilist)
{
    app_pc start, end, handler;
    if (!rseq_get_region_info(tag, &start, &end, &handler, NULL, NULL) || tag != start) {
        ASSERT_NOT_REACHED(); /* Caller must ensure tag is the start. */
        return;
    }
    instr_t *label = INSTR_CREATE_label(dcontext);
    instr_set_note(label, (void *)DR_NOTE_RSEQ_ENTRY);
    dr_instr_label_data_t *data = instr_get_label_data_area(label);
    data->data[0] = (ptr_uint_t)end;
    data->data[1] = (ptr_uint_t)handler;
    instrlist_meta_preinsert(ilist, instrlist_first(ilist), label);
}

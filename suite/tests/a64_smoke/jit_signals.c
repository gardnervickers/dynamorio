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

/*
 * The C workloads of the AArch64 real-workload smoke tests (see README.md):
 * code that is rewritten while other threads run and receive signals, the
 * windows in which a JIT'd runtime under DR (with -no_hw_cache_consistency,
 * where cache maintenance becomes a flush that synchronizes with every
 * thread) has broken.  Every count printed is fixed by the arguments, and
 * every computed value is checked, so the output does not depend on timing.
 *
 * Usage: a64_smoke_jit MODE [ROUNDS]
 *   flush      workers run register-heavy loops and hand a mutex around while
 *              the main thread rewrites and calls a code slot, and signals
 *              the workers in turn with tgkill, waiting for each to arrive
 *   jit        each writer thread rewrites "movz w0, #v; ret" slots in its own
 *              page, flushes and calls them; executor threads call slots of
 *              every page in a tight loop under a stream of SIGUSR1; a mapper
 *              thread maps, fills, calls and unmaps fresh code pages
 *   exclusive  two threads increment a shared and a private word with
 *              ldxr/stxr loops while the main thread rewrites and calls code
 *              and signals them: the totals must come out exact
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define MAX_THREADS 8
#define SLOTS 64

static atomic_int stop;
static atomic_int ready;
static pid_t tids[MAX_THREADS];
static atomic_long received[MAX_THREADS];
static __thread int my_index;

static void
fail(const char *what, long a, long b)
{
    fprintf(stderr, "FAIL: %s (%ld, %ld)\n", what, a, b);
    exit(1);
}

static double
now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static uint32_t *
code_page(void)
{
    uint32_t *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
        fail("mmap", 0, 0);
    return page;
}

/* Writes "movz w0, #value; ret" at slot and makes it executable. */
static void
put_movz(uint32_t *slot, uint32_t value)
{
    atomic_store_explicit((_Atomic uint32_t *)&slot[0],
                          0x52800000u | (value & 0xffff) << 5, memory_order_relaxed);
    slot[1] = 0xd65f03c0;
    __builtin___clear_cache((char *)slot, (char *)(slot + 2));
}

static uint32_t
call_slot(uint32_t *slot)
{
    return ((uint32_t (*)(void))slot)();
}

static uint64_t __attribute__((noinline))
mix(uint64_t a, uint64_t b, int n)
{
    uint64_t x = a, y = b, z = a ^ b, w = 7, v = a + 3;
    for (int i = 0; i < n; i++) {
        x = x * 6364136223846793005ULL + y;
        y ^= x >> 17;
        z += y * 3 + (x << 5);
        w ^= z + (uint64_t)i;
        v = (v << 7 | v >> 57) ^ w;
        if ((x & 3) == 0)
            y += w ^ v;
    }
    return x ^ y ^ z ^ w ^ v;
}

static void
handler(int sig, siginfo_t *info, void *ucontext)
{
    /* Register work in the handler too. */
    if (mix((uint64_t)sig, (uint64_t)my_index, 50) == 0)
        abort(); /* Never: keeps the call. */
    atomic_fetch_add(&received[my_index], 1);
}

static void
register_thread(int index)
{
    my_index = index;
    tids[index] = (pid_t)syscall(SYS_gettid);
    atomic_fetch_add(&ready, 1);
}

static void
wait_ready(int n)
{
    while (atomic_load(&ready) < n)
        sched_yield();
}

/* Signals thread index and waits until its handler has run. */
static void
signal_and_wait(int index)
{
    long before = atomic_load(&received[index]);
    syscall(SYS_tgkill, getpid(), tids[index], SIGUSR1);
    double start = now();
    while (atomic_load(&received[index]) == before) {
        if (now() - start > 120)
            fail("signal not delivered to thread", index, before);
        sched_yield();
    }
}

static void
join_all(pthread_t *th, int n, long *results)
{
    for (int i = 0; i < n; i++) {
        void *res;
        pthread_join(th[i], &res);
        if (results != NULL)
            results[i] = (long)res;
    }
}

/***************************************************************************
 * flush
 */

#define FLUSH_WORKERS 4
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static long handoffs;

static void *
flush_worker(void *arg)
{
    long id = (long)arg;
    register_thread((int)id);
    uint64_t ref = mix((uint64_t)id, 99, 1000);
    long bad = 0;
    for (long it = 0; !atomic_load(&stop); it++) {
        if (mix((uint64_t)id, 99, 1000) != ref) {
            fprintf(stderr, "worker %ld: wrong result at iteration %ld\n", id, it);
            bad++;
        }
        pthread_mutex_lock(&lock);
        handoffs++;
        pthread_mutex_unlock(&lock);
        if (it % 64 == 0)
            sched_yield();
    }
    return (void *)bad;
}

static void
run_flush(int rounds)
{
    pthread_t th[FLUSH_WORKERS];
    for (long i = 0; i < FLUSH_WORKERS; i++)
        pthread_create(&th[i], NULL, flush_worker, (void *)i);
    wait_ready(FLUSH_WORKERS);
    uint32_t *code = code_page();
    int signals = 0;
    for (int r = 0; r < rounds; r++) {
        uint32_t k = (uint32_t)r & 0xfff;
        /* add x0, x0, #k or sub x0, x0, #k; then ret. */
        code[0] = (r % 2 == 0 ? 0x91000000 : 0xd1000000) | (k << 10);
        code[1] = 0xd65f03c0;
        __builtin___clear_cache((char *)code, (char *)(code + 2));
        uint64_t got = ((uint64_t (*)(uint64_t))code)(100000);
        uint64_t want = r % 2 == 0 ? 100000 + k : 100000 - k;
        if (got != want)
            fail("generated code returned a stale result", (long)got, (long)want);
        if (r % 4 == 0) {
            signal_and_wait((r / 4) % FLUSH_WORKERS);
            signals++;
        }
    }
    atomic_store(&stop, 1);
    long bad[FLUSH_WORKERS];
    join_all(th, FLUSH_WORKERS, bad);
    for (int i = 0; i < FLUSH_WORKERS; i++) {
        if (bad[i] != 0)
            fail("worker computed wrong results", i, bad[i]);
    }
    printf("flush: rounds %d signals %d\n", rounds, signals);
    for (int i = 0; i < FLUSH_WORKERS; i++)
        printf("worker %d received %ld\n", i, atomic_load(&received[i]));
}

/***************************************************************************
 * jit
 */

#define JIT_WRITERS 3
#define JIT_EXECUTORS 2
static uint32_t *pages[JIT_WRITERS];
static long jit_rounds;
static atomic_int writers_done;
static atomic_long exec_bad;

/* Slot values encode the writer and the slot: (writer << 13) | (gen << 6) | slot. */
static void *
jit_writer(void *arg)
{
    long id = (long)arg;
    uint32_t *page = pages[id];
    for (long i = 0; i < jit_rounds; i++) {
        uint32_t slot = (uint32_t)(i % SLOTS);
        uint32_t value = (uint32_t)id << 13 | (uint32_t)(i / SLOTS % 128) << 6 | slot;
        put_movz(&page[slot * 2], value);
        uint32_t got = call_slot(&page[slot * 2]);
        if (got != value)
            fail("writer called a stale slot", (long)got, (long)value);
    }
    atomic_fetch_add(&writers_done, 1);
    return NULL;
}

static void *
jit_executor(void *arg)
{
    long id = (long)arg;
    register_thread((int)id);
    uint64_t x = (uint64_t)id * 0x9E3779B97F4A7C15ULL | 1;
    while (atomic_load(&writers_done) < JIT_WRITERS) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        uint32_t w = (uint32_t)(x % JIT_WRITERS), slot = (uint32_t)(x >> 8) % SLOTS;
        uint32_t got = call_slot(&pages[w][slot * 2]);
        if ((got & 63) != slot || got >> 13 != w)
            atomic_fetch_add(&exec_bad, 1);
    }
    return NULL;
}

static void *
jit_mapper(void *arg)
{
    long rounds = (long)arg;
    for (long i = 0; i < rounds; i++) {
        uint32_t *page = code_page();
        put_movz(page, (uint32_t)i);
        if (call_slot(page) != ((uint32_t)i & 0xffff))
            fail("fresh page returned a stale result", i, 0);
        munmap(page, 4096);
    }
    return NULL;
}

static void
run_jit(int rounds)
{
    /* Every slot starts as a valid function for its writer. */
    for (long w = 0; w < JIT_WRITERS; w++) {
        pages[w] = code_page();
        for (uint32_t s = 0; s < SLOTS; s++)
            put_movz(&pages[w][s * 2], (uint32_t)w << 13 | s);
    }
    pthread_t ex[JIT_EXECUTORS], wr[JIT_WRITERS], mapper;
    for (long i = 0; i < JIT_EXECUTORS; i++)
        pthread_create(&ex[i], NULL, jit_executor, (void *)i);
    wait_ready(JIT_EXECUTORS);
    jit_rounds = rounds;
    for (long i = 0; i < JIT_WRITERS; i++)
        pthread_create(&wr[i], NULL, jit_writer, (void *)i);
    pthread_create(&mapper, NULL, jit_mapper, (void *)(long)(rounds / 8));
    /* A SIGUSR1 stream to the executors until the writers finish. */
    long sent = 0;
    struct timespec gap = { 0, 50000 };
    while (atomic_load(&writers_done) < JIT_WRITERS) {
        syscall(SYS_tgkill, getpid(), tids[sent % JIT_EXECUTORS], SIGUSR1);
        sent++;
        nanosleep(&gap, NULL);
    }
    join_all(wr, JIT_WRITERS, NULL);
    join_all(&mapper, 1, NULL);
    join_all(ex, JIT_EXECUTORS, NULL);
    if (atomic_load(&exec_bad) != 0)
        fail("executors called slots with wrong contents", atomic_load(&exec_bad), 0);
    if (sent > 0 && atomic_load(&received[0]) + atomic_load(&received[1]) == 0)
        fail("no signal reached an executor", sent, 0);
    printf("jit: writers %d x %d rounds, mapper %d pages\n", JIT_WRITERS, rounds,
           rounds / 8);
}

/***************************************************************************
 * exclusive
 */

struct line {
    volatile uint64_t v;
    char pad[56];
};
static struct line shared __attribute__((aligned(64))),
    priv[2] __attribute__((aligned(64)));
static long exclusive_count;

static void
increment(volatile uint64_t *word)
{
    uint64_t v;
    uint32_t failed;
    do {
        __asm__ volatile("ldxr %0, [%2]\n\t"
                         "add %0, %0, #1\n\t"
                         "stxr %w1, %0, [%2]"
                         : "=&r"(v), "=&r"(failed)
                         : "r"(word)
                         : "memory");
    } while (failed != 0);
}

static void *
exclusive_worker(void *arg)
{
    long id = (long)arg;
    register_thread((int)id);
    for (long i = 0; i < exclusive_count; i++) {
        increment(&shared.v);
        increment(&priv[id].v);
        if (i % 256 == 0)
            sched_yield(); /* Let the main thread's flushes in. */
    }
    return NULL;
}

static void
run_exclusive(int rounds)
{
    long count = (long)rounds * 500;
    exclusive_count = count;
    pthread_t th[2];
    for (long i = 0; i < 2; i++)
        pthread_create(&th[i], NULL, exclusive_worker, (void *)i);
    wait_ready(2);
    uint32_t *code = code_page();
    for (uint32_t r = 0; shared.v < 2 * (uint64_t)count; r++) {
        put_movz(code, r);
        if (call_slot(code) != (r & 0xffff))
            fail("generated code returned a stale result", r, 0);
        if (r % 8 == 0)
            syscall(SYS_tgkill, getpid(), tids[r / 8 % 2], SIGUSR1);
        sched_yield();
    }
    join_all(th, 2, NULL);
    if (shared.v != 2 * (uint64_t)count || priv[0].v != (uint64_t)count ||
        priv[1].v != (uint64_t)count) {
        fprintf(stderr,
                "FAIL: shared %llu (want %llu), private %llu and %llu (want %ld)\n",
                (unsigned long long)shared.v, 2 * (unsigned long long)count,
                (unsigned long long)priv[0].v, (unsigned long long)priv[1].v, count);
        exit(1);
    }
    printf("exclusive: shared %llu private %llu %llu\n", (unsigned long long)shared.v,
           (unsigned long long)priv[0].v, (unsigned long long)priv[1].v);
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s flush|jit|exclusive [ROUNDS]\n", argv[0]);
        return 2;
    }
    int rounds = argc > 2 ? atoi(argv[2]) : 2000;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
    if (strcmp(argv[1], "flush") == 0)
        run_flush(rounds);
    else if (strcmp(argv[1], "jit") == 0)
        run_jit(rounds);
    else if (strcmp(argv[1], "exclusive") == 0)
        run_exclusive(rounds);
    else {
        fprintf(stderr, "unknown mode %s\n", argv[1]);
        return 2;
    }
    printf("ok\n");
    return 0;
}

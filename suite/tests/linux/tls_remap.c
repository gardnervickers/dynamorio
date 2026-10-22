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

/* Threads whose stack, and so their TLS block (glibc puts it at the top of a
 * user-supplied stack), lies in a region we unmap, remap and mprotect at the same
 * address between threads.  DR checks that the app's TLS base is mapped and
 * writable before switching the thread register to it, from its memory cache:
 * the cache must follow each change, or a thread runs on DR's private TLS (and
 * its TLS variable reads wrong) or DR writes to an unmapped TLS slot.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define SZ (1024 * 1024)
#define ITERS 50

static __thread long tls_var = 7;

static void *
thread_func(void *arg)
{
    if (tls_var != 7)
        return (void *)-1;
    tls_var = (long)arg;
    return (void *)tls_var;
}

static void
run_on(void *stack, size_t size, long val)
{
    pthread_attr_t attr;
    pthread_t thread;
    void *res;
    pthread_attr_init(&attr);
    if (pthread_attr_setstack(&attr, stack, size) != 0 ||
        pthread_create(&thread, &attr, thread_func, (void *)val) != 0 ||
        pthread_join(thread, &res) != 0 || (long)res != val) {
        fprintf(stderr, "thread %ld failed\n", val);
        exit(1);
    }
    pthread_attr_destroy(&attr);
}

static void
map_fixed(char *addr, size_t size, int prot)
{
    if (mmap(addr, size, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != addr) {
        perror("mmap");
        exit(1);
    }
}

int
main(void)
{
    long page = sysconf(_SC_PAGESIZE);
    char *base =
        mmap(NULL, 2 * SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    long val = 1;
    for (int i = 0; i < ITERS; i++) {
        run_on(base, SZ, val++);
        /* A fresh region at the same address. */
        munmap(base, 2 * SZ);
        map_fixed(base, SZ, PROT_READ | PROT_WRITE);
        run_on(base, SZ, val++);
        /* Inaccessible, then writable again. */
        mprotect(base, SZ, PROT_NONE);
        mprotect(base, SZ, PROT_READ | PROT_WRITE);
        run_on(base, SZ, val++);
        /* Mapped inaccessible, then made writable. */
        map_fixed(base, SZ, PROT_NONE);
        mprotect(base, SZ, PROT_READ | PROT_WRITE);
        run_on(base, SZ, val++);
        /* Another region moved over it. */
        char *other = mmap(NULL, 2 * SZ, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (other == MAP_FAILED ||
            mremap(other, 2 * SZ, 2 * SZ, MREMAP_MAYMOVE | MREMAP_FIXED, base) != base) {
            perror("mremap");
            return 1;
        }
        run_on(base, 2 * SZ, val++);
        /* Partly unmapped, with an inaccessible guard page below the stack. */
        munmap(base + SZ, SZ);
        mprotect(base, page, PROT_NONE);
        run_on(base + page, SZ - page, val++);
        map_fixed(base, 2 * SZ, PROT_READ | PROT_WRITE);
    }
    printf("all done\n");
    return 0;
}

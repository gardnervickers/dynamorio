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

/* client.a64_module_class: see a64_module_class.dll.c.  The app runs a function
 * with a direct branch in its own code, one in a library it dlopen()s, and
 * clock_gettime(), which runs the vdso's.
 */

#include "tools.h"
#include <dlfcn.h>
#include <time.h>

/* A direct branch over a word that is never run: DR elides it in a block when it
 * counts the code as code that cannot change unseen.
 */
int
a64_module_class_exe(void);
/* clang-format off */
__asm__(".text\n"
        ".globl a64_module_class_exe\n"
        ".type a64_module_class_exe, %function\n"
        "a64_module_class_exe:\n"
        "  mov x0, #1\n"
        "  b 1f\n"
        "  udf #0\n"
        "1:\n"
        "  add x0, x0, #1\n"
        "  ret\n");
/* clang-format on */

int
main(int argc, const char *argv[])
{
    if (argc < 2) {
        print("usage: a64_module_class <library>\n");
        return 1;
    }
    /* Indirectly, so that the function starts a block of its own (with -opt_speed a
     * direct call would be elided).
     */
    int (*volatile exe_func)(void) = a64_module_class_exe;
    print("executable: %d\n", exe_func());
    void *lib = dlopen(argv[1], RTLD_NOW);
    if (lib == NULL) {
        print("failed to load %s: %s\n", argv[1], dlerror());
        return 1;
    }
    int (*func)(void) = (int (*)(void))dlsym(lib, "a64_module_class_lib");
    if (func == NULL) {
        print("failed to find a64_module_class_lib\n");
        return 1;
    }
    print("library: %d\n", func());
    dlclose(lib);
    /* Through the vdso's __kernel_clock_gettime. */
    struct timespec ts;
    print("clock_gettime: %d\n", clock_gettime(CLOCK_MONOTONIC, &ts));
    print("all done\n");
    return 0;
}

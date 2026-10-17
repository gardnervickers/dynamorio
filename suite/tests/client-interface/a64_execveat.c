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
 * The app for client.a64_execveat (see a64_execveat.dll.c): fexecve's a
 * close-on-exec memfd copy of itself, whose image spins in a loop without
 * syscalls.  Unless DR follows the SYS_execveat the client is not there to
 * count the loop.
 */

#include "tools.h"
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#    define MFD_CLOEXEC 0x0001U
#endif
#ifndef AT_EMPTY_PATH
#    define AT_EMPTY_PATH 0x1000
#endif

/* Must match a64_execveat.dll.c. */
#define LOOP_ITERS 1000000

extern char **environ;

static volatile int counter;

int
main(int argc, char *argv[])
{
    char self[PATH_MAX], buf[4096];
    char *args[] = { self, (char *)"loop", NULL };
    ssize_t len;
    int mfd, fd;
    if (argc == 2 && strcmp(argv[1], "loop") == 0) {
        int i;
        for (i = 0; i < LOOP_ITERS; i++)
            counter++;
        print("loop done\n");
        return 0;
    }
    if (realpath(argv[0], self) == NULL) {
        perror("realpath");
        return 1;
    }
    mfd = (int)syscall(SYS_memfd_create, "a64_execveat", MFD_CLOEXEC);
    fd = open(self, O_RDONLY);
    if (mfd < 0 || fd < 0) {
        perror("open");
        return 1;
    }
    while ((len = read(fd, buf, sizeof(buf))) > 0) {
        if (write(mfd, buf, len) != len) {
            perror("write");
            return 1;
        }
    }
    close(fd);
    print("parent execs the memfd\n");
    syscall(SYS_execveat, mfd, "", args, environ, AT_EMPTY_PATH);
    perror("execveat");
    return 1;
}

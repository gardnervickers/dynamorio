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
 * Tests that DR follows SYS_execveat into the new image: fexecve of a
 * close-on-exec memfd and of an O_PATH fd (the fd is closed by the exec, yet
 * DR's loader must still open the app after it), a path relative to a
 * close-on-exec dirfd, AT_SYMLINK_NOFOLLOW, and scripts.  Execveats that fail
 * must fail with the native errno and leave the parent under DR, with no fd
 * left behind.  We use the raw syscall to avoid libc's fallbacks.
 */

#include "tools.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#    define MFD_CLOEXEC 0x0001U
#endif
#ifndef AT_EMPTY_PATH
#    define AT_EMPTY_PATH 0x1000
#endif
#ifndef O_PATH
#    define O_PATH 010000000
#endif

extern char **environ;

static char self[PATH_MAX];

static int
do_execveat(int dirfd, const char *path, char *const argv[], int flags)
{
    return (int)syscall(SYS_execveat, dirfd, path, argv, environ, flags);
}

static int
make_memfd(const char *name, unsigned int flags)
{
    int fd = (int)syscall(SYS_memfd_create, name, flags);
    if (fd < 0) {
        perror("memfd_create");
        exit(1);
    }
    return fd;
}

static int
copy_self_to_memfd(void)
{
    char buf[4096];
    ssize_t len;
    int mfd = make_memfd("execveat", MFD_CLOEXEC);
    int fd = open(self, O_RDONLY);
    if (fd < 0) {
        perror("open self");
        exit(1);
    }
    while ((len = read(fd, buf, sizeof(buf))) > 0) {
        if (write(mfd, buf, len) != len) {
            perror("write memfd");
            exit(1);
        }
    }
    close(fd);
    return mfd;
}

static int
count_fds(void)
{
    int count = 0;
    DIR *dir = opendir("/proc/self/fd");
    struct dirent *ent;
    if (dir == NULL)
        return -1;
    while ((ent = readdir(dir)) != NULL)
        count++;
    closedir(dir);
    return count;
}

/* Runs an execveat that should succeed in a child, which reports whether it is
 * under DR and checks the names the kernel gives it (comm is the one the kernel
 * gives since Linux 6.14).  A vfork child shares our memory, and so DR's state,
 * but not our fds.
 */
static void
exec_in_child(const char *tag, int dirfd, const char *path, int flags, const char *comm,
              bool use_vfork)
{
    int status, fds_before = count_fds();
    char execfn[PATH_MAX];
    char *args[] = { self, (char *)"child", (char *)tag, execfn, (char *)comm, NULL };
    pid_t child;
    if (dirfd != AT_FDCWD && path[0] != '/') {
        snprintf(execfn, sizeof(execfn), "/dev/fd/%d%s%s", dirfd,
                 path[0] == '\0' ? "" : "/", path);
    } else
        snprintf(execfn, sizeof(execfn), "%s", path);
    child = use_vfork ? vfork() : fork();
    if (child < 0) {
        perror("fork");
        exit(1);
    }
    if (child == 0) {
        do_execveat(dirfd, path, args, flags);
        _exit(1);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        print("ERROR: child %s exited abnormally: 0x%x\n", tag, status);
    if (count_fds() != fds_before)
        print("ERROR: %d fds before child %s, %d after\n", fds_before, tag, count_fds());
}

static void
expect_failure(const char *tag, int dirfd, const char *path, char *const argv[],
               int flags, int expect_errno)
{
    int res = do_execveat(dirfd, path, argv, flags);
    if (res != -1 || errno != expect_errno) {
        print("ERROR: execveat %s returned %d errno %s, not %s\n", tag, res,
              strerror(errno), strerror(expect_errno));
    } else
        print("execveat %s failed with %s\n", tag, strerror(expect_errno));
}

static int
child_main(const char *tag, const char *execfn, const char *comm)
{
    char buf[64] = "";
    const char *base = strrchr(execfn, '/') + 1;
    int fd = open("/proc/self/comm", O_RDONLY);
    print("child %s is running %s\n", tag,
          find_dynamo_library() ? "under DynamoRIO" : "natively");
    if (strcmp((const char *)getauxval(AT_EXECFN), execfn) != 0) {
        print("ERROR: AT_EXECFN is %s, not %s\n", (const char *)getauxval(AT_EXECFN),
              execfn);
    }
    if (fd < 0 || read(fd, buf, sizeof(buf) - 1) <= 0)
        perror("read comm");
    close(fd);
    if (strchr(buf, '\n') != NULL)
        *strchr(buf, '\n') = '\0';
    /* Before Linux 6.14 comm was always the basename of AT_EXECFN. */
    if (strncmp(buf, comm, 15) != 0 && strncmp(buf, base, 15) != 0)
        print("ERROR: comm is %s, not %s or %s\n", buf, comm, base);
    /* DR's loader must have disabled the var it was passed its fd in. */
    if (getenv("DYNAMORIO_EXE_FD") != NULL)
        print("ERROR: DYNAMORIO_EXE_FD is visible\n");
    return 0;
}

static void
test_failures(int mfd, int dirfd, const char *base)
{
    char *args[] = { self, (char *)"child", (char *)"fail", NULL };
    char *big_args[] = { self, NULL, NULL };
    char tmpdir[] = "/tmp/execveat.XXXXXX";
    char link[PATH_MAX];
    int tmpfd, fds_before, fds_after;
    /* The kernel limits a single argument to 32 pages. */
    size_t big_len = 512 * 1024;

    fds_before = count_fds();
    expect_failure("missing", dirfd, "no-such-file", args, 0, ENOENT);
    expect_failure("empty path", mfd, "", args, 0, ENOENT);
    expect_failure("bad flags", mfd, "", args, AT_EMPTY_PATH | 0x8000, EINVAL);
    expect_failure("bad fd", 9999, base, args, 0, EBADF);
    expect_failure("directory", dirfd, "", args, AT_EMPTY_PATH, EACCES);

    if (mkdtemp(tmpdir) == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(link, sizeof(link), "%s/link", tmpdir);
    if (symlink(self, link) != 0) {
        perror("symlink");
        exit(1);
    }
    tmpfd = open(tmpdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    expect_failure("nofollow", AT_FDCWD, link, args, AT_SYMLINK_NOFOLLOW, ELOOP);
    expect_failure("nofollow dirfd", tmpfd, "link", args, AT_SYMLINK_NOFOLLOW, ELOOP);
    close(tmpfd);
    unlink(link);
    rmdir(tmpdir);

    /* The kernel fails this one only after DR has redirected it to its loader. */
    big_args[1] = malloc(big_len);
    memset(big_args[1], 'x', big_len - 1);
    big_args[1][big_len - 1] = '\0';
    expect_failure("too big", mfd, "", big_args, AT_EMPTY_PATH, E2BIG);
    free(big_args[1]);

    fds_after = count_fds();
    if (fds_after != fds_before)
        print("ERROR: %d fds before failed execveats, %d after\n", fds_before, fds_after);
    print("parent is still running %s\n",
          find_dynamo_library() ? "under DynamoRIO" : "natively");
}

static void
test_scripts(void)
{
    /* The kernel passes the interpreter the script as /dev/fd/<fd>. */
    static const char script[] =
        "#!/bin/sh\n"
        "case \"$0\" in /dev/fd/*) from=/dev/fd;; *) from=\"$0\";; esac\n"
        "if grep -q libdynamorio /proc/$$/maps; then dr=\"under DynamoRIO\";\n"
        "else dr=natively; fi\n"
        "echo \"script from $from is running $dr\" >&2\n";
    char *args[] = { (char *)"script", NULL };
    int mfd = make_memfd("execveat-script", MFD_CLOEXEC);
    if (write(mfd, script, strlen(script)) != (ssize_t)strlen(script)) {
        perror("write script");
        exit(1);
    }
    /* The kernel fails a script whose /dev/fd name the exec closes. */
    expect_failure("cloexec script", mfd, "", args, AT_EMPTY_PATH, ENOENT);
    if (fcntl(mfd, F_SETFD, 0) != 0) {
        perror("F_SETFD");
        exit(1);
    }
    exec_in_child("script", mfd, "", AT_EMPTY_PATH, "", false);
    close(mfd);
}

int
main(int argc, char *argv[])
{
    int mfd, dirfd, pathfd;
    char dir[PATH_MAX];
    char *base;

    if (argc == 5 && strcmp(argv[1], "child") == 0)
        return child_main(argv[2], argv[3], argv[4]);
    if (realpath(argv[0], self) == NULL) {
        perror("realpath");
        return 1;
    }
    print("parent is running %s\n",
          find_dynamo_library() ? "under DynamoRIO" : "natively");

    mfd = copy_self_to_memfd();
    exec_in_child("memfd", mfd, "", AT_EMPTY_PATH, "memfd:execveat", false);
    exec_in_child("vfork memfd", mfd, "", AT_EMPTY_PATH, "memfd:execveat", true);

    pathfd = open(self, O_PATH | O_CLOEXEC);
    exec_in_child("O_PATH fd", pathfd, "", AT_EMPTY_PATH, strrchr(self, '/') + 1, false);
    close(pathfd);

    strncpy(dir, self, sizeof(dir));
    base = strrchr(dir, '/');
    *base++ = '\0';
    dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        perror("open dir");
        return 1;
    }
    exec_in_child("dirfd", dirfd, base, 0, base, false);
    exec_in_child("vfork dirfd", dirfd, base, 0, base, true);
    exec_in_child("nofollow", AT_FDCWD, self, AT_SYMLINK_NOFOLLOW, base, false);
    exec_in_child("absolute", dirfd, self, 0, base, false);

    test_failures(mfd, dirfd, base);
    test_scripts();

    close(dirfd);
    close(mfd);
    print("all done\n");
    return 0;
}

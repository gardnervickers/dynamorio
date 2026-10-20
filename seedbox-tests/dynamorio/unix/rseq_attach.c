#define _GNU_SOURCE
#include "dr_api.h"
#include "dr_app.h"
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <unistd.h>

extern const ptrdiff_t __rseq_offset;
static __thread char extended[64] __attribute__((aligned(64)));

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    (void)id;
    (void)argc;
    (void)argv;
}

int
main(void)
{
    char *original = (char *)__builtin_thread_pointer() + __rseq_offset;
    fprintf(stderr, "kernel rseq feature size=%lu\n", getauxval(AT_RSEQ_FEATURE_SIZE));
    if (syscall(SYS_rseq, original, 32, 1, 0x53053053)) {
        perror("unregister");
        return 2;
    }
    if (syscall(SYS_rseq, extended, 64, 0, 0x53053053)) {
        perror("register");
        return 3;
    }
    if (dr_app_setup_and_start() != 0)
        return 4;
    if (!dr_app_running_under_dynamorio())
        return 5;
    dr_app_stop_and_cleanup();
    if (dr_app_running_under_dynamorio())
        return 6;
    if (syscall(SYS_rseq, extended, 64, 1, 0x53053053)) {
        perror("unregister extended");
        return 7;
    }
    if (syscall(SYS_rseq, original, 32, 0, 0x53053053)) {
        perror("restore");
        return 8;
    }
    puts("OK rseq64 attach and detach");
    return 0;
}

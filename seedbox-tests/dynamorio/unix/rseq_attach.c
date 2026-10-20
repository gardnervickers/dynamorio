#define _GNU_SOURCE
#include "dr_api.h"
#include "dr_app.h"
#include <stddef.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <sys/rseq.h>
#include <sys/syscall.h>
#include <unistd.h>

static __thread char extended[64] __attribute__((aligned(64)));

enum { RSEQ_INITIAL_REGISTRATION_SIZE = 32 };

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
    size_t original_size = __rseq_size < RSEQ_INITIAL_REGISTRATION_SIZE
        ? RSEQ_INITIAL_REGISTRATION_SIZE
        : __rseq_size;
    fprintf(stderr, "kernel rseq feature size=%lu, registered size=%zu\n",
            getauxval(AT_RSEQ_FEATURE_SIZE), original_size);
    if (syscall(SYS_rseq, original, original_size, RSEQ_FLAG_UNREGISTER, RSEQ_SIG)) {
        perror("unregister");
        return 2;
    }
    if (syscall(SYS_rseq, extended, sizeof(extended), 0, RSEQ_SIG)) {
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
    if (syscall(SYS_rseq, extended, sizeof(extended), RSEQ_FLAG_UNREGISTER,
                RSEQ_SIG)) {
        perror("unregister extended");
        return 7;
    }
    if (syscall(SYS_rseq, original, original_size, 0, RSEQ_SIG)) {
        perror("restore");
        return 8;
    }
    puts("OK rseq64 attach and detach");
    return 0;
}

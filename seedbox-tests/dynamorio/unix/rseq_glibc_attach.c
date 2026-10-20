#define _GNU_SOURCE
#include "dr_api.h"
#include "dr_app.h"
#include <errno.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <sys/rseq.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { RSEQ_INITIAL_REGISTRATION_SIZE = 32 };

int
main(void)
{
    if (__rseq_size == 0)
        return 2;
    char *area = (char *)__builtin_thread_pointer() + __rseq_offset;
    size_t feature_size = __rseq_size < RSEQ_INITIAL_REGISTRATION_SIZE
        ? RSEQ_INITIAL_REGISTRATION_SIZE
        : __rseq_size;
    size_t alignment = getauxval(AT_RSEQ_ALIGN);
    if (alignment < RSEQ_INITIAL_REGISTRATION_SIZE)
        alignment = RSEQ_INITIAL_REGISTRATION_SIZE;
    size_t size = (feature_size + alignment - 1) / alignment * alignment;
    if (syscall(SYS_rseq, area, size, 0, RSEQ_SIG) != -1 || errno != EBUSY)
        return 3;
    if (dr_app_setup_and_start() != 0)
        return 4;
    if (!dr_app_running_under_dynamorio())
        return 5;
    dr_app_stop_and_cleanup();
    if (dr_app_running_under_dynamorio())
        return 6;
    puts("OK glibc rseq attach and detach");
    return 0;
}

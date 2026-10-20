#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <ucontext.h>
#include <unistd.h>

extern char observer_fault_instruction[];

__attribute__((noinline)) static void
fault_probe(void)
{
    __asm__ volatile(".globl observer_fault_instruction\n"
                     "observer_fault_instruction:\n"
                     "ud2\n");
}

static void
handler(int sig, siginfo_t *info, void *context)
{
    ucontext_t *u = context;
    const int signal_ok = sig == SIGSEGV;
    const int address_ok = info->si_addr != NULL;
    const int pc_ok =
        (uintptr_t)u->uc_mcontext.gregs[REG_RIP] == (uintptr_t)observer_fault_instruction;
    char result[] =
        "observer-fault-fixture: signal-match=0 nonnull-address=0 application-pc=0\n";
    result[37] = '0' + signal_ok;
    result[55] = '0' + address_ok;
    result[72] = '0' + pc_ok;
    if (write(STDOUT_FILENO, result, sizeof(result) - 1) != sizeof(result) - 1)
        _exit(4);
    _exit(signal_ok && address_ok && pc_ok ? 0 : 1);
}

int
main(void)
{
    struct sigaction action = { .sa_sigaction = handler, .sa_flags = SA_SIGINFO };
    if (sigemptyset(&action.sa_mask) || sigaction(SIGSEGV, &action, NULL))
        return 2;
    fault_probe();
    return 3;
}

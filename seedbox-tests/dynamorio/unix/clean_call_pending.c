/* Deterministic public observer probe: queue one signal while a clean call is
 * active, then require delivery after it returns to a warmed application loop.
 * The application mode provides native/plain controls for the same siginfo. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t handled,bad;
static void handler(int sig,siginfo_t *info,void *context) {
    (void)context;
    bad |= sig!=SIGUSR1 || info->si_code!=SI_QUEUE || info->si_pid!=getpid() ||
        info->si_uid!=getuid() || info->si_value.sival_int!=77;
    handled++;
}
/* Keep a stable public marker and the same polling path before/after queueing.
 * The client supplies the signal in client mode, the app in application mode. */
__attribute__((noinline,visibility("default"))) void unix_queue_probe(void) {
    __asm__ volatile("" ::: "memory");
}
int main(int argc,char **argv) {
    if(argc!=2 || (strcmp(argv[1],"client") && strcmp(argv[1],"application")))return 2;
    int application=!strcmp(argv[1],"application");
    struct sigaction action={0};
    action.sa_sigaction=handler;action.sa_flags=SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if(sigaction(SIGUSR1,&action,NULL))return 2;
    sigset_t mask;
    sigemptyset(&mask);sigaddset(&mask,SIGUSR1);
    if(sigprocmask(SIG_UNBLOCK,&mask,NULL))return 2;
    unsigned visits=0;
    while(!handled) {
        unix_queue_probe();
        if(application && ++visits==4096) {
            siginfo_t info={0};
            info.si_signo=SIGUSR1;info.si_code=SI_QUEUE;
            info.si_pid=getpid();info.si_uid=getuid();info.si_value.sival_int=77;
            if(syscall(SYS_rt_tgsigqueueinfo,getpid(),syscall(SYS_gettid),SIGUSR1,&info))return 2;
        }
    }
    printf("queued signal handled %d identityBad %d\n",handled,bad);
    puts(handled==1 && !bad ? "OK" : "FAIL");
    return handled!=1 || bad;
}

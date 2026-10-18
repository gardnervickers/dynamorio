/* CI cleanup fixture: the main thread exits while a worker remains alive. */
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void *worker(void *arg) {
    char buf[4096];
    for (;;) {
        FILE *f = fopen("/proc/self/stat", "r");
        if (!f || !fgets(buf, sizeof(buf), f)) abort();
        fclose(f);
        if (strrchr(buf, ')')[2] == 'Z') break;
        sched_yield();
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strcpy(addr.sun_path, arg);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) abort();
    dprintf(fd, "%d\n", getpid());
    char request;
    if (read(fd, &request, 1) != 1) abort();
    if (write(fd, "alive\n", 6) != 6) abort();
    for (;;) pause();
}
int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path))
        abort();
    signal(SIGTERM, SIG_IGN);
    pthread_t t;
    if (pthread_create(&t, NULL, worker, argv[1])) abort();
    pthread_exit(NULL);
}

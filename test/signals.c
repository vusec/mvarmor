#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <assert.h>
#include <signal.h>

static int foo = 0;

void handle_sig(int sig)
{
    foo = 13371337;
}

int main()
{
    struct sigaction sa_new, sa_old;
    pid_t pid;
    sa_new.sa_handler = handle_sig;
    sigemptyset(&sa_new.sa_mask);
    sa_new.sa_flags = 0;
    sigaction(SIGUSR1, &sa_new, &sa_old);

    pid = getpid();
    kill(pid, SIGUSR1);
    printf("foo: %d\n", foo);
    return 0;
}

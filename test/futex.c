#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>

volatile int foo = 0;

void *thread_main(void *arg)
{
    //fprintf(stderr, "In child thread\n");
    while (foo == 0);
    sleep(1);
    //fprintf(stderr, "foo = %d\n", foo);
    syscall(SYS_futex, &foo, FUTEX_WAKE, 1);
    fprintf(stderr, "woken \n");
    return NULL;
}

int main(void)
{
    pthread_t thread;

    fprintf(stderr, "Starting...\n");
    pthread_create(&thread, NULL, thread_main, NULL);
    //fprintf(stderr, "Thread created\n");

    foo = 1;
    syscall(SYS_futex, &foo, FUTEX_WAIT, 1, NULL);
    //fprintf(stderr, "Master done\n");

    pthread_join(thread, NULL);
    fprintf(stderr, "Thread joined\n");
    return 0;
}

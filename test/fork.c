#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/syscall.h>


int main()
{
    int pipefd[2];
    pid_t pid;
    printf("prefork %ld\n", syscall(SYS_getpid));

    pipe(pipefd);

    pid = fork();

    printf("forked pid = %d\n", pid);

    if (pid == 0)
    {
        char c;
        //printf("child fds %d %d\n", pipefd[0], pipefd[1]);
        printf("child reading %d\n", getpid());
        close(pipefd[1]);
        while (read(pipefd[0], &c, 1) > 0 && c)
            printf("READ %d %c\n", c, c);
        printf("child done\n");
        close(pipefd[0]);
        printf("child done2\n");

        /*
        pid = fork();
        if (pid == 0)
            printf("child: child\n");
        else
            printf("child: parent\n");
        */
    }
    else
    {
        char *foo = "foo\n";
        //printf("parent fds %d %d\n", pipefd[0], pipefd[1]);
        printf("parent writing %d\n", getpid());
        close(pipefd[0]);
        write(pipefd[1], foo, strlen(foo) + 1);
        close(pipefd[1]);
        printf("parent waiting\n");
        wait(NULL);
        printf("parent done\n");
    }


    return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/syscall.h>


int main()
{
    int pipefd[2];
    char c;
    char foo[] = "Hoi";
    int rv;
    printf("start\n");

    rv = pipe(pipefd);
    printf("pipe: %d [%d %d]\n", rv, pipefd[0], pipefd[1]);

    write(pipefd[1], foo, strlen(foo));
    close(pipefd[1]);
    while (read(pipefd[0], &c, 1) > 0)
        printf("READ %d %c\n", c, c);

    printf("Done\n");

    return 0;
}


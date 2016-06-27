#include <stdio.h>
#include <unistd.h>

int main(void)
{
    pid_t p;

    p = getpid();
    printf("%d\n", p);

    p = fork();
    printf("%d\n", p);

    p = getpid();
    printf("%d\n", p);

    return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main()
{
    int id = syscall(SYS_getpid);
    printf("getpid: %d\n", id);
    return 42;
}

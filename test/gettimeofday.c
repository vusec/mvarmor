#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>

int main(void)
{
    struct timeval tv;
    int n;
    time_t t;

    t = time(NULL);
    n = gettimeofday(&tv, 0);
    printf("%d  %ld %ld  ..  %ld\n", n, tv.tv_sec, tv.tv_usec, t);
    return 0;
}

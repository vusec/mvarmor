#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#define NUM_CALLS 100000000

inline unsigned long long int rdtsc(void)
{
    unsigned a, d;

    __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));

    return ((unsigned long long)a) | (((unsigned long long)d) << 32);;
}

int main()
{
    printf("rdtsc: %llu\n", rdtsc());
    return 0;
}

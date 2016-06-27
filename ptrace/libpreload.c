/*
 * Overrides some functions that can normally not be intercepted with ptrace.
 * The ptrace front-end will automatically preload this library into every
 * variant process.
 */

#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/time.h>

/* Glibc likes to cache this normally. */
pid_t getpid(void)
{
    return syscall(SYS_getpid);
}

/* Below functions are normally called via vDSO. */
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    long rv = syscall(SYS_gettimeofday, tv, tz);
    if (rv)
    {
        errno = -rv;
        return -1;
    }
    return 0;
}

time_t time(time_t *t)
{
    long rv = syscall(SYS_time, t);
    if (rv < 0)
    {
        errno = -rv;
        return -1;
    }
    return rv;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    long rv = syscall(SYS_clock_gettime, clk_id, tp);
    if (rv < 0)
    {
        errno = -rv;
        return -1;
    }
    return rv;
}

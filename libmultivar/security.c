#include <sys/syscall.h>
#include <sys/mman.h>

#include "multivar_internal.h"

#ifndef SEC_POL
#define SEC_POL 2
#endif

/*
 * Safe syscalls are not checked at all i.e. any variant can do these at any
 * time without triggering any monitor code.
 */
int sec_is_safe(struct syscall_args *syscall)
{
    if (syscall->nr == SYS_brk)
        return 1;

    return 0;
}

/*
 * Unsafe syscalls run in lockstep. Normally var0 completes the system call in
 * its entirity before puhsing it to the ringbuffer and the other variants
 * compare etc the syscall. If a system call is unsafe, var0 will save the
 * arguments, push it to the ringbuffer in partial state (without return value),
 * let the other variants do the comparison of arguments, before switching to
 * var0 again to complete the syscall.
 */
int sec_is_unsafe(struct syscall_args *syscall)
{
    if (syscall->nr == SYS_clone)
        return 1;
#if SEC_POL == 0
    return 0;
#elif SEC_POL == 1
    return 1;
#elif SEC_POL == 2
    /* Prevent code exec. */
    switch (syscall->nr)
    {
    case SYS_mmap:
    case SYS_mprotect:
    case SYS_remap_file_pages: /* Does not seem to actually use prot arg? */
        if (syscall->orig_args[2] & PROT_EXEC)
            return 1;
        else
            return 0;
    case SYS_execve:
    /*case SYS_execveat:*/ /* XXX new system call, not defined yet. */
        return 1;
    default:
        return 0;
    }
#elif SEC_POL == 3
    /* Prevent information leakage. */
    switch (syscall->nr)
    {
    case SYS_write:
    case SYS_pwrite64:
    case SYS_writev:
    case SYS_sendfile:
    case SYS_sendto:
    case SYS_sendmsg:
    case SYS_msgsnd: /* Message queues, should not be issue? */
    case SYS_mq_timedsend:
    case SYS_pwritev:
    case SYS_sendmmsg:
    case SYS_process_vm_writev:
        return 1;
    default:
        return 0;
    }
#else
#error Invalid SEC_POL value
#endif
}

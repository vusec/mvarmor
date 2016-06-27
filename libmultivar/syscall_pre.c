/*
 * Performs pre-syscall state synchronization between variants. Most
 * importantly, we have to determine whether the system call should really be
 * executed, and if so, whether any of its arguments have to be modified before
 * the call.
 *
 * As specified by syscall_types.c, some syscalls are always executed by all
 * variants (ALL, e.g. mmap). Some syscalls only by the leader (ONE, e.g. all
 * I/O, unless the file is also opened by the followers previously), and finally
 * some are never executed (FAKE, e.g. getpid). Furthermore, some arguments to
 * the real kernel have to be modified, as variants have a `virtualized' view of
 * some resources such as PIDs and file descriptors.
 *
 * This code sets the actions the front-end should perform:
 *  - execute the syscall or not (MV_ACTION_FAKE)
 *  - rewrite any of the arguments (MV_ACTION_REWRITEARG)
 */

#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>

#include "multivar_internal.h"
#include "proclist.h"

/*
 * Determines if arguments need rewriting and updates the state of the process
 * so that the user can access this data.
 * Mostly this is for file descriptors and pids.
 */
static int set_rewrite(mv_thread_t thread, struct syscall *syscall)
{
    int rwargs = 0;
    switch (syscall->nr)
    {
    case SYS_read:
    case SYS_pread64:
    case SYS_write:
    case SYS_pwrite64:
    case SYS_writev:
    case SYS_close:
    case SYS_fstat:
    case SYS_ioctl:
    case SYS_fcntl:
    case SYS_getdents:
    case SYS_lseek:
    case SYS_fadvise64:
    {
        int fd = syscall->orig_args[0];
        int rfd = fd_get(thread->proc, fd);
        if (rfd != -1)
            if (fd != rfd)
            {
                rwargs = 1;
                thread_rewriteargs_clear(thread);
                thread_rewriteargs_add(thread, 0, rfd);
            }
        break;
    }
    case SYS_sendfile:
    {
        int out_fd = syscall->orig_args[0];
        int in_fd = syscall->orig_args[1];
        int out_rfd = fd_get(thread->proc, out_fd);
        int in_rfd = fd_get(thread->proc, in_fd);
        if (out_rfd != -1 && in_rfd != -1)
        {
            thread_rewriteargs_clear(thread);
            if (out_fd != out_rfd)
            {
                rwargs = 1;
                thread_rewriteargs_add(thread, 0, out_rfd);
            }
            if (in_fd != in_rfd)
            {
                rwargs = 1;
                thread_rewriteargs_add(thread, 1, in_rfd);
            }
        }
        break;
    }
    case SYS_mmap:
    {
        /* If mmap is non anonymous, it will try to mmap a file, which we *need*
         * in our fd cache thingy, otherwise it's a file opened with write
         * permissions which is bad. */
        unsigned long flags = syscall->orig_args[3];
        if (!(flags & MAP_ANONYMOUS))
        {
            int fd = syscall->orig_args[4];
            int rfd = fd_get(thread->proc, fd);
            assert(rfd != -1);

            if (fd != rfd)
            {
                rwargs = 1;
                thread_rewriteargs_clear(thread);
                thread_rewriteargs_add(thread, 4, rfd);
            }
        }
        break;
    }
    case SYS_kill:
    {
        /* Arg pid is vpid, so rewrite it to real pid. This only allows kills
         * to procs in the mv-system. */
        pid_t vpid = syscall->orig_args[0];
        pid_t pid = find_pid_by_vpid(thread->proc, vpid);
        rwargs = 1;
        thread_rewriteargs_clear(thread);
        thread_rewriteargs_add(thread, 0, pid);
        break;
    }
    case SYS_tgkill:
    {
        int vtgid = syscall->orig_args[0];
        int vtid = syscall->orig_args[1];
        int tgid = find_pid_by_vpid(thread->proc, vtgid);
        mv_thread_t victim = find_thread_in_proc_by_vtid(thread->proc, vtid);
        int tid = victim->tid;
        rwargs = 1;
        thread_rewriteargs_clear(thread);
        thread_rewriteargs_add(thread, 0, tgid);
        thread_rewriteargs_add(thread, 1, tid);
        break;
    }
    case SYS_dup:
    {
        int oldfd = syscall->orig_args[0];
        int oldrfd = fd_get(thread->proc, oldfd);
        thread_rewriteargs_clear(thread);
        if (oldrfd != -1 && oldfd != oldrfd)
        {
            rwargs = 1;
            thread_rewriteargs_add(thread, 0, oldrfd);
        }
        break;
    }
    case SYS_dup2:
    case SYS_dup3:
    {
        int oldfd = syscall->orig_args[0];
        int newfd = syscall->orig_args[1];
        int oldrfd = fd_get(thread->proc, oldfd);
        int newrfd = fd_get(thread->proc, newfd);
        thread_rewriteargs_clear(thread);
        if (oldrfd != -1 && oldfd != oldrfd)
        {
            rwargs = 1;
            thread_rewriteargs_add(thread, 0, oldrfd);
        }
        if (newrfd != -1 && newfd != newrfd)
        {
            rwargs = 1;
            thread_rewriteargs_add(thread, 1, newrfd);
        }
        break;
    }
    case SYS_get_robust_list:
    {
        pid_t vpid = syscall->orig_args[0];
        assert(vpid == 0); /* TODO */
        (void)vpid;
        break;
    }
    case SYS_futex:
    {
        assert(syscall->orig_args[1] != FUTEX_FD);
        break;
    }
    case SYS_wait4:
    case SYS_sched_getparam:
    case SYS_sched_setparam:
    case SYS_sched_getscheduler:
    {
        pid_t vpid = syscall->orig_args[0];
        pid_t pid;
        if (vpid > 0)
        {
            mv_thread_t t = find_thread_in_proc_by_vtid(thread->proc, vpid);
            pid_t pid = t->tid;
            rwargs = 1;
            thread_rewriteargs_clear(thread);
            thread_rewriteargs_add(thread, 0, pid);
        }
        break;
    }
    }

    return rwargs;
}

/*
 * Determines and sets the pre-actions this process has to take for a given
 * syscall.
 */
void syscall_pre(mv_thread_t thread, struct syscall *syscall,
        struct syscall *syscall0)
{
    int type = 0;
    int rwargs = 0;
    int is_one = 0;

    assert(thread);
    assert(syscall);
    assert(thread->proc->variant_num == 0 ? (syscall0 == NULL) :
                                            (syscall0 != NULL));

    type = syscall_type[syscall->nr];
    assert(type == FAKE || type == ONE || type == ALL);

    if (syscall->nr == SYS_clone)
        thread_increase_childcount(thread);

    if (type == ONE && !syscall_type_is_one_to_all(thread, syscall, syscall0))
        is_one = 1;

    if (!is_one)
        rwargs = set_rewrite(thread, syscall);

    thread->actions_pre = MV_ACTION_CONTINUE |
                          MV_ACTION_WAKE_VARS |
                          MV_ACTION_WAKE_THREADS;
    if (type == FAKE)
        thread->actions_pre |= MV_ACTION_FAKE;
    if (is_one && thread->proc->variant_num)
        thread->actions_pre |= MV_ACTION_FAKE;
    if (rwargs)
        thread->actions_pre |= MV_ACTION_REWRITEARG;
}

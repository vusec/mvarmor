/*
 * Specifies the type of each system call, in terms of whether followers (and
 * the leader) should execute it.
 *
 * There are three types:
 *  - ALL: syscalls that are always executed by all variants (e.g., mmap,
 *         clone).
 *  - ONE: syscalls only executed by the leader (e.g. all I/O syscalls, unless
 *         the file is also opened by the followers previously).
 *  - FAKE: syscalls that are never actually executed, by neither leader nor
 *          followers (e.g., getpid).
 *
 * In this list, all I/O syscalls are marked as ONE. However, when a followers
 * also `owns' the file descriptor (it is not a fake `virtualized' file
 * descriptor, i.e., the file is opened in read-only mode), they can be of type
 * ALL instead. The syscall_type_is_one_to_all function checks for such cases.
 *
 * Additonally, TODO syscalls are not implemented in the system and thus provide
 * an easy assert as to whether the system is capable of handling it.
 */

#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "multivar_internal.h"
#include "proclist.h"

char syscall_type[] = {
    [SYS_read]                      = ONE,
    [SYS_write]                     = ONE,
    [SYS_open]                      = ONE,
    [SYS_close]                     = ONE,
    [SYS_stat]                      = ONE,
    [SYS_fstat]                     = ONE,
    [SYS_lstat]                     = ONE,
    [SYS_poll]                      = ONE,
    [SYS_lseek]                     = ONE,
    [SYS_mmap]                      = ALL,
    [SYS_mprotect]                  = ALL,
    [SYS_munmap]                    = ALL,
    [SYS_brk]                       = ALL,
    [SYS_rt_sigaction]              = ALL,
    [SYS_rt_sigprocmask]            = ALL,
    [SYS_rt_sigreturn]              = ALL,
    [SYS_ioctl]                     = ONE,
    [SYS_pread64]                   = ONE,
    [SYS_pwrite64]                  = ONE,
    [SYS_readv]                     = TODO,
    [SYS_writev]                    = ONE,
    [SYS_access]                    = ALL,
    [SYS_pipe]                      = ALL,
    [SYS_select]                    = ONE,
    [SYS_sched_yield]               = TODO,
    [SYS_mremap]                    = TODO,
    [SYS_msync]                     = ALL,
    [SYS_mincore]                   = ALL,
    [SYS_madvise]                   = ALL,
    [SYS_shmget]                    = TODO,
    [SYS_shmat]                     = TODO,
    [SYS_shmctl]                    = TODO,
    [SYS_dup]                       = ONE,
    [SYS_dup2]                      = ONE,
    [SYS_pause]                     = TODO,
    [SYS_nanosleep]                 = ALL,
    [SYS_getitimer]                 = TODO,
    [SYS_alarm]                     = ALL,
    [SYS_setitimer]                 = TODO,
    [SYS_getpid]                    = FAKE,
    [SYS_sendfile]                  = ONE,
    [SYS_socket]                    = ONE,
    [SYS_connect]                   = ONE,
    [SYS_accept]                    = ONE,
    [SYS_sendto]                    = ONE,
    [SYS_recvfrom]                  = ONE,
    [SYS_sendmsg]                   = ONE,
    [SYS_recvmsg]                   = ONE,
    [SYS_shutdown]                  = ONE,
    [SYS_bind]                      = ONE,
    [SYS_listen]                    = ONE,
    [SYS_getsockname]               = ONE,
    [SYS_getpeername]               = TODO,
    [SYS_socketpair]                = ALL,
    [SYS_setsockopt]                = ONE,
    [SYS_getsockopt]                = ONE,
    [SYS_clone]                     = ALL,
    [SYS_fork]                      = TODO,
    [SYS_vfork]                     = TODO,
    [SYS_execve]                    = ALL,
    [SYS_exit]                      = ALL,
    [SYS_wait4]                     = ALL,
    [SYS_kill]                      = ALL,
    [SYS_uname]                     = ALL,
    [SYS_semget]                    = ALL,
    [SYS_semop]                     = ALL,
    [SYS_semctl]                    = ALL,
    [SYS_shmdt]                     = TODO,
    [SYS_msgget]                    = TODO,
    [SYS_msgsnd]                    = TODO,
    [SYS_msgrcv]                    = TODO,
    [SYS_msgctl]                    = TODO,
    [SYS_fcntl]                     = ONE,
    [SYS_flock]                     = TODO,
    [SYS_fsync]                     = TODO,
    [SYS_fdatasync]                 = ONE,
    [SYS_truncate]                  = TODO,
    [SYS_ftruncate]                 = TODO,
    [SYS_getdents]                  = ONE,
    [SYS_getcwd]                    = ALL,
    [SYS_chdir]                     = ALL,
    [SYS_fchdir]                    = TODO,
    [SYS_rename]                    = ONE,
    [SYS_mkdir]                     = ONE,
    [SYS_rmdir]                     = TODO,
    [SYS_creat]                     = TODO,
    [SYS_link]                      = TODO,
    [SYS_unlink]                    = ONE,
    [SYS_symlink]                   = TODO,
    [SYS_readlink]                  = ALL,
    [SYS_chmod]                     = ONE,
    [SYS_fchmod]                    = TODO,
    [SYS_chown]                     = ONE,
    [SYS_fchown]                    = TODO,
    [SYS_lchown]                    = TODO,
    [SYS_umask]                     = ALL,
    [SYS_gettimeofday]              = ONE,
    [SYS_getrlimit]                 = ALL,
    [SYS_getrusage]                 = TODO,
    [SYS_sysinfo]                   = TODO,
    [SYS_times]                     = TODO,
    [SYS_ptrace]                    = TODO,
    [SYS_getuid]                    = ALL, /* Could be cached for FAKE */
    [SYS_syslog]                    = TODO,
    [SYS_getgid]                    = ALL,
    [SYS_setuid]                    = ALL,
    [SYS_setgid]                    = ALL,
    [SYS_geteuid]                   = ALL,
    [SYS_getegid]                   = ALL,
    [SYS_setpgid]                   = TODO,
    [SYS_getppid]                   = FAKE,
    [SYS_getpgrp]                   = TODO,
    [SYS_setsid]                    = ALL,
    [SYS_setreuid]                  = TODO,
    [SYS_setregid]                  = TODO,
    [SYS_getgroups]                 = TODO,
    [SYS_setgroups]                 = ALL,
    [SYS_setresuid]                 = TODO,
    [SYS_getresuid]                 = TODO,
    [SYS_setresgid]                 = TODO,
    [SYS_getresgid]                 = TODO,
    [SYS_getpgid]                   = TODO,
    [SYS_setfsuid]                  = TODO,
    [SYS_setfsgid]                  = TODO,
    [SYS_getsid]                    = TODO,
    [SYS_capget]                    = ALL,
    [SYS_capset]                    = TODO,
    [SYS_rt_sigpending]             = TODO,
    [SYS_rt_sigtimedwait]           = ALL,
    [SYS_rt_sigqueueinfo]           = TODO,
    [SYS_rt_sigsuspend]             = ALL,
    [SYS_sigaltstack]               = TODO,
    [SYS_utime]                     = TODO,
    [SYS_mknod]                     = TODO,
    [SYS_uselib]                    = TODO,
    [SYS_personality]               = TODO,
    [SYS_ustat]                     = TODO,
    [SYS_statfs]                    = ALL,
    [SYS_fstatfs]                   = TODO,
    [SYS_sysfs]                     = TODO,
    [SYS_getpriority]               = TODO,
    [SYS_setpriority]               = TODO,
    [SYS_sched_setparam]            = ALL,
    [SYS_sched_getparam]            = ONE,
    [SYS_sched_setscheduler]        = TODO,
    [SYS_sched_getscheduler]        = ONE,
    [SYS_sched_get_priority_max]    = ONE,
    [SYS_sched_get_priority_min]    = ONE,
    [SYS_sched_rr_get_interval]     = TODO,
    [SYS_mlock]                     = TODO,
    [SYS_munlock]                   = TODO,
    [SYS_mlockall]                  = TODO,
    [SYS_munlockall]                = TODO,
    [SYS_vhangup]                   = TODO,
    [SYS_modify_ldt]                = TODO,
    [SYS_pivot_root]                = TODO,
    [SYS__sysctl]                   = TODO,
    [SYS_prctl]                     = ALL,
    [SYS_arch_prctl]                = ALL,
    [SYS_adjtimex]                  = TODO,
    [SYS_setrlimit]                 = ALL,
    [SYS_chroot]                    = TODO,
    [SYS_sync]                      = TODO,
    [SYS_acct]                      = TODO,
    [SYS_settimeofday]              = TODO,
    [SYS_mount]                     = TODO,
    [SYS_umount2]                   = TODO,
    [SYS_swapon]                    = TODO,
    [SYS_swapoff]                   = TODO,
    [SYS_reboot]                    = TODO,
    [SYS_sethostname]               = TODO,
    [SYS_setdomainname]             = TODO,
    [SYS_iopl]                      = TODO,
    [SYS_ioperm]                    = TODO,
    [SYS_create_module]             = TODO,
    [SYS_init_module]               = TODO,
    [SYS_delete_module]             = TODO,
    [SYS_get_kernel_syms]           = TODO,
    [SYS_query_module]              = TODO,
    [SYS_quotactl]                  = TODO,
    [SYS_nfsservctl]                = TODO,
    [SYS_getpmsg]                   = TODO,
    [SYS_putpmsg]                   = TODO,
    [SYS_afs_syscall]               = TODO,
    [SYS_tuxcall]                   = TODO,
    [SYS_security]                  = TODO,
    [SYS_gettid]                    = FAKE,
    [SYS_readahead]                 = TODO,
    [SYS_setxattr]                  = TODO,
    [SYS_lsetxattr]                 = TODO,
    [SYS_fsetxattr]                 = TODO,
    [SYS_getxattr]                  = ONE,
    [SYS_lgetxattr]                 = TODO,
    [SYS_fgetxattr]                 = TODO,
    [SYS_listxattr]                 = TODO,
    [SYS_llistxattr]                = TODO,
    [SYS_flistxattr]                = TODO,
    [SYS_removexattr]               = TODO,
    [SYS_lremovexattr]              = TODO,
    [SYS_fremovexattr]              = TODO,
    [SYS_tkill]                     = TODO,
    [SYS_time]                      = ONE,
    [SYS_futex]                     = ALL,
    [SYS_sched_setaffinity]         = TODO,
    [SYS_sched_getaffinity]         = TODO,
    [SYS_set_thread_area]           = TODO,
    [SYS_io_setup]                  = TODO,
    [SYS_io_destroy]                = TODO,
    [SYS_io_getevents]              = TODO,
    [SYS_io_submit]                 = TODO,
    [SYS_io_cancel]                 = TODO,
    [SYS_get_thread_area]           = TODO,
    [SYS_lookup_dcookie]            = TODO,
    [SYS_epoll_create]              = ONE,
    [SYS_epoll_ctl_old]             = TODO,
    [SYS_epoll_wait_old]            = TODO,
    [SYS_remap_file_pages]          = TODO,
    [SYS_getdents64]                = TODO,
    [SYS_set_tid_address]           = ALL,
    [SYS_restart_syscall]           = TODO,
    [SYS_semtimedop]                = TODO,
    [SYS_fadvise64]                 = ONE,
    [SYS_timer_create]              = TODO,
    [SYS_timer_settime]             = TODO,
    [SYS_timer_gettime]             = TODO,
    [SYS_timer_getoverrun]          = TODO,
    [SYS_timer_delete]              = TODO,
    [SYS_clock_settime]             = TODO,
    [SYS_clock_gettime]             = ONE,
    [SYS_clock_getres]              = TODO,
    [SYS_clock_nanosleep]           = TODO,
    [SYS_exit_group]                = ALL,
    [SYS_epoll_wait]                = ONE,
    [SYS_epoll_ctl]                 = ONE,
    [SYS_tgkill]                    = ALL,
    [SYS_utimes]                    = TODO,
    [SYS_vserver]                   = TODO,
    [SYS_mbind]                     = TODO,
    [SYS_set_mempolicy]             = TODO,
    [SYS_get_mempolicy]             = TODO,
    [SYS_mq_open]                   = TODO,
    [SYS_mq_unlink]                 = TODO,
    [SYS_mq_timedsend]              = TODO,
    [SYS_mq_timedreceive]           = TODO,
    [SYS_mq_notify]                 = TODO,
    [SYS_mq_getsetattr]             = TODO,
    [SYS_kexec_load]                = TODO,
    [SYS_waitid]                    = TODO,
    [SYS_add_key]                   = TODO,
    [SYS_request_key]               = TODO,
    [SYS_keyctl]                    = TODO,
    [SYS_ioprio_set]                = TODO,
    [SYS_ioprio_get]                = TODO,
    [SYS_inotify_init]              = TODO,
    [SYS_inotify_add_watch]         = TODO,
    [SYS_inotify_rm_watch]          = TODO,
    [SYS_migrate_pages]             = TODO,
    [SYS_openat]                    = ONE,
    [SYS_mkdirat]                   = TODO,
    [SYS_mknodat]                   = TODO,
    [SYS_fchownat]                  = TODO,
    [SYS_futimesat]                 = TODO,
    [SYS_newfstatat]                = TODO,
    [SYS_unlinkat]                  = TODO,
    [SYS_renameat]                  = TODO,
    [SYS_linkat]                    = TODO,
    [SYS_symlinkat]                 = TODO,
    [SYS_readlinkat]                = TODO,
    [SYS_fchmodat]                  = TODO,
    [SYS_faccessat]                 = TODO,
    [SYS_pselect6]                  = TODO,
    [SYS_ppoll]                     = TODO,
    [SYS_unshare]                   = TODO,
    [SYS_set_robust_list]           = ALL,
    [SYS_get_robust_list]           = ALL,
    [SYS_splice]                    = TODO,
    [SYS_tee]                       = TODO,
    [SYS_sync_file_range]           = TODO,
    [SYS_vmsplice]                  = TODO,
    [SYS_move_pages]                = TODO,
    [SYS_utimensat]                 = TODO,
    [SYS_epoll_pwait]               = TODO,
    [SYS_signalfd]                  = TODO,
    [SYS_timerfd_create]            = TODO,
    [SYS_eventfd]                   = TODO,
    [SYS_fallocate]                 = TODO,
    [SYS_timerfd_settime]           = TODO,
    [SYS_timerfd_gettime]           = TODO,
    [SYS_accept4]                   = ONE,
    [SYS_eventfd2]                  = ONE,
    [SYS_signalfd4]                 = TODO,
    [SYS_epoll_create1]             = ONE,
    [SYS_dup3]                      = ONE,
    [SYS_pipe2]                     = ALL,
    [SYS_inotify_init1]             = TODO,
    [SYS_preadv]                    = TODO,
    [SYS_pwritev]                   = TODO,
    [SYS_rt_tgsigqueueinfo]         = TODO,
    [SYS_perf_event_open]           = TODO,
    [SYS_recvmmsg]                  = TODO,
    [SYS_fanotify_init]             = TODO,
    [SYS_fanotify_mark]             = TODO,
    [SYS_prlimit64]                 = TODO,
    [SYS_name_to_handle_at]         = TODO,
    [SYS_open_by_handle_at]         = TODO,
    [SYS_clock_adjtime]             = TODO,
    [SYS_syncfs]                    = TODO,
    [SYS_sendmmsg]                  = TODO,
    [SYS_setns]                     = TODO,
    [SYS_getcpu]                    = TODO,
    [SYS_process_vm_readv]          = TODO,
    [SYS_process_vm_writev]         = TODO,
    [SYS_kcmp]                      = TODO,
    [SYS_finit_module]              = TODO,
    [SYSCALL_RDTSC]                 = ONE,
};

/*
 * All syscall dealing with file descriptors are marked as ONE, but if all the
 * procs have the fd they can to it themselves, sparing var0 a copy of the
 * resulting data. System calls creating fds can also undergo this transition if
 * they open a file read-only or they duplicate a already shared fd.
 */
int syscall_type_is_one_to_all(mv_thread_t thread, struct syscall *syscall,
        struct syscall *syscall0)
{
    assert(syscall_type[syscall->nr] == ONE);

    /* On error, we always let just var0 do it. */
    if (syscall0 && syscall->rb_has_result && syscall0->rv < 0)
        return 0;

    switch (syscall->nr)
    {
#if VARN_OPEN_RO
    case SYS_open:
    {
        int flags = syscall->orig_args[1];
        const char *fn = (const char *)syscall->arg_data[0];
        if ((flags & O_WRONLY) == O_WRONLY || (flags & O_RDWR) == O_RDWR)
            return 0;
        if (!strcmp(fn, "/dev/random") || !strcmp(fn, "/dev/urandom"))
            return 0;
        return 1;
        break;
    }
    case SYS_openat:
    {
        int flags = syscall->orig_args[2];
        if (!((flags & O_WRONLY) || (flags & O_RDWR)))
            return 1;
        break;
    }
#endif
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
    case SYS_shutdown:
    case SYS_dup:
    case SYS_fdatasync:
    {
        int fd = syscall->orig_args[0];
        int rfd = fd_get(thread->proc, fd);
        if (rfd != -1)
            return 1;
        break;
    }
    case SYS_sendfile:
    {
        int out_fd = syscall->orig_args[0];
        int in_fd = syscall->orig_args[1];
        int out_rfd = fd_get(thread->proc, out_fd);
        int in_rfd = fd_get(thread->proc, in_fd);
        if (out_rfd != -1 && in_rfd != -1)
            return 1;
        break;
    }
    case SYS_dup2:
    case SYS_dup3:
    {
        int oldfd = syscall->orig_args[0];
        int newfd = syscall->orig_args[1];
        int oldrfd = fd_get(thread->proc, oldfd);
        int newrfd = fd_get(thread->proc, newfd);
        if (oldrfd == -1 && newrfd == -1)
            return 0;
        else if (oldrfd == -1 && newrfd != -1)
            assert(!"TODO: !oldfd newfd");
        else if (oldrfd != -1 && newrfd == -1)
        {
            if (newfd == 0 || newfd == 1 || newfd == 2)
                return 1;
            else
                assert(!"TODO: oldfd !newfd !012");
        }
        else if (oldrfd != -1 && newrfd != -1)
            return 1;

        break;
    }
    case SYS_poll:
    {
        int i;
        struct pollfd *fds = (void *)syscall->arg_data[0];
        int nfds = syscall->orig_args[1];
        for (i = 0; i < nfds; i++)
            if (fd_get(thread->proc, fds[i].fd) != -1)
                assert(!"TODO: poll with var-local fd");
    }
    }

    return 0;
}

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/capability.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/sem.h>
#include <linux/futex.h>
#include <signal.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>

#include "multivar_internal.h"
#include "ringbuffer.h"
#include "ksigaction.h"

void resize_data_area(struct syscall *syscall, size_t size,
        alloc_mem_func_t alloc_mem, realloc_mem_func_t realloc_mem)
{
    /* Cache allocations since they are expensive. */
    if (syscall->data_area == NULL)
    {
        syscall->data_area = alloc_mem(size);
        syscall->data_size = size;
    }
    else if (syscall->data_size < size)
    {
        syscall->data_area = realloc_mem(syscall->data_area,
                size, syscall->data_size);
        syscall->data_size = size;
    }
}

/*
 * Memcpy implementation, for use in local address space.
 */
void local_memcpy(void *dest, void *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        ((unsigned char*)dest)[i] = ((unsigned char*)src)[i];
}

/*
 * Copies a string from userspace (src) into the local address space (dest), up
 * to n characters including the terminating null-byte. dest should thus point
 * to a buffer at least n bytes large. If the (n) copied bytes to not contain a
 * null-byte, -1 is returned (but the dest buffer will be modified). The return
 * value is the length of the copied string, *excluding* the terminating
 * null-byte.
 */
long strncpy_from_user(pid_t pid, const char *dest, const char *src,
        size_t n)
{
    size_t i;
    if (n == 0)
        return -1;
    /* Copy entire chunk from user and then scan for \0 */
    copy_from_user(pid, (void *)dest, (void *)src, n);
    for (i = 0; i < n && dest[i]; i++);
    if (i == n && dest[n - 1] != '\0')
        return -1;
    return i;
}

long strncpy_from_user_slow(pid_t pid, const char *dest, const char *src,
        size_t n)
{
    size_t i;
    if (n == 0)
        return -1;
    /* Copy entire chunk from user and then scan for \0 */
    for (i = 0; i < n; i++)
    {
        copy_from_user(pid, (void*)&dest[i], (void*)&src[i], 1);
        if (dest[i] == '\0')
            return i;
    }
    return -1;
}

/*
 * Copies an entire execve-style array into this address space. Arrays like this
 * consists of a array of consecutive points, terminated by a nullpointer. Every
 * pointer in this array points to an actual item in the array, a
 * (null-terminated) string. The result (the array of pointers for the current
 * address space) is copied into return_dest.
 *
 * So we will: copy the pointer-array into our mem, containing pointers for the
 * child address space. We then allocate two areas of memory: one for our local
 * pointer-array and one for the string-data. While all of this data is usually
 * consecutive, it's possible it isn't so we try to keep that in mind.
 */
char **copy_execve_array(pid_t pid, char **user_array,
        alloc_mem_func_t alloc_mem, realloc_mem_func_t realloc_mem)
{
    /* The env is most likely larger than this, but we can realloc. */
    size_t local_strings_max = 1024, local_strings_used = 0;
    char *local_strings = alloc_mem(local_strings_max * sizeof(char));
    /* 1024 pointers should be more than enough - my rather bloated environment
     * is around 50-60 entries. */
    char **local_ptrs = alloc_mem(1024 * sizeof(char *));
    /* Keep track of the lens of all strings copied, so we can reconstruct the
     * pointer-array later. We cannot do this on-the-fly as realloc might change
     * the pointers halfway through. */
    long lens[1024];
    char *user_ptrs[1024];
    char *t;
    size_t i;
    long copied;

    copy_from_user(pid, user_ptrs, user_array, 1024 * sizeof(char *));
    for (i = 0; i < 1024; i++)
    {
        copy_from_user(pid, &user_ptrs[i], &user_array[i], sizeof(char *));
        if (user_ptrs[i] == NULL)
        {
            local_ptrs[i] = NULL;
            break;
        }
        do
        {
            copied = strncpy_from_user_slow(pid,
                    &local_strings[local_strings_used], user_ptrs[i],
                    local_strings_max - local_strings_used);
            if (copied == -1)
            {
                local_strings_max *= 2;
                local_strings = realloc_mem(local_strings, local_strings_max,
                        local_strings_max / 2);
            }
        } while (copied == -1);
        local_strings_used += copied + 1;
        assert(local_strings_used <= local_strings_max);
        lens[i] = copied + 1;
    }

    if (i == 1024)
        assert(!"more than 1024 entries in execve-style array!");

    lens[i] = -1;
    t = local_strings;
    for (i = 0; lens[i] != -1; i++)
    {
        local_ptrs[i] = t;
        t += lens[i];
    }

    return local_ptrs;
}

/* NOTE: when using copy_iovec, don't set any sizes in save_args since it will
 * overwrite the iovec data copied here. */
struct iovec *copy_write_iovec(pid_t pid, struct syscall *syscall,
        struct iovec *user_iov, int iovcnt, alloc_mem_func_t alloc_mem,
        realloc_mem_func_t realloc_mem)
{
    struct iovec *iov;
    struct iovec *tmp;
    size_t total_len = 0;
    int i;

    resize_data_area(syscall, iovcnt * sizeof(struct iovec), alloc_mem,
            realloc_mem);
    iov = syscall->data_area;

    copy_from_user(pid, iov, user_iov, sizeof(struct iovec) * iovcnt);
    for (i = 0; i < iovcnt; i++)
        total_len += iov[i].iov_len;
    resize_data_area(syscall, sizeof(struct iovec) * iovcnt + total_len,
            alloc_mem, realloc_mem);
    iov = syscall->data_area;
    tmp = iov + iovcnt;
    for (i = 0; i < iovcnt; i++)
    {
        copy_from_user(pid, tmp, iov[i].iov_base, iov[i].iov_len);
        iov[i].iov_base = tmp;
        tmp = (struct iovec *)((char *)tmp + iov[i].iov_len);
    }

    return iov;
}

struct iovec *copy_read_iovec(pid_t pid, struct syscall *syscall,
        struct iovec *user_iov, int iovcnt, alloc_mem_func_t alloc_mem,
        realloc_mem_func_t realloc_mem)
{
    struct iovec *iov;

    resize_data_area(syscall, iovcnt * sizeof(struct iovec), alloc_mem,
            realloc_mem);
    iov = syscall->data_area;
    copy_from_user(pid, iov, user_iov, sizeof(struct iovec) * iovcnt);

    return iov;
}


struct iovec *copy_msghdr(pid_t pid, struct syscall *syscall,
        struct iovec *user_iov, int iovcnt, alloc_mem_func_t alloc_mem,
        realloc_mem_func_t realloc_mem)
{
    struct iovec *iov;

    resize_data_area(syscall, sizeof(struct msghdr) + sizeof(struct iovec),
            alloc_mem, realloc_mem);
    copy_from_user(pid, syscall->data_area, user_iov, sizeof(struct iovec) * iovcnt);

    resize_data_area(syscall, iovcnt * sizeof(struct iovec), alloc_mem,
            realloc_mem);
    iov = syscall->data_area;
    copy_from_user(pid, iov, user_iov, sizeof(struct iovec) * iovcnt);

    return iov;
}


#define STRARG_N(arg, post) \
    do { \
        n ## post = strncpy_from_user(pid, buf ## post, \
                (const char *)syscall->orig_args[arg], 256); \
        if (n ## post >= 0) \
        { \
            sizes[arg] = (n ## post) + 1; \
            src[arg] = buf ## post; \
            from_userspace[arg] = 0; \
        } \
        else \
            assert(!"string " #arg " > 1024 chars!!"); \
    } while (0)
#define STRARG(arg) STRARG_N(arg, 1)
#define STRARG2(arg) STRARG_N(arg, 2)

/*
 * Copies all arguments of the system call into the current addr space.
 */
void save_args(pid_t pid, struct syscall_args *syscall,
        struct syscall *syscall_save, alloc_mem_func_t alloc_mem,
        realloc_mem_func_t realloc_mem)
{
    char from_userspace[6] = { 1, 1, 1, 1, 1, 1 };
    size_t sizes[6] = { 0, 0, 0, 0, 0, 0 };
    void *raw_addr[6] = { NULL, NULL, NULL, NULL, NULL, NULL };
    uint64_t *args = syscall->orig_args;
    void *src[6] = { (void*)args[0], (void*)args[1], (void*)args[2],
                     (void*)args[3], (void*)args[4], (void*)args[5] };
    size_t total_size = 0;
    void *data_cur;
    size_t i;
    long n1, n2;
    char buf1[256], buf2[256];

    switch (syscall->nr)
    {
    case SYS_read:
        break;
    case SYS_write:
        sizes[1] = args[2];
        break;
    case SYS_open:
        STRARG(0);
        break;
    case SYS_close:
        break;
    case SYS_stat:
    case SYS_lstat:
        STRARG(0);
        break;
    case SYS_fstat:
        break;
    case SYS_poll:
        sizes[0] = args[1] * sizeof(struct pollfd);
        break;
    case SYS_lseek:
    case SYS_mmap:
    case SYS_mprotect:
    case SYS_munmap:
    case SYS_brk:
        break;
    case SYS_rt_sigaction:
        sizes[1] = sizeof(struct ksigaction);
        break;
    case SYS_rt_sigprocmask:
        sizes[1] = args[3];
        break;
    case SYS_rt_sigreturn:
    case SYS_ioctl:
        switch (args[1])
        {
            /* XXX not complete */
            case FIONBIO:
                sizes[2] = sizeof(int);
        }
        break;
    case SYS_pread64:
        break;
    case SYS_pwrite64:
        sizes[1] = args[2];
        break;
    /*
    case SYS_readv:
    */
    case SYS_writev:
        /* NOTE: when using copy_iovec, don't set any sizes since it will
         * overwrite the iovec data copied here. */
        raw_addr[1] = copy_write_iovec(pid, syscall_save,
                (struct iovec *)args[1], args[2],
                alloc_mem, realloc_mem);
        break;
    case SYS_access:
        STRARG(0);
        break;
    case SYS_pipe:
        break;
    case SYS_select:
        sizes[1] = sizeof(fd_set);
        sizes[2] = sizeof(fd_set);
        sizes[3] = sizeof(fd_set);
        sizes[4] = sizeof(struct timeval);
        break;
    /*
    case SYS_sched_yield:
    case SYS_mremap:
    */
    case SYS_msync:
    case SYS_mincore:
    case SYS_madvise:
        break;
    /*
    case SYS_shmget:
    case SYS_shmat:
    case SYS_shmctl:
    */
    case SYS_dup:
    case SYS_dup2:
        break;
    /*
    case SYS_pause:
    */
    case SYS_nanosleep:
        sizes[0] = sizeof(struct timespec);
        break;
    /*
    case SYS_getitimer:
    */
    case SYS_alarm:
        break;
    /*
    case SYS_setitimer:
    */
    case SYS_getpid:
        break;
    case SYS_sendfile:
        sizes[2] = sizeof(off_t);
        break;
    case SYS_socket:
        break;
    case SYS_connect:
        sizes[1] = (socklen_t)args[2];
        break;
    case SYS_accept:
        sizes[2] = sizeof(socklen_t);
        break;
    case SYS_sendto:
        sizes[1] = args[2];
        sizes[4] = args[5];
        break;
    case SYS_recvfrom:
        sizes[5] = sizeof(socklen_t);
        break;
    case SYS_sendmsg:
    {
        /* We need a deep copy of a bunch of data including an iovec thing, so
         * we manually copy all data here. First we copy the header so we know
         * all the sizes etc, then the remaining parts. Finally all iovec data.
         * Luckily we don't need the original struct anymore, so we can fill the
         * one we copy with local pointers.
         * Don't forgot, resize_data_area invalidates all pointers!
         */
        struct msghdr *hdr;
        void *name, *control;
        struct iovec *iov;
        char *iov_data;
        size_t iov_data_len = 0;

        resize_data_area(syscall_save, sizeof(struct msghdr), alloc_mem,
                realloc_mem);
        copy_from_user(pid, syscall_save->data_area,
                (void *)args[1], sizeof(struct msghdr));
        hdr = syscall_save->data_area;

        resize_data_area(syscall_save, sizeof(struct msghdr) +
                hdr->msg_namelen + hdr->msg_controllen + hdr->msg_iovlen *
                sizeof(struct iovec), alloc_mem, realloc_mem);
        hdr = syscall_save->data_area;
        iov = (void *)((char *)hdr + sizeof(struct msghdr) + hdr->msg_namelen +
            hdr->msg_controllen);
        copy_from_user(pid, iov, hdr->msg_iov, hdr->msg_iovlen *
                sizeof(struct iovec));

        for (i = 0; i < hdr->msg_iovlen; i++)
            iov_data_len += iov[i].iov_len;
        resize_data_area(syscall_save, sizeof(struct msghdr) +
                hdr->msg_namelen + hdr->msg_controllen + hdr->msg_iovlen *
                sizeof(struct iovec) + iov_data_len, alloc_mem, realloc_mem);
        hdr = syscall_save->data_area;
        name = hdr + 1;
        control = (char *)name + hdr->msg_namelen;
        iov = (void *)((char *)control + hdr->msg_controllen);
        iov_data = (char *)iov + hdr->msg_iovlen * sizeof(struct iovec);

        if (hdr->msg_name)
            copy_from_user(pid, name, hdr->msg_name, hdr->msg_namelen);
        if (hdr->msg_control)
            copy_from_user(pid, control, hdr->msg_control,
                    hdr->msg_controllen);
        for (i = 0; i < hdr->msg_iovlen; i++)
        {
            copy_from_user(pid, iov_data, iov[i].iov_base,
                    iov[i].iov_len);
            iov[i].iov_base = iov_data;
            iov_data += iov[i].iov_len;
        }

        hdr->msg_name = name;
        hdr->msg_control = control;
        hdr->msg_iov = iov;
        raw_addr[1] = hdr;

        break;
    }
    case SYS_recvmsg:
    {
        /* We need to do a deep copy here, so we avoid using the normal copy
         * system. We need both a deep copy, but also the original pointers, so
         * we save pointers to the nested data in other arg_data entries which
         * should be unused. */

        struct msghdr *hdr;

        /* Copy msghdr itself */
        resize_data_area(syscall_save, sizeof(struct msghdr), alloc_mem,
                realloc_mem);
        copy_from_user(pid, syscall_save->data_area,
                (void *)args[1], sizeof(struct msghdr));
        hdr = syscall_save->data_area;

        /* Copy iov entries. */
        resize_data_area(syscall_save,
                sizeof(struct msghdr) + hdr->msg_iovlen * sizeof(struct iovec),
                alloc_mem, realloc_mem);
        hdr = raw_addr[1] = syscall_save->data_area;
        raw_addr[2] = (char *)syscall_save->data_area + sizeof(struct msghdr);
        copy_from_user(pid, raw_addr[2], hdr->msg_iov,
                sizeof(struct iovec) * hdr->msg_iovlen);
        break;
    }
    case SYS_shutdown:
        break;
    case SYS_bind:
        sizes[1] = (socklen_t)args[2];
        break;
    case SYS_listen:
        break;
    case SYS_getsockname:
        sizes[2] = sizeof(socklen_t);
        break;
    /*
    case SYS_getpeername:
    */
    case SYS_socketpair:
        break;
    case SYS_setsockopt:
        sizes[3] = (socklen_t)args[4];
        break;
    case SYS_getsockopt:
        sizes[4] = sizeof(socklen_t);
        break;
    case SYS_clone:
        break;
    /*
    case SYS_fork:
    case SYS_vfork:
    */
    case SYS_execve:
    {
        STRARG(0);
        raw_addr[1] = copy_execve_array(pid, (char **)args[1],
                alloc_mem, realloc_mem);
        raw_addr[2] = copy_execve_array(pid, (char **)args[2],
                alloc_mem, realloc_mem);
        break;
    }
    case SYS_exit:
    case SYS_wait4:
    case SYS_kill:
    case SYS_uname:
    case SYS_semget:
        break;
    case SYS_semop:
        sizes[1] = sizeof(struct sembuf) * args[2];
        break;
    case SYS_semctl:
        /* TODO */
        break;
    /*
    case SYS_shmdt:
    case SYS_msgget:
    case SYS_msgsnd:
    case SYS_msgrcv:
    case SYS_msgctl:
    */
    case SYS_fcntl:
        break;
    /*
    case SYS_flock:
    case SYS_fsync:
    */
    case SYS_fdatasync:
        break;
    /*
    case SYS_truncate:
    case SYS_ftruncate:
    */
    case SYS_getdents:
    case SYS_getcwd:
        break;
    case SYS_chdir:
        STRARG(0);
        break;
    case SYS_rename:
        STRARG(0);
        STRARG2(1);
        break;
    case SYS_mkdir:
    case SYS_unlink:
    case SYS_readlink:
    case SYS_chmod:
        STRARG(0);
        break;
    case SYS_umask:
    case SYS_gettimeofday:
    case SYS_getrlimit:
    case SYS_getuid:
    case SYS_getgid:
    case SYS_geteuid:
    case SYS_getegid:
    case SYS_getppid:
    case SYS_setsid:
        break;
    case SYS_capget:
        sizes[0] = sizeof(struct __user_cap_header_struct);
        break;
    case SYS_rt_sigtimedwait:
        /* TODO */
        break;
    case SYS_rt_sigsuspend:
        sizes[0] = sizeof(sigset_t);
        break;
    case SYS_statfs:
        STRARG(0);
        break;
    case SYS_sched_getparam:
        break;
    case SYS_sched_setparam:
        sizes[1] = sizeof(struct sched_param);
        break;
    case SYS_sched_getscheduler:
    case SYS_sched_get_priority_min:
    case SYS_sched_get_priority_max:
    case SYS_prctl:
    case SYS_arch_prctl:
        break;
    case SYS_setrlimit:
        sizes[1] = sizeof(struct rlimit);
        break;
    case SYS_gettid:
        break;
    case SYS_getxattr:
        STRARG(0);
        STRARG2(1);
        break;
    case SYS_time:
        break;
    case SYS_futex:
        if (syscall->orig_args[1] == FUTEX_WAIT)
            sizes[3] = sizeof(struct timespec);
        break;
    case SYS_epoll_create:
    case SYS_set_tid_address:
    case SYS_fadvise64:
    case SYS_clock_gettime:
    case SYS_exit_group:
        break;
    case SYS_epoll_wait:
        break;
    case SYS_epoll_ctl:
        sizes[3] = sizeof(struct epoll_event);
        break;
    case SYS_tgkill:
        break;
    case SYS_openat:
        STRARG(1);
        break;
    case SYS_set_robust_list:
        sizes[0] = (size_t)args[1];
        break;
    case SYS_get_robust_list:
        break;
    case SYS_accept4:
        sizes[2] = sizeof(socklen_t);
        break;
    case SYS_eventfd2:
    case SYS_epoll_create1:
    case SYS_dup3:
    case SYS_pipe2:
    case SYSCALL_RDTSC:
        break;
    default:
        print("Syscall not implemented in save_args: %d\n", syscall->nr);
        assert(!"syscall not implemented (save_args)");
    }

    syscall_save->nr = syscall->nr;
    for (i = 0; i < 6; i++)
    {
        total_size += sizes[i];
        syscall_save->orig_args[i] = args[i];
        syscall_save->arg_data[i] = NULL;
        if (raw_addr[i])
            syscall_save->arg_data[i] = raw_addr[i];
    }

    if (total_size)
    {
        resize_data_area(syscall_save, total_size, alloc_mem, realloc_mem);
        data_cur = syscall_save->data_area;
        for (i = 0; i < 6; i++)
        {
            if (sizes[i] && src[i])
            {
                if (from_userspace[i])
                    copy_from_user(pid, data_cur, src[i], sizes[i]);
                else
                    local_memcpy(data_cur, src[i], sizes[i]);
                syscall_save->arg_data[i] = data_cur;
                data_cur = (char *)data_cur + sizes[i];
            }
        }
    }
}

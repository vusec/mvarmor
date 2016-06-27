/*
 * Performs post-syscall state syncrhonization between variants. This includes
 * modifying the return value (e.g., the PID) and copying return values of the
 * system call placed in structs to other variants, if they themselves did not
 * execute it.
 *
 * For the leader, it copies all relevant state (return value, populated
 * structs/buffers) into the ringbuffer entry. Then, when the followers reach
 * the point where they (should have) executed the system call, these values are
 * copied from the shared ringbuffer to the follower. Every follower (or rather,
 * its monitor) does this for itself.
 *
 * For ONE-type system calls (as specified by syscall_types.c) return value and
 * `return-value buffers' are copied to variants, unless it is converted into an
 * ALL-type system call (which can happen when it does I/O on file descriptors
 * available to all variants). These `return-value buffers' are user-space
 * memory of which pointers are passed as arguments to syscalls, so the kernel
 * can populate it to return larger values (e.g., the buffer passed to read).
 *
 * This copying happens via a `ret area' buffer. This is a chunk of memory
 * visible to all variant monitors, and is assiociated to a ringbuffer entry.
 * There is only a single `ret area' buffer, even when multiple buffers are
 * passed to the kernel for return values, in order to reduce the amount of
 * allocations (similarly to how save_args handles the copying of buffers for
 * comparison). The arg_data array of pointers is abused to point into this `ret
 * area' chunk of memory. There is a slight exception for value-result arguments
 * (where the buffer contains some initial value that influences the execution
 * of the system call, and is then overwritten for the return value). The
 * assiociated arg_data pointer points into the originally passed value buffer,
 * and we use another (unused) arg_data entry to point into the `ret area'
 * buffer. All of this bookkeeping is taken care of by the copyresults_sizes
 * function.
 */

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stddef.h>
#include <poll.h>
#include <termios.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/sched.h>
#include <linux/futex.h>
#include <stdio.h>

#include "multivar_internal.h"
#include "proclist.h"
#include "ringbuffer.h"


/* This doesn't match user-space version exposed by termios.h */
#define __KERNEL_NCCS 19
struct __kernel_termios
  {
    tcflag_t c_iflag;       /* input mode flags */
    tcflag_t c_oflag;       /* output mode flags */
    tcflag_t c_cflag;       /* control mode flags */
    tcflag_t c_lflag;       /* local mode flags */
    cc_t c_line;        /* line discipline */
    cc_t c_cc[__KERNEL_NCCS];   /* control characters */
  };

/*
 * Every ringbuffer entry has an assiociated `ret area', a chunk of allocated
 * memory visible to all variant monitors. Here, the leader stores the contents
 * of any `return-value buffers', i.e., buffers passed to the kernel, that are
 * populated by the kernel on succesfull execution of a system call.
 *
 * As allocating and resizing is expensive (as it can operate on shared memory),
 * these are persisted even when the ringbuffer entry is not needed anymore.
 * This function can be called with a certain size, and afterwards the code can
 * be sure a buffer both exists, and is large enough to contain size. It might
 * be larger, as it basically caches this from previous uses of the ringbuffer
 * entry.
 */
static void resize_ret_area(struct syscall *syscall, size_t size)
{
    if (syscall->ret_area == NULL)
    {
        syscall->ret_area = alloc_mem(size);
        syscall->ret_size = size;
    }
    else if (syscall->ret_size < size)
    {
        syscall->ret_area = realloc_mem(syscall->ret_area, size,
                syscall->ret_size);
        syscall->ret_size = size;
    }
}

/*
 * Sets the correct fake return value for syscalls. This includes all FAKE
 * system calls, and some exceptions (e.g., clone which returns a PID).
 */
static void set_fake_rv(mv_thread_t thread, struct syscall *syscall,
        struct syscall *syscall0)
{
    if (syscall_type[syscall->nr] == FAKE)
    {
        thread->actions_post |= MV_ACTION_FAKE;

        switch (syscall->nr)
        {
        case SYS_getpid:
            syscall->fake_rv = thread->proc->vpid;
            break;
        case SYS_getppid:
            syscall->fake_rv = thread->proc->vppid;
            break;
        case SYS_gettid:
            syscall->fake_rv = thread->vtid;
            break;
        default:
            assert(!"FAKE but no retval case");
        }
    }

    /* Some exceptions where all variants execute the syscall (i.e., type !=
     * FAKE) but we still have to patch the return value. */
    switch (syscall->nr)
    {
    case SYS_clone:
    {
        /* Fixes the returnvalue of fork() etc in the parent. */
        pid_t vtid = vtid_generate(thread);
        syscall->fake_rv = vtid;
        thread->actions_post |= MV_ACTION_FAKE;

        /* NOTE: front-end should handle CLONE_CHILD_SETTID and PARENT_SETTID
         * for the child. */
        if (syscall->orig_args[0] & CLONE_PARENT_SETTID)
        {
            void *ptid = (void*)syscall->orig_args[2];
            copy_to_user(thread->proc->pid, ptid, &thread->vtid,
                    sizeof(pid_t));
        }
        break;
    }
    case SYS_set_tid_address:
    {
        pid_t vtid = mv_thread_getvtid(thread);
        syscall->fake_rv = vtid;
        thread->actions_post |= MV_ACTION_FAKE;
        break;
    }
    case SYS_setsid:
    {
        /* While we still need all variants to do this, they should all have
         * the same return value (session id). */
        if (thread->proc->variant_num > 0)
        {
            syscall->fake_rv = syscall0->rv;
            thread->actions_post |= MV_ACTION_FAKE;
        }
        break;
    }
    }
}


/*
 * Given a system call and an array of six 0-values, it will write the correct
 * size of every argument that was a return value of the system call.
 * The store argument is somewhat of a hack and is used for value-result
 * arguments, where we don't want to overwrite the data passed in: if the nth
 * element is set to m (m != 0), it means the nth argument is a value-result
 * argument *and* that the pointer of the return-value should be stored in the
 * mth entry (thus not overwriting the call-data passed in the nth argument.
 */
static void copyresults_sizes(struct syscall *syscall, size_t sizes[6],
        unsigned store[6])
{
    switch (syscall->nr)
    {
    case SYS_read:
    case SYS_pread64:
        if ((long)syscall->rv > 0)
            sizes[1] = syscall->rv;
        break;
    case SYS_stat:
    case SYS_fstat:
    case SYS_lstat:
        sizes[1] = sizeof(struct stat);
        break;
    case SYS_poll:
        sizes[0] = sizeof(struct pollfd) * (int)syscall->orig_args[1];
        store[0] = 1;
        break;
    case SYS_pipe:
    case SYS_pipe2:
        sizes[0] = sizeof(int) * 2;
        break;
    case SYS_socketpair:
        sizes[3] = sizeof(int) * 2;
        break;
    case SYS_select:
        if (syscall->orig_args[1])
            sizes[1] = sizeof(fd_set);
        if (syscall->orig_args[2])
            sizes[2] = sizeof(fd_set);
        if (syscall->orig_args[3])
            sizes[3] = sizeof(fd_set);
        break;
    case SYS_accept:
    case SYS_accept4:
    case SYS_getsockname:
        sizes[1] = *(socklen_t *)syscall->arg_data[2];
        sizes[2] = sizeof(socklen_t);
        store[2] = 3;
        break;
    case SYS_getsockopt:
        sizes[3] = *(socklen_t *)syscall->arg_data[4];
        sizes[4] = sizeof(socklen_t);
        store[4] = 5;
        break;
    case SYS_recvfrom:
        sizes[1] = syscall->orig_args[2];
        if (syscall->orig_args[4])
        {
            sizes[4] = *(socklen_t *)syscall->arg_data[5];
            sizes[5] = sizeof(socklen_t);
            store[5] = 3;
        }
        break;
    case SYS_sendfile:
        if (syscall->orig_args[2])
        {
            sizes[2] = sizeof(off_t);
            store[2] = 3;
        }
        break;
    case SYS_getdents:
        sizes[1] = syscall->orig_args[2];
        break;
    case SYS_ioctl:
        /* XXX not complete */
        switch (syscall->orig_args[1])
        {
            case FIONREAD:
                sizes[2] = sizeof(int);
                break;
            case TIOCGWINSZ:
                sizes[2] = sizeof(struct winsize);
                break;
            case TCGETS:
                sizes[2] = sizeof(struct __kernel_termios);
                break;
        }
        break;
    case SYS_getxattr:
        sizes[2] = syscall->orig_args[3];
        break;
    case SYS_gettimeofday:
        if (syscall->orig_args[0])
            sizes[0] = sizeof(struct timeval);
        if (syscall->orig_args[1])
            sizes[1] = sizeof(struct timezone);
        break;
    case SYS_time:
        if (syscall->orig_args[0])
            sizes[0] = sizeof(time_t);
        break;
    case SYS_clock_gettime:
        if (syscall->orig_args[1])
            sizes[1] = sizeof(struct timespec);
        break;
    case SYS_sched_getparam:
        sizes[1] = sizeof(struct sched_param);
        break;
    case SYS_sched_getscheduler:
        sizes[2] = sizeof(struct sched_param);
        break;
    }
}

/*
 * When a system call influenced the variant's file descriptors, we need to
 * update our administration.
 */
static void update_fd_mappings(mv_thread_t thread, struct syscall *syscall,
        struct syscall *syscall0)
{
    switch (syscall->nr)
    {
    case SYS_open:
    case SYS_openat:
        if (syscall_type_is_one_to_all(thread, syscall, syscall0))
        {
            fd_add(thread->proc, syscall->rv, syscall0->rv);
            if (thread->proc->variant_num > 0 && syscall->rv != syscall0->rv)
            {
                syscall->fake_rv = syscall0->rv;
                thread->actions_post |= MV_ACTION_FAKE;
            }
        }
        break;
    case SYS_dup:
        if (syscall_type_is_one_to_all(thread, syscall, syscall0))
            fd_add(thread->proc, syscall->rv, syscall0->rv);
        break;
    case SYS_dup2:
    case SYS_dup3:
        if (syscall_type_is_one_to_all(thread, syscall, syscall0))
            fd_add(thread->proc, syscall->orig_args[1], syscall0->orig_args[1]);
        break;
    case SYS_pipe:
    case SYS_pipe2:
    case SYS_socketpair:
    {
        int *filedes_user, *filedes_fake;
        int filedes[2];
        int arg_idx = syscall->nr == SYS_socketpair ? 3 : 0;
        filedes_user = (int *)syscall->orig_args[arg_idx];
        copy_from_user(thread->proc->pid, filedes, filedes_user,
                sizeof(int) * 2);

        if (thread->proc->variant_num == 0)
            filedes_fake = filedes;
        else
            filedes_fake = (int *)syscall0->arg_data[arg_idx];

        fd_add(thread->proc, filedes[0], filedes_fake[0]);
        fd_add(thread->proc, filedes[1], filedes_fake[1]);
        break;
    }
    case SYS_close:
    {
        int fd = syscall->orig_args[0];
        int rfd = fd_get(thread->proc, fd);
        epoll_data_close_fd(thread->proc, fd);
        if (rfd != -1) /* -> ALL */
            fd_rm(thread->proc, fd);
        break;
    }
    case SYS_epoll_ctl:
    {
        int epfd = syscall->orig_args[0];
        int op = syscall->orig_args[1];
        int fd = syscall->orig_args[2];
        struct epoll_event *event =
            (struct epoll_event *)syscall->arg_data[3];
        assert(op == EPOLL_CTL_ADD || op == EPOLL_CTL_DEL ||
            op == EPOLL_CTL_MOD);
        if (op == EPOLL_CTL_ADD)
            epoll_data_add(thread->proc, epfd, fd, event->data.u64);
        else if (op == EPOLL_CTL_MOD)
            epoll_data_mod(thread->proc, epfd, fd, event->data.u64);
        else if (op == EPOLL_CTL_DEL)
            epoll_data_rm(thread->proc, epfd, fd);
        break;
    }
    }
}

/* Copies the results for the epoll_wait syscall from the leader into the `ret
 * area' buffer, and for followers copies it back. Additionally, it has to
 * modify some of the data being copied per variant: the data associated with an
 * fd register in epoll can differ per variant, as it can be a pointer (which is
 * local to every variant). Thus, we map the data to an fd, and then back to the
 * variant-specific data.
 */
static void copyresults_epoll_wait(mv_thread_t thread,
        struct syscall *syscall, struct syscall *syscall0)
{
    pid_t pid = thread->proc->pid;
    int epfd = syscall->orig_args[0];
    size_t total_size = 0;
    int num_events;
    size_t i;

    if (thread->proc->variant_num == 0)
    {
        struct epoll_event *v0_events =
            (struct epoll_event *)syscall->orig_args[1];
        struct epoll_event *buf;
        num_events = syscall->rv;
        if (num_events <= 0)
            return;

        total_size = num_events * sizeof(struct epoll_event);
        resize_ret_area(syscall, total_size);
        buf = (struct epoll_event *)syscall->ret_area;
        copy_from_user(pid, buf, v0_events, total_size);
        syscall->arg_data[1] = (void *)buf;

        /* Rewrite data to fd in this buffer, so var-n procs don't have to do
         * this (which would require var0 state). The other variants still have
         * to map this from fd to the veriant-specific data. */
        for (i = 0; i < (unsigned)num_events; i++)
            buf[i].data.fd = epoll_data_to_fd(thread->proc, epfd,
                    buf[i].data.u64);
    }
    else
    {
        struct epoll_event *v0_events_orig =
            (struct epoll_event *)syscall0->arg_data[1];
        struct epoll_event *v0_events_local;
        struct epoll_event *vn_events =
            (struct epoll_event *)syscall->orig_args[1];
        num_events = syscall0->rv;
        if (num_events <= 0)
            return;

        /* Copy the var0 events into a local buffer, rewrite the fd's to
         * variant-specific data and then write this buffer to the proc memory
         * itself. */
        v0_events_local = alloc_mem_local(
                num_events * sizeof(struct epoll_event));
        memcpy(v0_events_local, v0_events_orig,
                num_events * sizeof(struct epoll_event));
        for (i = 0; i < (unsigned)num_events; i++)
            v0_events_local[i].data.u64 =
                epoll_data_get(thread->proc, epfd,
                        v0_events_local[i].data.fd);
        copy_to_user(pid, vn_events, v0_events_local,
                num_events * sizeof(struct epoll_event));
        free_mem_local(v0_events_local);
    }
}

/*
 * Copies the return values for the recvmsg syscall from the leader to the `ret
 * area' buffer, and for followers copies it back. This is a more complicated as
 * the struct passed in in itself contains nested structs and buffers.
 *
 * The layout of the `ret area' for this is as follows:
 *  namelen      sizeof(socklen_t)
 *  controllen   sizeof(size_t)
 *  flags        sizeof(int)
 *  name         namelen
 *  control      controllen
 *  iov          sum(iov[i].iov_len)
 */
static void copyresults_recvmsg(mv_thread_t thread,
        struct syscall *syscall, struct syscall *syscall0)
{
    pid_t pid = thread->proc->pid;
    struct msghdr *hdr = (struct msghdr *)syscall->arg_data[1];
    struct msghdr *hdr_user = (struct msghdr *)syscall->orig_args[1];
    struct iovec *iov = (struct iovec *)syscall->arg_data[2];
    socklen_t namelen = 0;
    size_t controllen = 0;
    void *l_name, *l_control, *l_iov;
    int flags;
    size_t i;

    if (thread->proc->variant_num == 0)
    {
        size_t total_len = 0;

        /* Fetch namelen and controllen (value-result args) so we know how big
         * our entire ret-area needs to be. */
        if (hdr->msg_name)
            copy_from_user(pid, &namelen,
                    (char *)hdr_user + offsetof(struct msghdr, msg_namelen),
                    sizeof(socklen_t));
        if (hdr->msg_control)
            copy_from_user(pid, &controllen,
                    (char *)hdr_user +
                        offsetof(struct msghdr, msg_controllen),
                    sizeof(size_t));
        copy_from_user(pid, &flags, (char *)hdr_user +
                offsetof(struct msghdr, msg_flags), sizeof(int));

        /* Count size of all iov buffers. */
        for (i = 0; i < hdr->msg_iovlen; i++)
            total_len += iov[i].iov_len;

        total_len += sizeof(socklen_t) + sizeof(size_t) + sizeof(int);
        total_len += namelen + controllen;
        total_len += sizeof(struct iovec) * hdr->msg_iovlen;

        resize_ret_area(syscall, total_len);
        l_name = (char *)syscall->ret_area + sizeof(socklen_t) +
            sizeof(size_t) + sizeof(int);
        l_control = (char *)l_name + namelen;
        l_iov = (char *)l_control + controllen;

        *(socklen_t *)syscall->ret_area = namelen;
        *(size_t *)((char *)syscall->ret_area + sizeof(socklen_t)) =
            controllen;
        *(int *)((char *)syscall->ret_area + sizeof(socklen_t) +
                sizeof(size_t)) = flags;

        if (hdr->msg_name)
            copy_from_user(pid, l_name, hdr->msg_name, namelen);
        if (hdr->msg_control)
            copy_from_user(pid, l_control, hdr->msg_control,
                    controllen);

        for (i = 0; i < hdr->msg_iovlen; i++)
        {
            copy_from_user(pid, l_iov, iov[i].iov_base,
                    iov[i].iov_len);
            l_iov = (char *)l_iov + iov[i].iov_len;
        }
    }
    else
    {
        char *base = syscall0->ret_area;
        namelen = *(socklen_t *)base;
        controllen = *(size_t *)(base + sizeof(socklen_t));
        flags = *(int *)(base + sizeof(socklen_t) + sizeof(size_t));
        l_name = base + sizeof(socklen_t) + sizeof(size_t) + sizeof(int);
        l_control = (char *)l_name + namelen;
        l_iov = (char *)l_control + controllen;

        copy_to_user(pid,
                (char *)hdr_user + offsetof(struct msghdr, msg_namelen),
                &namelen, sizeof(socklen_t));
        copy_to_user(pid,
                (char *)hdr_user + offsetof(struct msghdr, msg_controllen),
                &controllen, sizeof(size_t));
        copy_to_user(pid,
                (char *)hdr_user + offsetof(struct msghdr, msg_flags),
                &flags, sizeof(int));
        if (hdr->msg_name)
            copy_to_user(pid, hdr->msg_name, l_name, namelen);
        if (hdr->msg_control)
            copy_to_user(pid, hdr->msg_control, l_control,
                    controllen);

        for (i = 0; i < hdr->msg_iovlen; i++)
        {
            copy_to_user(pid, iov[i].iov_base, l_iov,
                    iov[i].iov_len);
            l_iov = (char *)l_iov + iov[i].iov_len;
        }
    }
}

static void copyresults(mv_thread_t thread, struct syscall *syscall,
        struct syscall *syscall0)
{
    size_t copy_sizes[6] = { 0, 0, 0, 0, 0, 0 };
    unsigned copy_store[6] = { 0, 0, 0, 0, 0, 0 };
    size_t total_size = 0;
    unsigned i;
    pid_t pid = thread->proc->pid;

    /* We have some exceptions to the generic copying of results structs, where
     * we need to do deep-copying and/or modify the copied values per variant.
     */
    if (syscall->nr == SYS_epoll_wait)
    {
        copyresults_epoll_wait(thread, syscall, syscall0);
        return;
    }
    else if (syscall->nr == SYS_recvmsg)
    {
        copyresults_recvmsg(thread, syscall, syscall0);
        return;
    }

    copyresults_sizes(syscall0, copy_sizes, copy_store);

    for (i = 0; i < 6; i++)
        total_size += copy_sizes[i];

    if (total_size == 0)
        return;

    if (thread->proc->variant->num == 0)
    {
        /* Copy everything to shared administration (saving it in var0's
         * arg_data) so other variants can copy it later themselves. */
        void *ret_area_cur;
        resize_ret_area(syscall, total_size);
        ret_area_cur = syscall->ret_area;

        for (i = 0; i < 6; i++)
            if (copy_sizes[i])
            {
                unsigned idx = copy_store[i] ? : i;
                syscall->arg_data[idx] = ret_area_cur;
                copy_from_user(pid, syscall->arg_data[idx],
                        (void *)syscall->orig_args[i], copy_sizes[i]);
                ret_area_cur = (char *)ret_area_cur + copy_sizes[i];
            }
    }
    else
    {
        /* At this point var0 should have copied the results to its admin area,
         * so we can copy it from there. */
        for (i = 0; i < 6; i++)
            if (copy_sizes[i])
                copy_to_user(pid, (void *)syscall->orig_args[i],
                        syscall0->arg_data[copy_store[i] ? : i], copy_sizes[i]);
    }

}

/*
 * Handle copies of return values (both the direct rv in rax and any other stuff
 * written to in memory) and set correct actions for processes after a system
 * call.
 */
void syscall_post(mv_thread_t thread, struct syscall *syscall,
        struct syscall *syscall0)
{
    int type = syscall_type[syscall->nr];

    assert((thread->proc->variant_num == 0 && syscall == syscall0) ||
           (thread->proc->variant_num != 0 && syscall != syscall0));

    thread->actions_post = MV_ACTION_CONTINUE |
                           MV_ACTION_WAKE_VARS |
                           MV_ACTION_WAKE_THREADS;

    set_fake_rv(thread, syscall, syscall0);

    /* Only update file descriptor administration copy result structs if syscall
     * was succes. */
    if ((thread->proc->variant_num == 0 && syscall->rv >= 0) ||
        (thread->proc->variant_num > 0 && syscall0->rv >= 0))
    {
        update_fd_mappings(thread, syscall, syscall0);
        copyresults(thread, syscall, syscall0);
    }

    if (thread->proc->variant_num != 0 && type == ONE &&
            !syscall_type_is_one_to_all(thread, syscall, syscall0))
    {
        syscall->fake_rv = syscall0->rv;
        thread->actions_post |= MV_ACTION_FAKE;
    }
}

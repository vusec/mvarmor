#define _GNU_SOURCE
#include <sys/syscall.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/futex.h>

/* Added in Linux 3.11 and glibc 2.20 */
#ifndef O_TMPFILE
#define O_TMPFILE 020200000
#endif

#include "multivar_internal.h"
#include "ksigaction.h"
#include "syscall_signatures.h"

void syscall_print_args(struct syscall_args *syscall, pid_t pid)
{
    struct syscall_signature *sig = &syscall_signatures[syscall->nr];
    unsigned i;
    print(" ~ %u: %s(", pid, sig->name);
    for (i = 0; i < sig->nr_args; i++)
        print("%#lx, ", syscall->orig_args[i]);
    print(")\n");
}

void print_c(char c)
{
    if (c == '\n')
        print("\\n");
    else if (c == '\r')
        print("\\r");
    else if (c == '\t')
        print("\\t");
    else if (c == '\0')
        print("\\0");
    /*
    else if (c < 32 || c >= 127)
        print("\\%x", c);
    */
    else
        print("%c", c);
}
void print_str_len(const char *str, size_t len)
{
    unsigned i;
    print("\"");
    for (i = 0; i < len; i++)
        print_c(str[i]);
    print("\"");
}
void print_str(const char *str)
{
    unsigned i;
    print("\"");
    for (i = 0; str[i]; i++)
        print_c(str[i]);
    print("\"");
}

/*
 * Prints all strings in a execve-style array of pointers, up to 10 max.
 */
void print_str_array(char **strs)
{
    unsigned i;
    print("{");
    for (i = 0; i < 10 && strs[i]; i++)
    {
        if (i > 0)
            print(", ");
        print_str(strs[i]);
    }
    if (i == 10 && strs[i - 1])
        print(", ...");
    print("}");
}

void print_iovec(struct iovec *iov, int iovcnt)
{
    int i;
    print("{");
    for (i = 0; i < iovcnt; i++)
    {
        if (i > 0)
            print(", ");
        print_str_len(iov[i].iov_base, iov[i].iov_len);
    }
    print("}");
}

void syscall_print_saved(struct syscall *syscall, pid_t pid, long rv, long orig_rv)
{
    unsigned i;
    uint64_t *orig_args = (uint64_t *)syscall->orig_args;
    unsigned long **arg_data = (unsigned long **)syscall->arg_data;
    struct syscall_signature *sig = &syscall_signatures[syscall->nr];
    print(" ~ %u: (#%lu|%lu) %s(%d)(", pid, syscall->var_id_pre,
            syscall->var_id_post, sig->name, syscall->nr);

    switch (syscall->nr)
    {
    case SYS_read:
    {
        unsigned int fd = orig_args[0];
        char *buf = (char *)orig_args[1];
        size_t c = orig_args[2];
        print("%d, %p, %zu", fd, buf, c);
        break;
    }
    case SYS_write:
    {
        unsigned int fd = orig_args[0];
        const char *buf = (const char *)arg_data[1];
        size_t c = orig_args[2];
        print("%d, ", fd);
        print_str_len(buf, c);
        print(", %zu", c);
        break;
    }
    case SYS_open:
    {
        const char *fn = (const char *)arg_data[0];
        int flags = orig_args[1];
        int mode = orig_args[2]; /* Ignored unless O_CREAT or O_TMPFILE */
        int tflags = flags, t = 0;
        print_str(fn);
        print(", ");
#define PFLAG(f) \
        if ((tflags & (f)) == (f)) { \
            if (t) \
                print(" | "); \
            t = 1; \
            print( #f ); \
            tflags &= ~(f); \
        }
        if (!(tflags & O_RDWR) && !(tflags & O_WRONLY))
        {
            print("O_RDONLY");
            t = 1;
        }
        PFLAG(O_RDWR);
        PFLAG(O_WRONLY);
        PFLAG(O_APPEND);
        PFLAG(O_ASYNC);
        PFLAG(O_DSYNC);
        PFLAG(O_SYNC);
        PFLAG(O_EXCL);
        PFLAG(O_TRUNC);
        PFLAG(O_NOCTTY);
        PFLAG(O_NOFOLLOW);
        PFLAG(O_NONBLOCK);
        PFLAG(O_CLOEXEC);
        PFLAG(O_DIRECTORY);
        PFLAG(O_CREAT);
        PFLAG(O_TMPFILE);
#undef PFLAG
        if (tflags)
            print("%d", tflags);
        if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE)
            print(", %d", mode);
        break;
    }
    case SYS_close:
    {
        unsigned fd = orig_args[0];
        print("%d", fd);
        break;
    }
    case SYS_stat:
    case SYS_lstat:
    {
        const char *fn = (const char *)arg_data[0];
        void *statbuf = (void *)orig_args[1];
        print_str(fn);
        print(", %p", statbuf);
        break;
    }
    case SYS_fstat:
    {
        unsigned int fd = orig_args[0];
        const char *statbuf = (const char *)orig_args[1];
        print("%d, %p", fd, statbuf);
        break;
    }
    case SYS_poll:
    {
        struct pollfd *fds = (void *)arg_data[0];
        nfds_t nfds = orig_args[1];
        int timeout = orig_args[2];
        print("[");
        for (i = 0; i < nfds; i++)
            print("{ %d, %d },", fds[i].fd, fds[i].events);
        print("], %d, %d", nfds, timeout);
        break;
    }
    case SYS_lseek:
    {
        unsigned fd     = orig_args[0];
        off_t offset    = orig_args[1];
        unsigned origin = orig_args[2];
        print("%u, %lu, %u", fd, offset, origin);
        break;
    }
    case SYS_mmap:
    {
        unsigned long addr  = orig_args[0];
        unsigned long len   = orig_args[1];
        unsigned long prot  = orig_args[2];
        unsigned long flags = orig_args[3];
        unsigned long fd    = orig_args[4];
        unsigned long off   = orig_args[5];
        print("%#lx, %ld, %ld, %ld, ", addr, len, prot, flags);
        if ((int)fd == -1)
            print("-1, ");
        else
            print("%ld, ", fd);
        print("%ld) = %#lx\n", off, rv);
        return;
    }
    /*
    case SYS_mprotect:
    case SYS_munmap:
    */
    case SYS_brk:
    {
        unsigned long addr  = orig_args[0];
        print("%#lx) = %#lx\n", addr, rv);
        return;
    }
    case SYS_rt_sigaction:
    {
        int sig = orig_args[0];
        struct ksigaction *act = (struct ksigaction *)arg_data[1];
        void *oact = (void *)orig_args[2];
        size_t sigsetsize = orig_args[3];
        print("%d, { ", sig);
        if (act)
        {
            /* These two are the same pointer in a union, but whatever. */
            if (act->ksa_flags & SA_SIGINFO)
                print("%p, ", act->ksa_sigaction);
            else
                print("%p, ", act->ksa_handler);
            print("%ld, %p", act->ksa_flags, act->ksa_restorer);
        }
        else
            print("NULL");
        print(" }, %p, %zu", oact, sigsetsize);
        break;
    }
    case SYS_rt_sigprocmask:
    {
        int how = orig_args[0];
        sigset_t *nset = (void *)orig_args[1];
        void *oset = (void *)orig_args[2];
        size_t sigsetsize = orig_args[3];
        print("%d, %p, %p, %zu", how, nset, oset, sigsetsize);
        break;
    }
    /*
    case SYS_rt_sigreturn:
    */
    case SYS_ioctl:
    {
        unsigned fd  = orig_args[0];
        unsigned cmd = orig_args[1];
        unsigned long arg = orig_args[2];
        char *cmd_str = NULL;
        switch (cmd)
        {
#define O(c) case c: cmd_str = #c; break;
            O(TIOCGWINSZ);
            O(TCGETS);
            O(FIONREAD);
            O(FIONBIO);
#undef O
        }
        if (cmd_str)
            print("%d, %s, %#lx", fd, cmd_str, arg);
        else
            print("%d, %x, %#lx", fd, cmd, arg);

        switch (cmd)
        {
            case FIONBIO:
                print(" (=%d)", *((int*)arg_data[2]));
                break;
        }
        break;
    }
    case SYS_pread64:
    {
        unsigned int fd = orig_args[0];
        void *buf = (void *)orig_args[1];
        size_t c = orig_args[2];
        off_t offset = orig_args[3];
        print("%d, %p, %zu, %jd", fd, buf, c, offset);
        break;
    }
    case SYS_pwrite64:
    {
        unsigned int fd = orig_args[0];
        const char *buf = (const char *)arg_data[1];
        size_t c = orig_args[2];
        off_t offset = orig_args[3];
        print("%d, ", fd);
        print_str_len(buf, c);
        print(", %zu, %jd", c, offset);
        break;
    }
    /*
    case SYS_readv:
    */
    case SYS_writev:
    {
        int fd = orig_args[0];
        struct iovec *iov = (struct iovec *)arg_data[1];
        int iovcnt = orig_args[2];
        print("%d, ", fd);
        print_iovec(iov, iovcnt);
        print(", %d", iovcnt);
        break;
    }
    case SYS_access:
    {
        const char *path = (const char *)arg_data[0];
        int mode = orig_args[1];
        print_str(path);
        print(", %d", mode);
        break;
    }
    case SYS_pipe:
    {
        int *filedes = (int *)orig_args[0];
        print("%p", filedes);
        break;
    }
    case SYS_select:
    {
        int nfds = orig_args[0];
        void *readfds = (void *)orig_args[1];
        void *writefds = (void *)orig_args[2];
        void *exceptfds = (void *)orig_args[3];
        void *timeout = (void *)orig_args[4];
        print("%d, %p, %p, %p, %p", nfds, readfds, writefds,
                exceptfds, timeout);
        break;
    }
    /*
    case SYS_sched_yield:
    case SYS_mremap:
    */
    case SYS_msync:
    {
        void *addr = (void *)orig_args[0];
        size_t len = orig_args[1];
        int flags = orig_args[2];
        print("%p, %zu, %d", addr, len, flags);
        break;
    }
    case SYS_mincore:
    {
        void *addr = (void *)orig_args[0];
        size_t len = orig_args[1];
        void *vec = (void *)orig_args[2];
        print("%p, %zu, %p", addr, len, vec);
        break;
    }
    case SYS_madvise:
    {
        void *addr = (void *)orig_args[0];
        size_t len = orig_args[1];
        int advice = orig_args[2];
        print("%p, %zu, %d", addr, len, advice);
        break;
    }
    /*
    case SYS_shmget:
    case SYS_shmat:
    case SYS_shmctl:
    */
    case SYS_dup:
    {
        int oldfd = orig_args[0];
        print("%d", oldfd);
        break;
    }
    case SYS_dup2:
    {
        int oldfd = orig_args[0];
        int newfd = orig_args[1];
        print("%d, %d", oldfd, newfd);
        break;
    }
    /*
    case SYS_pause:
    */
    case SYS_nanosleep:
    {
        struct timespec *req = (struct timespec *)arg_data[0],
                        *rem = (struct timespec *)orig_args[1];
        print("{ sec=%ld, nsec=%ld }, %p", req->tv_sec, req->tv_nsec,
                rem);
        break;
    }
    /*
    case SYS_getitimer:
    */
    case SYS_alarm:
    {
        unsigned seconds = orig_args[0];
        print("%u", seconds);
        break;
    }
    /*
    case SYS_setitimer:
    */
    case SYS_getpid:
        /* No args */
        break;
    case SYS_sendfile:
    {
        int out_fd   = orig_args[0];
        int in_fd     = orig_args[1];
        off_t *offset = (off_t *)orig_args[2];
        size_t count = orig_args[3];
        off_t offset_val = 0;
        if (offset)
            offset_val = *(off_t *)arg_data[2];
        print("%d, %d, %jd @ %p, %zu", out_fd, in_fd, offset_val,
                offset, count);
        break;
    }
    case SYS_socket:
    {
        int domain   = orig_args[0];
        int type     = orig_args[1];
        int protocol = orig_args[2];
        print("%d, %d, %d", domain, type, protocol);
        break;
    }
    case SYS_connect:
    {
        int fd = orig_args[0];
        struct sockaddr *addr = (struct sockaddr *)arg_data[1];
        unsigned addrlen = orig_args[2];
        /* TODO this assumed ipv4: we could calculate this based on addrlen. */
        print("%d, { ", fd);
        if (addr->sa_family == AF_INET)
        {
            unsigned short port;
            memcpy(&port, addr->sa_data, 2); /* GCC strict aliasing... */
            print("AF_INET, %u, %u.%u.%u.%u",
                ntohs(port), addr->sa_data[2],
                addr->sa_data[3], addr->sa_data[4], addr->sa_data[5]);
        }
        else if (addr->sa_family == AF_LOCAL)
        {
            print(" AF_LOCAL, \"");
            print_str((char *)addr + sizeof(sa_family_t));
            print("\"");
        }
        else
            print(" %u, ...", addr->sa_family);

        print(" }, %u", addrlen);

        break;
    }
    case SYS_accept:
    {
        int fd = orig_args[0];
        void *addr = (void *)orig_args[1];
        void *addrlen = (void *)orig_args[2];
        socklen_t addrlen_val = *(socklen_t *)arg_data[2];
        print("%d, %p, %d (@ %p)", fd, addr, addrlen_val, addrlen);
        break;
    }
    case SYS_sendto:
    {
        unsigned int fd = orig_args[0];
        const char *buf = (const char *)arg_data[1];
        size_t c = orig_args[2];
        int flags = orig_args[3];
        const struct sockaddr *dest_addr = (void *)orig_args[4];
        socklen_t addrlen = orig_args[5];

        print("%d, ", fd);
        print_str_len(buf, c);
        print(", %zu, %d, %p, %zu", c, flags, dest_addr, addrlen);
        break;
    }
    case SYS_recvfrom:
    {
        int fd = orig_args[0];
        void *buf = (void *)orig_args[1];
        size_t len = orig_args[2];
        int flags = orig_args[3];
        void *src_addr = (void *)orig_args[4];
        void *addrlen = (void *)orig_args[5];
        socklen_t addrlen_val = 0;
        if (addrlen)
            addrlen_val = *(socklen_t *)arg_data[2];
        print("%d, %p, %zu, %d, %p, %d (@ %p)", fd, buf, len, flags,
                src_addr, addrlen_val, addrlen);
        break;
    }
    /*
    case SYS_sendmsg:
    */
    case SYS_recvmsg:
    {
        int fd = orig_args[0];
        int flags = orig_args[2];
        struct msghdr *hdr = (void *)arg_data[1];
        struct iovec *iov = (void *)arg_data[2];

        print("%d, {name=%p, namelen=%zu, iov=%p, iovlen=%zu, control=%p, "
                "conntrollen=%zu, flags=%d}, %d", fd, hdr->msg_name,
                hdr->msg_namelen, hdr->msg_iov, hdr->msg_iovlen,
                hdr->msg_control, hdr->msg_controllen, hdr->msg_flags, flags);
        print("   iov=[");
        for (i = 0; i < hdr->msg_iovlen; i++)
            print("{%p, %zu}, ", iov[i].iov_base, iov[i].iov_len);
        print("]");

        break;
    }
    /*
    case SYS_shutdown:
    */
    case SYS_bind:
    {
        int fd = orig_args[0];
        struct sockaddr *addr = (struct sockaddr *)arg_data[1];
        unsigned addrlen = orig_args[2];
        unsigned short port;
        memcpy(&port, addr->sa_data, 2); /* GCC strict aliasing... */
        /* TODO this assumed ipv4: we could calculate this based on addrlen. */
        print("%d, { %u, %u, %u.%u.%u.%u }, %u", fd, addr->sa_family,
                ntohs(port), addr->sa_data[2],
                addr->sa_data[3], addr->sa_data[4], addr->sa_data[5],  addrlen);

        break;
    }
    case SYS_listen:
    {
        int fd = orig_args[0];
        int backlog = orig_args[1];
        print("%d, %d", fd, backlog);
        break;
    }
    case SYS_getsockname:
    {
        int fd = orig_args[0];
        void *addr = (void *)orig_args[1];
        void *addrlen = (void *)orig_args[2];
        socklen_t addrlen_val = orig_args[2];
        print("%d, %p, %d (@ %p)", fd, addr, addrlen_val, addrlen);
        break;
    }
    /*
    case SYS_getpeername:
    */
    case SYS_socketpair:
    {
        int domain = orig_args[0];
        int type = orig_args[1];
        int protocol = orig_args[2];
        int *sv = (int *)orig_args[3];
        print("%d, %d, %d, %p", domain, type, protocol, sv);
        break;
    }
    case SYS_setsockopt:
    case SYS_getsockopt:
    {
        int fd = orig_args[0];
        int level = orig_args[1];
        int optname = orig_args[2];
        int optval = orig_args[3]; /* might be more than an int... */
        unsigned optlen = orig_args[4];
        print("%d, %d, %d, %d, %u", fd, level, optname, optval,
                optlen);
        break;
    }
    case SYS_clone:
    {
        unsigned long flags = orig_args[0];
        void *child_stack = (void *)orig_args[1];
        void *ptid = (void *)orig_args[2];
        void *ctid = (void *)orig_args[3];
        void *regs = (void *)orig_args[4];
        print("%lu, %p, %p, %p, %p", flags, child_stack, ptid, ctid,
                regs);
        break;
    }
    /*
    case SYS_fork:
    case SYS_vfork:
    */
    case SYS_execve:
    {
        const char *fn = (const char *)arg_data[0];
        char **argv = (char **)arg_data[1];
        char **envp = (char **)arg_data[2];
        print_str(fn);
        print(", ");
        print_str_array(argv);
        print(", ");
        print_str_array(envp);
        break;
    }
    case SYS_exit:
    {
        int status = orig_args[0];
        print("%d", status);
        break;
    }
    case SYS_wait4:
    {
        pid_t pid = orig_args[0];
        int *status = (int *)orig_args[1];
        int options = orig_args[2];
        void *rusage = (void *)orig_args[3];
        print("%d, %p, %d, %p", pid, status, options, rusage);
        break;
    }
    case SYS_kill:
    {
        pid_t pid = orig_args[0];
        int sig = orig_args[1];
        print("%d, %d", pid, sig);
        break;
    }
    case SYS_uname:
    {
        void *buf = (void *)orig_args[0];
        print("%p", buf);
        break;
    }
    /*
    case SYS_semget:
    case SYS_semop:
    case SYS_semctl:
    case SYS_shmdt:
    case SYS_msgget:
    case SYS_msgsnd:
    case SYS_msgrcv:
    case SYS_msgctl:
    */
    case SYS_fcntl:
    {
        unsigned fd  = orig_args[0];
        unsigned cmd = orig_args[1];
        unsigned long arg = orig_args[2];
        unsigned use_arg[] = { F_SETFD, F_SETFL, F_SETLK, F_SETLKW, F_GETLK,
            F_SETOWN, F_GETOWN_EX, F_SETOWN_EX, F_SETSIG, F_SETLEASE, F_NOTIFY,
            F_SETPIPE_SZ };
        print("%d, ", fd);
#define CMD(c) case (c): print( #c ); break;
        switch (cmd) {
            CMD(F_DUPFD_CLOEXEC);
            CMD(F_DUPFD);
            CMD(F_GETFD);
            CMD(F_SETFD);
            CMD(F_GETFL);
            CMD(F_SETFL);
            CMD(F_SETLK);
            CMD(F_SETLKW);
            CMD(F_GETLK);
            /*CMD(F_OFD_SETLK);*/
            /*CMD(F_OFD_SETLKW);*/
            /*CMD(F_OFD_GETLK);*/
            CMD(F_GETOWN);
            CMD(F_SETOWN);
            CMD(F_GETOWN_EX);
            CMD(F_SETOWN_EX);
            CMD(F_GETSIG);
            CMD(F_SETSIG);
            CMD(F_SETLEASE);
            CMD(F_GETLEASE);
            CMD(F_NOTIFY);
            CMD(F_SETPIPE_SZ);
            CMD(F_GETPIPE_SZ);
            default: print("%d", cmd);
        }
#undef PCMD
        for (i = 0; i < sizeof(use_arg) / sizeof(unsigned); i++)
            if (use_arg[i] == cmd)
                print(", %#lx", arg);
        break;
    }
    /*
    case SYS_flock:
    case SYS_fsync:
    case SYS_fdatasync:
    case SYS_truncate:
    case SYS_ftruncate:
    */
    case SYS_getdents:
    {
        unsigned fd  = orig_args[0];
        void *dirent  = (void *)orig_args[1];
        unsigned count = orig_args[2];
        print("%d, %p, %u", fd, dirent, count);
        break;
    }
    case SYS_getcwd:
    {
        char *buf = (char *)orig_args[0];
        unsigned long size = orig_args[1];
        print("%p, %lu", buf, size);
        break;
    }
    case SYS_chdir:
    {
        const char *fn = (const char *)arg_data[0];
        print_str(fn);
        break;
    }
    case SYS_rename:
    {
        const char *oldname = (const char *)arg_data[0],
                   *newname = (const char *)arg_data[1];
        print_str(oldname);
        print(", ");
        print_str(newname);
        break;
    }
    case SYS_mkdir:
    {
        const char *fn = (const char *)arg_data[0];
        mode_t mode = orig_args[1];
        print_str(fn);
        print(", %u", mode);
        break;
    }
    case SYS_unlink:
    {
        const char *fn = (const char *)arg_data[0];
        print_str(fn);
        break;
    }
    case SYS_readlink:
    {
        const char *path = (const char *)arg_data[0];
        char *buf = (char *)orig_args[1];
        int bufsize = orig_args[2];
        print_str(path);
        print(", %p, %d", buf, bufsize);
        break;
    }
    case SYS_chmod:
    {
        const char *path = (const char *)arg_data[0];
        mode_t mode = (mode_t)orig_args[1];
        print_str(path);
        print(", %d", mode);
        break;
    }
    case SYS_chown:
    {
        const char *path = (const char *)arg_data[0];
        uid_t owner = (uid_t)orig_args[1];
        gid_t group = (gid_t)orig_args[2];
        print_str(path);
        print(", %d", owner);
        print(", %d", group);
        break;
    }
    case SYS_umask:
    {
        int res = orig_args[0];
        print("%d", res);
        break;
    }
    case SYS_gettimeofday:
    {
        void *tv = (void *)orig_args[0];
        void *tz = (void *)orig_args[1];
        print("%p, %p", tv, tz);
        break;
    }
    case SYS_getrlimit:
    {
        int res = orig_args[0];
        void *rlim = (void *)orig_args[1];
        print("%d, %p", res, rlim);
        break;
    }
    case SYS_setgid:
    {
        gid_t gid = orig_args[0];
        print("%d", gid);
        break;
    }
    case SYS_geteuid:
    case SYS_setsid:
        /* No args */
        break;
    case SYS_setgroups:
    {
        int size = orig_args[0];
        gid_t *list = (gid_t *)arg_data[1];
        print("%d, { ", size);
        for (i = 0; i < (unsigned)size; i++)
            print("%d, ", list[i]);
        print("}");
        break;
    }
    case SYS_rt_sigsuspend:
    {
        void *mask = (void *)orig_args[0];
        size_t sigsetsize = orig_args[1];
        print("%p, %zu", mask, sigsetsize);
        break;
    }
    case SYS_statfs:
    {
        const char *path = (const char *)arg_data[0];
        void *buf = (void *)orig_args[1];
        print_str(path);
        print(", %p", buf);
        break;
    }
    case SYS_prctl:
    {
        int option = orig_args[0];
        unsigned long arg2 = orig_args[1],
                      arg3 = orig_args[2],
                      arg4 = orig_args[3];
        print("%d, %lu, %lu, %lu", option, arg2, arg3, arg4);
        break;
    }
    case SYS_arch_prctl:
    {
        int code = orig_args[0];
        void *addr = (void *)orig_args[1];
        print("%d, %p", code, addr);
        break;
    }
    case SYS_getxattr:
    {
        const char *path = (const char *)arg_data[0];
        const char *name = (const char *)arg_data[1];
        void *val = (void *)orig_args[2];
        size_t size = orig_args[3];
        print_str(path);
        print(", ");
        print_str(name);
        print(", %p, %zu", val, size);
        break;
    }
    case SYS_time:
    {
        time_t *t = (time_t *)orig_args[0];
        print("%p", t);
        break;
    }
    case SYS_futex:
    {
        int *uaddr = (int *)orig_args[0];
        int op = orig_args[1];
        int val = orig_args[2];
        struct timespec *timeout = (struct timespec *)arg_data[3];
        int timeout_overload = orig_args[3];
        int *uaddr2 = (int *)orig_args[4];
        int val3 = orig_args[5];
        print("%p, ", uaddr);
        switch (op & FUTEX_CMD_MASK)
        {
        case FUTEX_WAIT:
            print("FUTEX_WAIT, %d, ", val);
            if (!timeout)
                print("NULL");
            else
                print("{ sec=%ld, nsec=%ld }", timeout->tv_sec,
                        timeout->tv_nsec);
            break;
        case FUTEX_WAKE:
            print("FUTEX_WAKE, %d", val);
            break;
        case FUTEX_FD:
            print("FUTEX_FD, %d", val);
            break;
        case FUTEX_REQUEUE:
            print("FUTEX_REQUEUE, %d, %p", val, uaddr2);
            break;
        case FUTEX_CMP_REQUEUE:
            print("FUTEX_CMP_REQUEUE, %d, %p, %d", val, uaddr2, val3);
            break;
        case FUTEX_WAKE_OP:
            print("FUTEX_WAKE_OP, %d, %d, %p, %d", val, timeout_overload,
                    uaddr2, val3);
            break;
        case FUTEX_WAIT_BITSET:
            print("FUTEX_WAIT_BITSET, %d, ", val);
            if (!timeout)
                print("NULL, ");
            else
                print("{ sec=%ld, nsec=%ld }, ", timeout->tv_sec,
                        timeout->tv_nsec);
            print("%x, ", val3);
            break;
        default:
            print("UNKNOWN OP (%d)", op);
        }
        break;
    }
    case SYS_epoll_create:
    {
        int size = orig_args[0];
        print("%d", size);
        break;
    }
    case SYS_set_tid_address:
    {

        void *tidptr = (void *)orig_args[0];
        print("%p", tidptr);
        break;
    }
    case SYS_fadvise64:
    {
        int fd = orig_args[0];
        long long off = orig_args[1];
        size_t len = orig_args[2];
        int adv = orig_args[3];
        print("%d, %lld, %zu, %d", fd, off, len, adv);
        break;
    }
    case SYS_clock_gettime:
    {
        clockid_t clk_id = orig_args[0];
        void *tp = (void *)orig_args[1];
        print("%d, %p", clk_id, tp);
        break;
    }
    case SYS_exit_group:
    {
        int error_code = orig_args[0];
        print("%d", error_code);
        break;
    }
    case SYS_epoll_wait:
    {
        int epfd = orig_args[0];
        void *events = (void *)orig_args[1];
        int maxevents = orig_args[2];
        int timeout = orig_args[3];
        print("%d, %p, %d, %d", epfd, events, maxevents, timeout);
        break;
    }
    case SYS_epoll_ctl:
    {
        const char *ops[] = {NULL, "EPOLL_CTL_ADD", "EPOLL_CTL_MOD",
            "EPOLL_CTL_DEL"};
        int epfd = orig_args[0];
        int op = orig_args[1];
        int fd = orig_args[2];
        struct epoll_event *event = (struct epoll_event *)arg_data[3];
        print("%d, %s, %d, { %u, %lu }", epfd, ops[op], fd, event->events,
                event->data.u64);
        break;
    }
    case SYS_openat:
    {
        int dfd = orig_args[0];
        const char *fn = (const char *)arg_data[1];
        int flags = orig_args[2];
        int mode = orig_args[3]; /* Ignored unless O_CREAT or O_TMPFILE */
        print("%d, ", dfd);
        print_str(fn);
        print(", %d", mode);
        if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE)
            print(", %d", mode);
        break;
    }
    case SYS_set_robust_list:
    {
        void *head = (void *)orig_args[0];
        size_t len = orig_args[1];
        print("%p, %zu", head, len);
        break;
    }
    case SYS_get_robust_list:
    {
        int pid = orig_args[0];
        void **head_ptr = (void **)orig_args[1];
        size_t *len_ptr = (size_t *)orig_args[2];
        print("%d, %p, %p", pid, head_ptr, len_ptr);
        break;
    }
    case SYS_pipe2:
    {
        int *filedes = (int *)orig_args[0];
        int flags = (int)orig_args[1];
        print("%p, %d", filedes, flags);
        break;
    }
    default:
        for (i = 0; i < sig->nr_args; i++)
            print("%#lx, ", orig_args[i]);
    }
    print(") = %ld (%ld)\n", rv, orig_rv);
}

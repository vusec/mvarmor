#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sys/capability.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sem.h>
#include <linux/futex.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

#include "multivar_internal.h"
#include "ksigaction.h"

/* Added in Linux 3.11 and glibc 2.20 */
#ifndef O_TMPFILE
#define O_TMPFILE 020200000
#endif

int compare_str_array(char **strs1, char **strs2)
{
    unsigned i;
    for (i = 0; strs1[i]; i++)
    {
        if (strs2[i] == NULL)
            return 0;
        if (strcmp(strs1[i], strs2[i]))
            return 0;
    }
    if (strs2[i] != NULL)
        return 0;
    return 1;
}

int compare_iovec(struct iovec *iov1, struct iovec *iov2, int iovcnt)
{
    int i;
    for (i = 0; i < iovcnt; i++)
    {
        if (iov1[i].iov_len != iov2[i].iov_len)
            return 0;
        if (memcmp(iov1[i].iov_base, iov2[i].iov_base, iov1[i].iov_len))
            return 0;
    }
    return 1;
}

/*
 * Returns true (1) if the system calls are equivalent.
 */
int compare_args(struct syscall *syscall1, struct syscall *syscall2)
{
    uint64_t *orig_args1, *orig_args2;
    unsigned long **arg_data1, **arg_data2;
    size_t i;

    if (syscall1->nr != syscall2->nr)
        return 0;

    orig_args1 = syscall1->orig_args;
    orig_args2 = syscall2->orig_args;
    arg_data1 = syscall1->arg_data;
    arg_data2 = syscall2->arg_data;

    switch (syscall1->nr)
    {
    case SYS_read:
    {
        unsigned int fd1 = orig_args1[0], fd2 = orig_args2[0];
        size_t c1 = orig_args1[2], c2 = orig_args2[2];
        return fd1 == fd2 && c1 == c2;
    }
    case SYS_write:
    {
        const char *buf1 = (const char *)arg_data1[1],
                   *buf2 = (const char *)arg_data2[1];
        unsigned int fd1 = orig_args1[0], fd2 = orig_args2[0];
        size_t c1 = orig_args1[2], c2 = orig_args2[2];
        return fd1 == fd2 && c1 == c2 && !memcmp(buf1, buf2, c1);
    }
    case SYS_open:
    {
        const char *fn1 = (const char *)arg_data1[0],
                   *fn2 = (const char *)arg_data2[0];
        int flags1 = orig_args1[1], flags2 = orig_args2[1];
        /* Ignored unless O_CREAT or O_TMPFILE */
        int mode1 = orig_args1[2], mode2 = orig_args2[2];
        return !strcmp(fn1, fn2) && flags1 == flags2 &&
            (!((flags1 & O_CREAT) || (flags1 & O_TMPFILE) == O_TMPFILE) ||
                mode1 == mode2);
    }
    case SYS_close:
    {
        unsigned int fd1 = orig_args1[0],
                     fd2 = orig_args2[0];
        return fd1 == fd2;
    }
    case SYS_stat:
    case SYS_lstat:
    {
        const char *fn1 = (const char *)arg_data1[0],
                   *fn2 = (const char *)arg_data2[0];
        return !strcmp(fn1, fn2);
    }
    case SYS_fstat:
    {
        unsigned int fd1 = orig_args1[0],
                     fd2 = orig_args2[0];
        return fd1 == fd2;
    }
    case SYS_poll:
    {
        struct pollfd *fds1 = (void *)arg_data1[0],
                      *fds2 = (void *)arg_data2[0];
        nfds_t nfds1 = orig_args1[1], nfds2 = orig_args2[1];
        int timeout1 = orig_args1[2], timeout2 = orig_args2[2];
        if (nfds1 != nfds2)
            return 0;
        for (i = 0; i < nfds1; i++)
            if (fds1[i].fd != fds2[i].fd || fds1[i].events != fds2[i].events)
                return 0;
        return timeout1 == timeout2;
    }
    case SYS_lseek:
    {
        unsigned fd1     = orig_args1[0], fd2     = orig_args2[0];
        off_t offset1    = orig_args1[1], offset2 = orig_args2[1];
        unsigned origin1 = orig_args1[2], origin2 = orig_args2[2];
        return fd1 == fd2 && offset1 == offset2 && origin1 == origin2;
    }
    case SYS_mmap:
    {
        /*unsigned long addr1  = orig_args1[0], addr2  = orig_args2[0];*/
        unsigned long len1   = orig_args1[1], len2   = orig_args2[1];
        unsigned long prot1  = orig_args1[2], prot2  = orig_args2[2];
        unsigned long flags1 = orig_args1[3], flags2 = orig_args2[3];
        unsigned long fd1    = orig_args1[4], fd2    = orig_args2[4];
        unsigned long off1   = orig_args1[5], off2   = orig_args2[5];
        return len1 == len2 && prot1 == prot2 && flags1 == flags2 &&
                fd1 == fd2 && off1 == off2;
    }
    case SYS_mprotect:
    {
        /*unsigned long addr1  = orig_args1[0], addr2  = orig_args2[0];*/
        unsigned long len1  = orig_args1[1], len2  = orig_args2[1];
        unsigned long prot1 = orig_args1[2], prot2 = orig_args2[2];
        return len1 == len2 && prot1 == prot2;
    }
    case SYS_munmap:
    {
        /* XXX: jemalloc does some crazy alignment thing */
        /*unsigned long addr1  = *args1[0], addr2  = *args2[0];*/
        unsigned long len1 = orig_args1[1], len2 = orig_args2[1];
        return len1 == len2;
    }
    case SYS_brk:
    {
        unsigned long brk1 = orig_args1[0], brk2 = orig_args2[0];
        return brk1 == brk2;
    }
    case SYS_rt_sigaction:
    {
        int sig1 = orig_args1[0], sig2 = orig_args2[0];
        struct ksigaction *act1 = (struct ksigaction *)arg_data1[1],
                          *act2 = (struct ksigaction *)arg_data2[1];
        struct ksigaction *oact1 = (struct ksigaction *)orig_args1[2],
                          *oact2 = (struct ksigaction *)orig_args2[2];
        int sigsetsize1 = orig_args1[3], sigsetsize2 = orig_args2[3];
        if (act1)
        {
            if (!act2)
                return 0;

            /* While theoretically there could be padding filled with garbage,
             * this seems to be the only and safest way of comparing sigset_t */
            if (memcmp(&act1->ksa_mask, &act2->ksa_mask, sizeof(sigset_t)) ||
                act1->ksa_flags != act2->ksa_flags)
                return 0;
            /*
            if ((act1->ksa_flags & SA_SIGINFO &&
                        act1->ksa_handler != act2->ksa_handler) ||
                (!(act1->ksa_flags & SA_SIGINFO) &&
                        act1->ksa_sigaction != act2->ksa_sigaction))
                return 0;
            */
        }
        if (act2 && !act1)
            return 0;
        if ((oact1 && !oact2) || (!oact1 && oact2))
            return 0;
        return sig1 == sig2 && sigsetsize1 == sigsetsize2;
    }
    case SYS_rt_sigprocmask:
    {
        int how1 = orig_args1[0], how2 = orig_args2[0];
        sigset_t *nset1 = (sigset_t *)arg_data1[1],
                 *nset2 = (sigset_t *)arg_data2[1];
        sigset_t *oset1 = (sigset_t *)orig_args1[2],
                 *oset2 = (sigset_t *)orig_args2[2];
        int sigsetsize1 = orig_args1[3], sigsetsize2 = orig_args2[3];
        if (nset1)
        {
            if (!nset2)
                return 0;
            if (memcmp(nset1, nset2, sigsetsize1))
                return 0;
            if (how1 != how2)
                return 0;
        }
        if (nset2 && !nset1)
            return 0;
        if ((oset1 && !oset2) || (!oset1 && oset2))
            return 0;
        return sigsetsize1 == sigsetsize2;
    }
    case SYS_rt_sigreturn:
        /* No args. */
        return 1;
    case SYS_ioctl:
    {
        unsigned fd1  = orig_args1[0], fd2  = orig_args2[0];
        unsigned cmd1 = orig_args1[1], cmd2 = orig_args2[1];
        int *arg1 = (int*)arg_data1[2], *arg2 = (int*)arg_data2[2];
        switch (cmd1)
        {
            /* XXX not complete */
            case FIONBIO:
                if (*arg1 != *arg2)
                    return 0;
                break;
        }
        return fd1 == fd2 && cmd1 == cmd2;
    }
    case SYS_pread64:
    {
        unsigned int fd1 = orig_args1[0], fd2 = orig_args2[0];
        size_t c1 = orig_args1[2], c2 = orig_args2[2];
        off_t off1 = orig_args1[3], off2 = orig_args2[3];
        return fd1 == fd2 && c1 == c2 && off1 == off2;
    }
    case SYS_pwrite64:
    {
        const char *buf1 = (const char *)arg_data1[1],
                   *buf2 = (const char *)arg_data2[1];
        unsigned int fd1 = orig_args1[0], fd2 = orig_args2[0];
        size_t c1 = orig_args1[2], c2 = orig_args2[2];
        size_t off1 = orig_args1[3], off2 = orig_args2[3];
        return fd1 == fd2 && c1 == c2 && off1 == off2 &&
            !memcmp(buf1, buf2, c1);
    }
    /*
    case SYS_readv:
    */
    case SYS_writev:
    {
        int fd1 = orig_args1[0], fd2 = orig_args2[0];
        struct iovec *iov1 = (struct iovec *)arg_data1[1],
                     *iov2 = (struct iovec *)arg_data2[1];
        int iovcnt1 = orig_args1[2], iovcnt2 = orig_args2[2];
        if (fd1 != fd2 || iovcnt1 != iovcnt2)
            return 0;
        return compare_iovec(iov1, iov2, iovcnt1);
    }
    case SYS_access:
    {
        const char *fn1 = (const char *)arg_data1[0],
                   *fn2 = (const char *)arg_data2[0];
        int mode1 = orig_args1[1], mode2 = orig_args2[1];
        return !strcmp(fn1, fn2) && mode1 == mode2;
    }
    case SYS_pipe:
    {
        /*
        int *fn1 = (int *)args1[0],
            *fn2 = (int *)args2[0];
        */
        return 1;
    }
    case SYS_select:
    {
        int nfds1 = orig_args1[0], nfds2 = orig_args2[0];
        fd_set *readfds1 = (fd_set *)arg_data1[1],
               *readfds2 = (fd_set *)arg_data2[1];
        fd_set *writefds1 = (fd_set *)arg_data1[2],
               *writefds2 = (fd_set *)arg_data2[2];
        fd_set *exceptfds1 = (fd_set *)arg_data1[3],
               *exceptfds2 = (fd_set *)arg_data2[3];
        struct timeval *timeout1 = (struct timeval *)arg_data1[4],
                       *timeout2 = (struct timeval *)arg_data2[4];
        if ((readfds1 && !readfds2) || (!readfds1 && readfds2))
            return 0;
        if ((writefds1 && !writefds2) || (!writefds1 && writefds2))
            return 0;
        if ((exceptfds1 && !exceptfds2) || (!exceptfds1 && exceptfds2))
            return 0;
        if ((timeout1 && !timeout2) || (!timeout1 && timeout2))
            return 0;
        if (readfds1 && memcmp(readfds1, readfds2, sizeof(fd_set)))
            return 0;
        if (writefds1 && memcmp(writefds1, writefds2, sizeof(fd_set)))
            return 0;
        if (exceptfds1 && memcmp(exceptfds1, exceptfds2, sizeof(fd_set)))
            return 0;
        if (timeout1 && memcmp(timeout1, timeout2, sizeof(struct timeval)))
            return 0;
        return nfds1 == nfds2;
    }
    /*
    case SYS_sched_yield:
    case SYS_mremap:
    */
    case SYS_msync:
    {
        /*unsigned long addr1 = orig_args1[0], addr2 = orig_args2[0];*/
        unsigned long len1 = orig_args1[1], len2 = orig_args2[1];
        int flags1 = orig_args1[2], flags2  = orig_args2[2];
        return len1 == len2 && flags1 == flags2;
    }
    case SYS_mincore:
    {
        /*unsigned long addr1 = orig_args1[0], addr2 = orig_args2[0];*/
        unsigned long len1 = orig_args1[1], len2 = orig_args2[1];
        /*void *vec1 = orig_args1[2], *vec2  = orig_args2[2]; */
        return len1 == len2;
    }
    case SYS_madvise:
    {
        /*unsigned long addr1 = orig_args1[0], addr2 = orig_args2[0];*/
        unsigned long len1 = orig_args1[1], len2 = orig_args2[1];
        unsigned long advice1 = orig_args1[2], advice2 = orig_args2[2];
        return len1 == len2 && advice1 == advice2;
    }
    /*
    case SYS_shmget:
    case SYS_shmat:
    case SYS_shmctl:
    */
    case SYS_dup:
    {
        int oldfd1 = orig_args1[0], oldfd2 = orig_args2[0];
        return oldfd1 == oldfd2;
    }
    case SYS_dup2:
    {
        int oldfd1 = orig_args1[0], oldfd2 = orig_args2[0];
        int newfd1 = orig_args1[1], newfd2 = orig_args2[1];
        return oldfd1 == oldfd2 && newfd1 == newfd2;
    }
    /*
    case SYS_pause:
    */
    case SYS_nanosleep:
    {
        struct timespec *req1 = (struct timespec *)arg_data1[0],
                        *req2 = (struct timespec *)arg_data2[0];
        void *rem1 = (void *)orig_args1[1], *rem2 = (void *)orig_args2[1];
        if ((rem1 == NULL && rem2 != NULL) || (rem1 != NULL && rem2 == NULL))
            return 0;
        return req1->tv_sec == req2->tv_sec && req1->tv_nsec == req2->tv_nsec;
    }
    /*
    case SYS_getitimer:
    */
    case SYS_alarm:
    {
        int sec1 = orig_args1[0], sec2 = orig_args2[0];
        return sec1 == sec2;
    }
    /*
    case SYS_setitimer:
    */
    case SYS_getpid:
        /* No args */
        return 1;
    case SYS_sendfile:
    {
        int out_fd1 = orig_args1[0], out_fd2 = orig_args2[0];
        int in_fd1 = orig_args1[1], in_fd2 = orig_args2[1];
        off_t *offset1 = (off_t *)orig_args1[2],
              *offset2 = (off_t *)orig_args2[2];
        size_t count1 = orig_args1[3], count2 = orig_args2[3];

        if ((offset1 && !offset2) || (!offset1 && offset2))
            return 0;
        if (offset1)
        {
            off_t off1 = *(off_t *)arg_data1[2],
                  off2 = *(off_t *)arg_data2[2];
            if (off1 != off2)
                return 0;
        }
        return out_fd1 == out_fd2 && in_fd1 == in_fd2 && count1 == count2;
    }
    case SYS_socket:
    {
        int domain1   = orig_args1[0], domain2   = orig_args2[0];
        int type1     = orig_args1[1], type2     = orig_args2[1];
        int protocol1 = orig_args1[2], protocol2 = orig_args2[2];
        return domain1 == domain2 && type1 == type2 && protocol1 == protocol2;
    }
    case SYS_connect:
    {
        int fd1 = orig_args1[0], fd2 = orig_args2[0];
        struct sockaddr *addr1 = (struct sockaddr *)arg_data1[1],
                        *addr2 = (struct sockaddr *)arg_data2[1];
        socklen_t addrlen1 = orig_args1[2], addrlen2 = orig_args2[2];
        if (fd1 != fd2 || addrlen1 != addrlen2 ||
                addr1->sa_family != addr2->sa_family)
            return 0;

        if (addr1->sa_family == AF_LOCAL)
            return !strncmp((char *)addr1 + sizeof(sa_family_t),
                            (char *)addr2 + sizeof(sa_family_t), 108);
        return memcmp(addr1, addr2, addrlen1) == 0;
    }
    case SYS_accept:
    {
        int fd1 = orig_args1[0], fd2 = orig_args2[0];
        /*struct sockaddr *addr1 = *(struct sockaddr **)args1[1],
                          *addr2 = *(struct sockaddr **)args2[1]; */
        socklen_t addrlen1 = *(socklen_t *)arg_data1[2],
                  addrlen2 = *(socklen_t *)arg_data2[2];
        return fd1 == fd2 && addrlen1 == addrlen2;
    }
    case SYS_sendto:
    {
        int sockfd1 = orig_args1[0], sockfd2 = orig_args2[0];
        const void *buf1 = (const char *)arg_data1[1],
                   *buf2 = (const char *)arg_data2[1];
        size_t c1 = orig_args1[2], c2 = orig_args2[2];
        int flags1 = orig_args1[3], flags2 = orig_args2[3];
        const struct sockaddr *dest1 = (void *)arg_data1[4],
                              *dest2 = (void *)arg_data2[4];
        socklen_t addrlen1 = orig_args1[5], addrlen2 = orig_args2[5];
        if (addrlen1 != addrlen2)
            return 0;
        if (addrlen1 && memcmp(dest1, dest2, addrlen1))
            return 0;
        return sockfd1 == sockfd2 && c1 == c2 && !memcmp(buf1, buf2, c1) &&
            flags1 == flags2;
    }
    case SYS_recvfrom:
    {
        int fd1 = orig_args1[0], fd2 = orig_args2[0];
        /*void *addr1 = (void *)orig_args1[1],
               *addr2 = (void *)orig_args2[1]; */
        int len1 = orig_args1[2], len2 = orig_args2[2];
        int flags1 = orig_args1[3], flags2 = orig_args2[3];
        /*struct sockaddr *addr1 = *(struct sockaddr **)args1[4],
                          *addr2 = *(struct sockaddr **)args2[4]; */
        struct sockaddr *addr1 = (struct sockaddr *)orig_args1[4],
                        *addr2 = (struct sockaddr *)orig_args2[4];

        if ((addr1 && !addr2) || (!addr1 && addr2))
            return 0;
        if (addr1)
        {
            socklen_t addrlen1 = *(socklen_t *)arg_data1[2],
                      addrlen2 = *(socklen_t *)arg_data2[2];
            if (addrlen1 != addrlen2)
                return 0;
        }
        return fd1 == fd2 && len1 == len2 && flags1 == flags2;
    }
    case SYS_sendmsg:
    {
        int fd1 = orig_args1[0], fd2 = orig_args2[0];
        struct msghdr *msg1 = (void *)arg_data1[1],
                      *msg2 = (void *)arg_data2[1];
        int flags1 = orig_args1[2], flags2 = orig_args2[2];

        if (fd1 != fd2 || flags1 != flags2)
            return 0;
        if (msg1->msg_namelen != msg2->msg_namelen ||
            msg1->msg_controllen != msg2->msg_controllen ||
            msg1->msg_iovlen != msg2->msg_iovlen)
            return 0;
        if (msg1->msg_namelen && memcmp(msg1->msg_name, msg2->msg_name,
                    msg1->msg_namelen))
            return 0;
        if (msg1->msg_controllen && memcmp(msg1->msg_control, msg2->msg_control,
                    msg1->msg_controllen))
            return 0;
        return compare_iovec(msg1->msg_iov, msg2->msg_iov, msg1->msg_iovlen);
    }
    case SYS_recvmsg:
    {
        int fd1 = orig_args1[0], fd2 = orig_args2[0];
        struct msghdr *msg1 = (void *)arg_data1[1],
                      *msg2 = (void *)arg_data2[1];
        int flags1 = orig_args1[2], flags2 = orig_args2[2];

        if ((msg1->msg_name && !msg2->msg_name) ||
            (!msg1->msg_name && msg2->msg_name))
            return 0;
        if ((msg1->msg_iov && !msg2->msg_iov) ||
            (!msg1->msg_iov && msg2->msg_iov))
            return 0;
        if ((msg1->msg_control && !msg2->msg_control) ||
            (!msg1->msg_control && msg2->msg_control))
            return 0;
        if (msg1->msg_namelen != msg2->msg_namelen ||
            msg1->msg_iovlen != msg2->msg_iovlen ||
            msg1->msg_controllen != msg2->msg_controllen)
            return 0;

        return fd1 == fd2 && flags1 == flags2;
    }
    case SYS_shutdown:
    {
        int fd1 = orig_args1[0], fd2 = orig_args2[0];
        int how1 = orig_args1[1], how2 = orig_args2[1];
        return fd1 == fd2 && how1 == how2;
    }
    case SYS_bind:
    {
        int fd1 = orig_args1[0], fd2 = orig_args2[0];
        struct sockaddr *addr1 = (struct sockaddr *)arg_data1[1],
                        *addr2 = (struct sockaddr *)arg_data2[1];
        socklen_t addrlen1 = orig_args1[2], addrlen2 = orig_args2[2];
        if (fd1 != fd2 || addrlen1 != addrlen2)
            return 0;
        return memcmp(addr1, addr2, addrlen1) == 0;
    }
    case SYS_listen:
    {
        int fd1      = orig_args1[0], fd2      = orig_args2[0];
        int backlog1 = orig_args1[1], backlog2 = orig_args2[1];
        return fd1 == fd2 && backlog1 == backlog2;
    }
    case SYS_getsockname:
    {
        int fd1 = orig_args1[0], fd2 = orig_args2[0];
        /*struct sockaddr *addr1 = *(struct sockaddr **)args1[1],
                          *addr2 = *(struct sockaddr **)args2[1]; */
        socklen_t addrlen1 = *(socklen_t *)arg_data1[2],
                  addrlen2 = *(socklen_t *)arg_data2[2];
        return fd1 == fd2 && addrlen1 == addrlen2;
    }
    /*
    case SYS_getpeername:
    */
    case SYS_socketpair:
    {
        int domain1 = orig_args1[0], domain2 = orig_args2[0];
        int type1 = orig_args1[1], type2 = orig_args2[1];
        int protocol1 = orig_args1[2], protocol2 = orig_args2[2];
        /* int *sv1 = (int **)args1[3], *sv2 = (int **)args2[3]; */
        return domain1 == domain2 && type1 == type2 && protocol1 == protocol2;
    }
    case SYS_setsockopt:
    {
        int fd1           = orig_args1[0], fd2      = orig_args2[0];
        int level1        = orig_args1[1], level2   = orig_args2[1];
        int optname1      = orig_args1[2], optname2 = orig_args2[2];
        socklen_t optlen1 = orig_args1[4], optlen2  = orig_args2[4];
        void *optval1 = (void *)arg_data1[3],
             *optval2 = (void *)arg_data2[3];
        if (fd1 != fd2 || level1 != level2 || optname1 != optname2 ||
                optlen1 != optlen2)
            return 0;
        return memcmp(optval1, optval2, optlen1) == 0;
    }
    case SYS_getsockopt:
    {
        int fd1           = orig_args1[0], fd2      = orig_args2[0];
        int level1        = orig_args1[1], level2   = orig_args2[1];
        int optname1      = orig_args1[2], optname2 = orig_args2[2];
        socklen_t addrlen1 = *(socklen_t *)arg_data1[4],
                  addrlen2 = *(socklen_t *)arg_data2[4];
        return fd1 == fd2 && level1 == level2 && optname1 == optname2 &&
            addrlen1 == addrlen2;
    }
    case SYS_clone:
    {
        unsigned long flags1 = orig_args1[0], flags2 = orig_args2[0];
        void *stack1 = (void*)orig_args1[1], *stack2 = (void*)orig_args2[1];
        void *ptid1 = (void*)orig_args1[2], *ptid2 = (void*)orig_args2[2];
        void *ctid1 = (void*)orig_args1[3], *ctid2 = (void*)orig_args2[3];
        void *regs1 = (void*)orig_args1[4], *regs2 = (void*)orig_args2[4];
        return flags1 == flags2 &&
            ((stack1 && stack2) || (!stack1 && !stack2)) &&
            ((ctid1 && ctid2) || (!ctid1 && !ctid2)) &&
            ((ptid1 && ptid2) || (!ptid1 && !ptid2)) &&
            ((regs1 && regs2) || (!regs1 && !regs2));
    }
    /*
    case SYS_fork:
    case SYS_vfork:
    */
    case SYS_execve:
    {
        const char *fn1 = (const char *)arg_data1[0],
                   *fn2 = (const char *)arg_data2[0];
        char **argv1 = (char **)arg_data1[1], **argv2 = (char **)arg_data2[1];
        char **envp1 = (char **)arg_data1[2], **envp2 = (char **)arg_data2[2];
        return !strcmp(fn1, fn2) && compare_str_array(argv1, argv2) &&
            compare_str_array(envp1, envp2);
    }
    case SYS_exit:
    {
        int status1 = orig_args1[0], status2 = orig_args2[0];
        return status1 == status2;
    }
    case SYS_wait4:
    {
        pid_t pid1 = orig_args1[0], pid2 = orig_args2[0];
        /*int *status1 = *args1[1], *status2 = *args2[1];*/
        int options1 = orig_args1[2], options2 = orig_args2[2];
        /*struct rusage *rusage1 = *args1[3], *rusage2 = *args2[3];*/
        return pid1 == pid2 && options1 == options2;
    }
    case SYS_kill:
    {
        pid_t pid1 = orig_args1[0], pid2 = orig_args2[0];
        int sig1 = orig_args1[1], sig2 = orig_args2[1];
        return pid1 == pid2 && sig1 == sig2;
    }
    case SYS_uname:
        /* Nothing to compare. */
        return 1;
    case SYS_semget:
    {
        key_t key1 = orig_args1[0], key2 = orig_args2[0];
        int nsems1 = orig_args1[1], nsems2 = orig_args2[1];
        int flags1 = orig_args1[2], flags2 = orig_args2[2];

        return key1 == key2 && nsems1 == nsems2 && flags1 == flags2;
    }
    case SYS_semop:
    {
        int semid1 = orig_args1[0], semid2 = orig_args2[0];
        struct sembuf *sops1 = (struct sembuf *)arg_data1[1],
                      *sops2 = (struct sembuf *)arg_data2[1];
        size_t nsops1 = orig_args1[2], nsops2 = orig_args2[2];
        return semid1 == semid2 && nsops1 == nsops2 &&
            !memcmp(sops1, sops2, nsops1 * sizeof(struct sembuf));
    }
    case SYS_semctl:
        /* TODO */
        return 1;
    /*
    case SYS_shmdt:
    case SYS_msgget:
    case SYS_msgsnd:
    case SYS_msgrcv:
    case SYS_msgctl:
    */
    case SYS_fcntl:
    {
        unsigned use_arg[] = { F_SETFD, F_SETFL, F_SETLK, F_SETLKW, F_GETLK,
            F_SETOWN, F_GETOWN_EX, F_SETOWN_EX, F_SETSIG, F_SETLEASE, F_NOTIFY,
            F_SETPIPE_SZ };
        unsigned fd1  = orig_args1[0], fd2  = orig_args2[0];
        unsigned cmd1 = orig_args1[1], cmd2 = orig_args2[1];
        unsigned long arg1 = orig_args1[2], arg2 = orig_args2[2];
        for (i = 0; i < sizeof(use_arg) / sizeof(unsigned); i++)
            if (use_arg[i] == cmd1)
            {
                if (arg1 != arg2)
                    return 0;
                break;
            }
        return fd1 == fd2 && cmd1 == cmd2;
    }
    /*
    case SYS_flock:
    case SYS_fsync:
    */
    case SYS_fdatasync:
    {
        unsigned fd1 = orig_args1[0], fd2 = orig_args2[0];
        return fd1 == fd2;
    }
    /*
    case SYS_truncate:
    case SYS_ftruncate:
    */
    case SYS_getdents:
    {
        unsigned fd1 = orig_args1[0], fd2 = orig_args2[0];
        unsigned count1 = orig_args1[2], count2 = orig_args2[2];
        return fd1 == fd2 && count1 == count2;
    }
    case SYS_getcwd:
    {
        unsigned long size1 = orig_args1[1], size2 = orig_args2[1];
        return size1 == size2;
    }
    case SYS_chdir:
    {
        const char *fn1 = (const char *)arg_data1[0],
                   *fn2 = (const char *)arg_data2[0];
        return !strcmp(fn1, fn2);
    }
    case SYS_rename:
    {
        const char *oldname1 = (const char *)arg_data1[0],
                   *oldname2 = (const char *)arg_data2[0];
        const char *newname1 = (const char *)arg_data1[1],
                   *newname2 = (const char *)arg_data2[1];
        return !strcmp(oldname1, oldname2) && !strcmp(newname1, newname2);
    }
    case SYS_mkdir:
    {
        const char *fn1 = (const char *)arg_data1[0],
                   *fn2 = (const char *)arg_data2[0];
        mode_t mode1 = orig_args1[1], mode2 = orig_args2[1];
        return mode1 == mode2 && !strcmp(fn1, fn2);
    }
    case SYS_unlink:
    {
        const char *fn1 = (const char *)arg_data1[0],
                   *fn2 = (const char *)arg_data2[0];
        return !strcmp(fn1, fn2);
    }
    case SYS_readlink:
    {
        const char *path1 = (const char *)arg_data1[0],
                   *path2 = (const char *)arg_data2[0];
        unsigned size1 = orig_args1[2], size2 = orig_args2[2];
        return size1 == size2 && !strcmp(path1, path2);
    }
    case SYS_chmod:
    {
        const char *path1 = (const char *)arg_data1[0],
                   *path2 = (const char *)arg_data2[0];
        mode_t mode1 = orig_args1[1], mode2 = orig_args2[1];
        return mode1 == mode2 && !strcmp(path1, path2);
    }
    case SYS_umask:
    {
        mode_t mask1 = orig_args1[0], mask2 = orig_args2[0];
        return mask1 == mask2;
    }
    case SYS_gettimeofday:
    {
        struct timeval *tv1 = (struct timeval *)orig_args1[0],
                       *tv2 = (struct timeval *)orig_args2[0];
        struct timezone *tz1 = (struct timezone *)orig_args1[0],
                       *tz2 = (struct timezone *)orig_args2[0];
        if ((tv1 && !tv2) || (!tv1 && tv2))
            return 0;
        if ((tz1 && !tz2) || (!tz1 && tz2))
            return 0;
        return 1;
    }
    case SYS_getrlimit:
    {
        int res1 = orig_args1[0], res2 = orig_args2[0];
        /* struct rlimit *rlim1 = (struct rlimit *)orig_args1[1],
                         *rlim2 = (struct rlimit *)orig_args2[1]; */
        return res1 == res2;
    }
    case SYS_getuid:
    case SYS_getgid:
    case SYS_geteuid:
    case SYS_getegid:
    case SYS_getppid:
    case SYS_setsid:
        /* No args */
        return 1;
    case SYS_capget:
    {
        cap_user_header_t hdrp1 = (cap_user_header_t)arg_data1[0],
                          hdrp2 = (cap_user_header_t)arg_data2[0];
        return hdrp1->version == hdrp2->version && hdrp1->pid == hdrp2->pid;

    }
    case SYS_rt_sigtimedwait:
    {
        return 1; /* TODO */
    }
    case SYS_rt_sigsuspend:
    {
        sigset_t *mask1 = (sigset_t *)arg_data1[0],
                 *mask2 = (sigset_t *)arg_data2[0];
        size_t sigsetsize1 = orig_args1[1], sigsetsize2 = orig_args2[1];
        return sigsetsize1 == sigsetsize2 &&
            !memcmp(mask1, mask2, sizeof(sigset_t));
    }
    case SYS_statfs:
    {
        const char *path1 = (const char *)arg_data1[0],
                   *path2 = (const char *)arg_data2[0];
        return !strcmp(path1, path2);
    }
    case SYS_sched_setparam:
    {
        pid_t pid1 = orig_args1[0], pid2 = orig_args2[0];
        struct sched_param *param1 = (struct sched_param *)arg_data1[1],
                           *param2 = (struct sched_param *)arg_data2[1];
        return pid1 == pid2 && param1->sched_priority == param2->sched_priority;
    }
    case SYS_sched_getparam:
    case SYS_sched_getscheduler:
    {
        pid_t pid1 = orig_args1[0], pid2 = orig_args2[0];
        return pid1 == pid2;
    }
    case SYS_sched_get_priority_max:
    case SYS_sched_get_priority_min:
    {
        int policy1 = orig_args1[0], policy2 = orig_args2[0];
        return policy1 == policy2;
    }
    case SYS_prctl:
    {
        int option1 = orig_args1[0], option2 = orig_args2[0];
        unsigned long arg21 = orig_args1[1], arg22 = orig_args2[1];
        unsigned long arg31 = orig_args1[2], arg32 = orig_args2[2];
        unsigned long arg41 = orig_args1[3], arg42 = orig_args2[3];
        return option1 == option2 && arg21 == arg22 && arg31 == arg32 &&
            arg41 == arg42;
    }
    case SYS_arch_prctl:
    {
        int code1 = orig_args1[0], code2 = orig_args2[0];
        /* unsigned long *addr1 = (unsigned long *)orig_args1[1],
                         *addr2 = (unsigned long *)orig_args2[1]; */
        return code1 == code2;
    }
    case SYS_setrlimit:
    {
        int res1 = orig_args1[0], res2 = orig_args2[0];
        const struct rlimit *rlim1 = (void *)arg_data1[1],
                            *rlim2 = (void *)arg_data2[1];
        return res1 == res2 && rlim1->rlim_cur == rlim2->rlim_cur &&
            rlim1->rlim_max == rlim2->rlim_max;
    }
    case SYS_gettid:
        return 1;
    case SYS_getxattr:
    {
        const char *path1 = (const char *)arg_data1[0],
                   *path2 = (const char *)arg_data2[0];
        const char *name1 = (const char *)arg_data1[1],
                   *name2 = (const char *)arg_data2[1];
        unsigned size1 = orig_args1[3], size2 = orig_args2[3];
        return size1 == size2 && !strcmp(path1, path2) && !strcmp(name1, name2);
    }
    case SYS_time:
    {
        time_t *t1 = (time_t *)orig_args1[0], *t2 = (time_t *)orig_args2[0];
        if ((t1 && !t2) || (!t1 && t2))
            return 0;
        return 1;
    }
    case SYS_futex:
    {
        /* int *uaddr1 = (int *)orig_args1[0],
               *uaddr2 = (int *)orig_args2[0]; */
        int op1 = orig_args1[1], op2 = orig_args2[1];
        int val1 = orig_args1[2], val2 = orig_args2[2];
        struct timespec *timeout1 = (struct timespec *)arg_data1[3],
                        *timeout2 = (struct timespec *)arg_data2[3];
        int timeout_o1 = orig_args1[3], timeout_o2 = orig_args2[3];
        /* int *uaddr21 = (int *)orig_args1[4],
               *uaddr22 = (int *)orig_args2[4]; */
        int val31 = orig_args1[5], val32 = orig_args2[5];
        if (op1 != op2)
            return 0;
        switch (op1 & FUTEX_CMD_MASK)
        {
        case FUTEX_WAIT_BITSET:
            /* TODO newer glibc versions pass uninitialized (i.e., random
             * per-variant) data here during initialization (to test whether the
             * system support this syscalls). */
            /*
            if (val31 != val32)
                return 0;
            */
            /* Fallthrough */
        case FUTEX_WAIT:
            if (val1 != val2 ||
                    ((timeout1 && !timeout2) || (!timeout1 && timeout2)))
                return 0;
            if (timeout1 == NULL)
                return 1;
            return timeout1->tv_sec == timeout2->tv_sec &&
                   timeout1->tv_nsec == timeout2->tv_nsec;
        case FUTEX_WAKE:
            return val1 == val2;
        case FUTEX_FD:
            return val1 == val2;
        case FUTEX_REQUEUE:
            return val1 == val2;
        case FUTEX_CMP_REQUEUE:
            return val1 == val2 && val31 == val32;
        case FUTEX_WAKE_OP:
            return val1 == val2 && timeout_o1 == timeout_o2 && val31 == val32;
        default:
            print("cmp: unknown futex op %d\n", op1);
            return 0;
        }
    }
    case SYS_epoll_create:
    {
        int size1 = orig_args1[0], size2 = orig_args2[0];
        return size1 == size2;
    }
    case SYS_set_tid_address:
    {
        /* void *tidptr1 = *args1[0], tidptr2 = *args2[0]; */
        return 1;
    }
    case SYS_fadvise64:
    {
        int fd1        = orig_args1[0], fd2  = orig_args2[0];
        long long off1 = orig_args1[1], off2 = orig_args2[1];
        size_t len1    = orig_args1[2], len2 = orig_args2[2];
        int adv1       = orig_args1[3], adv2 = orig_args2[3];
        return fd1 == fd2 && off1 == off2 && len1 == len2 && adv1 == adv2;
    }
    case SYS_clock_gettime:
    {
        clockid_t clk_id1 = orig_args1[0], clk_id2 = orig_args2[0];
        /* struct timespec *tp1 = (struct timespec *)orig_args1[1],
                           *tp2 = (struct timespec *)orig_args2[1]; */
        return clk_id1 == clk_id2;
    }
    case SYS_exit_group:
    {
        int err1 = orig_args1[0], err2 = orig_args2[0];
        return err1 == err2;
    }
    case SYS_epoll_wait:
    {
        /*
        struct epoll_event *event1 = (struct epoll_event *)orig_args1[1],
                           *event2 = (struct epoll_event *)orig_args2[1];
        */
        int epfd1 = orig_args1[0], epfd2 = orig_args2[0];
        int maxevents1 = orig_args1[2], maxevents2 = orig_args2[2];
        int timeout1 = orig_args1[3], timeout2 = orig_args2[3];
        return epfd1 == epfd2 && maxevents1 == maxevents2 &&
            timeout1 == timeout2;
    }
    case SYS_epoll_ctl:
    {
        int epfd1 = orig_args1[0], epfd2 = orig_args2[0];
        int op1 = orig_args1[1], op2 = orig_args2[1];
        int fd1 = orig_args1[2], fd2 = orig_args2[2];
        struct epoll_event *event1 = (struct epoll_event *)arg_data1[3],
                           *event2 = (struct epoll_event *)arg_data2[3];
        if (epfd1 != epfd2 || op1 != op2 || fd1 != fd2)
            return 0;
        if (op1 == EPOLL_CTL_DEL)
            return 1;
        return event1->events == event2->events;
        /* data can be ptr.
            event1->data.u64 == event2->data.u64;
        */
    }
    case SYS_tgkill:
    {
        int tgid1 = orig_args1[0], tgid2 = orig_args2[0];
        int tid1 = orig_args1[1], tid2 = orig_args2[1];
        int sig1 = orig_args1[2], sig2 = orig_args2[2];
        return tgid1 == tgid2 && tid1 == tid2 && sig1 == sig2;
    }
    case SYS_openat:
    {
        int dfd1 = orig_args1[0], dfd2 = orig_args2[0];
        const char *fn1 = (const char *)arg_data1[1],
                   *fn2 = (const char *)arg_data2[1];
        int flags1 = orig_args1[2], flags2 = orig_args2[2];
        /* Ignored unless O_CREAT or O_TMPFILE */
        int mode1 = orig_args1[3], mode2 = orig_args2[3];
        return dfd1 == dfd2 && !strcmp(fn1, fn2) && flags1 == flags2 &&
            (!((flags1 & O_CREAT) || (flags1 & O_TMPFILE) == O_TMPFILE) ||
                mode1 == mode2);
    }
    case SYS_set_robust_list:
    {
        /* struct robust_list_head
            *head1 = (struct robust_list_head *)arg_data1[0],
            *head2 = (struct robust_list_head *)arg_data2[0]; */
        size_t len1 = orig_args1[1], len2 = orig_args2[1];
        return len1 == len2;
        /*
        if (len1 != len2)
            return 0;
        return memcmp(head1, head2, len1) == 0;
        */
    }
    case SYS_get_robust_list:
    {
        int pid1 = orig_args1[0], pid2 = orig_args2[0];
        /*
        struct robust_list_head **h1 = *(struct robust_list_head ***)args1[1],
                                **h2 = *(struct robust_list_head ***)args2[1];
        size_t *len_ptr1 = *(size_t **)args1[2],
               *len_ptr2 = *(size_t **)args2[2];
        */
        return pid1 == pid2;
    }
    case SYS_accept4:
    {
        int fd1 = orig_args1[0], fd2 = orig_args2[0];
        /*struct sockaddr *addr1 = *(struct sockaddr **)args1[1],
                          *addr2 = *(struct sockaddr **)args2[1]; */
        socklen_t addrlen1 = *(socklen_t *)arg_data1[2],
                  addrlen2 = *(socklen_t *)arg_data2[2];
        int flags1 = orig_args1[3], flags2 = orig_args2[3];
        return fd1 == fd2 && addrlen1 == addrlen2 && flags1 == flags2;
    }
    case SYS_eventfd2:
    {
        unsigned initval1 = orig_args1[0], initval2 = orig_args2[0];
        int flags1 = orig_args1[1], flags2 = orig_args2[1];
        return initval1 == initval2 && flags1 == flags2;
    }
    case SYS_epoll_create1:
    {
        int flags1 = orig_args1[0], flags2 = orig_args2[0];
        return flags1 == flags2;
    }
    case SYS_dup3:
    {
        int oldfd1 = orig_args1[0], oldfd2 = orig_args2[0];
        int newfd1 = orig_args1[1], newfd2 = orig_args2[1];
        int flags1 = orig_args1[2], flags2 = orig_args2[2];
        return oldfd1 == oldfd2 && newfd1 == newfd2 && flags1 == flags2;
    }
    case SYS_pipe2:
    {
        /*
        int *fn1 = (int *)args1[0],
            *fn2 = (int *)args2[0];
        */
        int flags1 = (int)orig_args1[1], flags2 = (int)orig_args2[1];
        return flags1 == flags2;
    }
    case SYSCALL_RDTSC:
        return 1;
    default:
        assert(!"syscall not implemented");
    }

    return 0;
}

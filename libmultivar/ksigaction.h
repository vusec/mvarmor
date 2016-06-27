#ifndef KSIGACTION_H
#define KSIGACTION_H

/*
 * In the normal struct sigaction, as exposed by glibc, the sa_restorer and
 * sa_mask fields are reversed in memory. So, what is sent to the kernel
 * matches the struct below, but it is not available in any include file
 * provided by libc/etc.
 */
struct ksigaction
{
    union
    {
        __sighandler_t ksa_handler;
        void (*ksa_sigaction) (int, siginfo_t *, void *);
    };
    unsigned long ksa_flags;
    void (*ksa_restorer)(void);
    sigset_t ksa_mask;
};

#endif

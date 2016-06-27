#ifndef MV_SHAREDDEFS_H
#define MV_SHAREDDEFS_H

#define MV_LOADER_DONE_SYSCALL    400
#define MV_WHITELIST_PASS_SYSCALL 401
#define MV_WHITELIST_INC_SYSCALL  402
#define MV_WHITELIST_DEC_SYSCALL  403
#define MV_UNWIND_PASS_SYSCALL    500

struct backtrace_info
{
    unsigned long ip, sp, proc_off;
    char proc_name[32];
};

typedef void (*get_backtrace_for_context_t)(ucontext_t *uc,
        struct backtrace_info *bt, size_t bt_len);

#endif

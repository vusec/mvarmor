#ifndef DUNE_UNWIND_USER_H
#define DUNE_UNWIND_USER_H

#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include "mv_user_kernel_shareddefs.h"

/* Function to unwind the stack of userspace, given a context. This is a bit of
 * a hack: we pass the pointer to this function to dune so libdune
 * (kernel-space) can unwind the app (user-space). By using a function from
 * userspace for this, it will use the correct libc and thus the correct libc
 * state such as dl_iterate_phdr. */
void get_backtrace_for_context(unw_context_t *uc, struct backtrace_info *bt,
        size_t bt_len)
{
    unw_cursor_t cursor;
    size_t i = 0;

    unw_init_local(&cursor, uc);
    unw_get_reg(&cursor, UNW_REG_IP, &bt[i].ip);
    unw_get_reg(&cursor, UNW_REG_SP, &bt[i].sp);
    unw_get_proc_name(&cursor, (char *)&bt[i].proc_name, 32, &bt[i].proc_off);
    i++;
    while (unw_step(&cursor) > 0 && i < bt_len - 1)
    {
        unw_get_reg(&cursor, UNW_REG_IP, &bt[i].ip);
        unw_get_reg(&cursor, UNW_REG_SP, &bt[i].sp);
        unw_get_proc_name(&cursor, (char *)&bt[i].proc_name, 32,
                &bt[i].proc_off);
        i++;
    }
    bt[i].ip = 0;
    bt[i].sp = 0;
    bt[i].proc_off = 0;
    bt[i].proc_name[0] = '\0';
}

void pass_backtrace_to_kernel(void)
{
    syscall(MV_UNWIND_PASS_SYSCALL, get_backtrace_for_context);
}

#endif

/*
 * Non-blocking versions of variant and thread synchronization functions (for
 * use in non-blocking mode, e.g., ptrace where there is a single monitor
 * front-end process). The blocking (default) versions are in multivar.c.
 *
 * These functions return a non-zero value if they did not succeed (would have
 * to wait on other variants/threads). In such cases, execution within the
 * back-end stops, and the front-end should wait on other variants/threads to
 * receive events. Optionally, the front-end can be instructed to re-check other
 * variants/functions previously paused.
 */

#include "multivar_internal.h"
#include "proclist.h"

int save_and_compare_nonblocking(mv_thread_t thread,
        struct syscall_args *syscall, struct syscall **syscall_var0)
{
    /* If we had to return before finishing in non-blocking mode due to
     * different syscall orderings between threads, we can skip all the syscall
     * fetch and sync with other vars. */
    if (thread->non_blocking_ret_during_thread_sync_pre)
        return 0;

    /* If we had to return before finishing in non-blocking mode due to mismatch
     * in order in lockstep mode, skip saving/comparing the syscall. */
    if (thread->non_blocking_ret_during_lockstep)
    {
        if (!ringbuffer_check_compared(&thread->ringbuffer))
            return 1;
        thread->non_blocking_ret_during_lockstep = 0;
        return 0;
    }

    /* Case when first calling into monitor for a syscall. Try to claim a spot
     * in the ringbuffer, or find the corresponding item (for leader and
     * follower respectively). Then, save the syscall arguments and compare
     * them. During any of the synchronization stages, the state of the
     * ringbuffer might not be correct, meaning we'd have to wait. Hence, we
     * return with value 1 to indicate we want to exit the monitor. Optionally
     * we set state so we skip parts of this next time. */
    if (thread->proc->variant_num == 0)
    {
        thread->last_syscall = ringbuffer_try_get_new(&thread->ringbuffer);
        if (!thread->last_syscall)
            return 1;

        __sync_add_and_fetch(thread->var_id_pre, 1);
        thread->last_syscall->var_id_pre = *thread->var_id_pre;

        save_args(thread->proc->pid, syscall, thread->last_syscall, alloc_mem,
                realloc_mem);

        thread->last_syscall->is_lockstep = sec_is_unsafe(syscall);
        ringbuffer_mark_saved(&thread->ringbuffer);

        if (thread->last_syscall->is_lockstep)
        {
            /* Lockstep - wait for all followers to perform comparison. */
            if (!ringbuffer_check_compared(&thread->ringbuffer))
            {
                thread->non_blocking_ret_during_lockstep = 1;
                return 1;
            }
        }
    }
    else
    {
        if (thread->last_syscall == NULL)
        {
            thread->last_syscall = alloc_mem_local(sizeof(struct syscall));
            thread->last_syscall->data_area = NULL;
            thread->last_syscall->data_size = 0;
        }
        save_args(thread->proc->pid, syscall, thread->last_syscall,
                alloc_mem_local, realloc_mem_local);
        *syscall_var0 = ringbuffer_try_get_saved(&thread->ringbuffer);
        if (!*syscall_var0)
            return 1;

        compare_syscall_to_var0(thread, *syscall_var0);

        if ((*syscall_var0)->is_lockstep)
        {
            /* Lockstep - say we did the comparison and wait for leader. */
            ringbuffer_mark_compared(&thread->ringbuffer);
            if (!ringbuffer_check_compared(&thread->ringbuffer))
            {
                thread->non_blocking_ret_during_lockstep = 1;
                return 1;
            }
        }
    }

    return 0;
}

int syscall_order_pre_nonblocking(mv_thread_t thread,
        struct syscall *syscall_var0)
{
    if (syscall_var0->var_id_pre != *thread->var_id_pre + 1)
    {
        thread->non_blocking_ret_during_thread_sync_pre = 1;
        return 1;
    }

    __sync_add_and_fetch(thread->var_id_pre, 1);
    thread->last_syscall->var_id_pre = *thread->var_id_pre;

    return 0;
}

int syscall_order_post_nonblocking(mv_thread_t thread,
        struct syscall *syscall_var0)
{
    if (syscall_var0->var_id_post != *thread->var_id_post + 1)
    {
        thread->non_blocking_ret_during_thread_sync_post = 1;
        return 1;
    }

    __sync_add_and_fetch(thread->var_id_post, 1);
    thread->last_syscall->var_id_post = *thread->var_id_post;

    thread->non_blocking_ret_during_thread_sync_post = 0;
    return 0;
}

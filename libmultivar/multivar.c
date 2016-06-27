#include <stdio.h>
#include <sys/syscall.h>

#include "multivar_internal.h"
#include "proclist.h"
#include "ringbuffer.h"

/* print all system calls and their arguments at certain points during
 * execution. Later ones contain more detailed prints (PRE prints only raw
 * arguments instead of more semantic info such as structs, only POST knows
 * return value). */
#define DEBUG_PRINT_PRE 0
#define DEBUG_PRINT_PRE_POSTCOPY 0
#define DEBUG_PRINT_POST 0


unsigned mv_num_variants;
static int non_blocking;

int *mv_aborted_execution HIDDEN = NULL;

print_func_t            print               HIDDEN = NULL;
alloc_mem_func_t        alloc_mem           HIDDEN = NULL;
free_mem_func_t         free_mem            HIDDEN = NULL;
realloc_mem_func_t      realloc_mem         HIDDEN = NULL;
alloc_mem_func_t        alloc_mem_local     HIDDEN = NULL;
free_mem_func_t         free_mem_local      HIDDEN = NULL;
realloc_mem_func_t      realloc_mem_local   HIDDEN = NULL;
copy_from_user_func_t   copy_from_user      HIDDEN = NULL;
copy_to_user_func_t     copy_to_user        HIDDEN = NULL;
backtrace_func_t        show_backtrace      HIDDEN = NULL;

#define CHECK_ABORTED_EXECUTION() \
    do { \
        if (*mv_aborted_execution) \
            return MV_ACTION_ABORT; \
    } while(0)

int mv_init(unsigned num_variants, int non_blocking_,
        struct mv_functions *functions)
{
    int rv;
    mv_num_variants = num_variants;
    non_blocking = non_blocking_;

    print = functions->print;
    alloc_mem = functions->alloc_mem_shared;
    free_mem = functions->free_mem_shared;
    realloc_mem = functions->realloc_mem_shared;
    alloc_mem_local = functions->alloc_mem_local;
    free_mem_local = functions->free_mem_local;
    realloc_mem_local = functions->realloc_mem_local;
    copy_from_user = functions->copy_from_user;
    copy_to_user = functions->copy_to_user;
    show_backtrace = functions->backtrace;

    if (sizeof(struct syscall) % 64)
    {
        print("sizeof(struct syscall) = %zu, but should be multiple of 64\n",
                sizeof(struct syscall));
        assert(!"sizeof(struct syscall) should be multiple of 64");
        return 1;
    }

    if ((rv = proclist_init()))
        return rv;

    if ((rv = ringbuffer_init(num_variants - 1)))
        return rv;

    return 0;
}

void *mv_state_alloc(void)
{
    return proclist_alloc_base();
}

void mv_state_inherit(void *state)
{
    proclist_inherit_base(state);
}

void compare_syscall_to_var0(mv_thread_t thread,
        struct syscall *syscall_var0)
{
    if (unlikely(!compare_args(syscall_var0, thread->last_syscall)))
    {
        print("!!! SYSCALL MISMATCH for p%d t%d "
                "(variants v0 and v%d, vpid %d, vtid %d), "
                "syscalls %u and %u, varid %lu|%lu\n",
                thread->proc->pid, thread->tid, thread->proc->variant_num,
                thread->proc->vpid, thread->vtid, syscall_var0->nr,
                thread->last_syscall->nr, thread->last_syscall->var_id_pre,
                thread->last_syscall->var_id_post);
        syscall_print_saved(syscall_var0, 0, -1, -1);
        syscall_print_saved(thread->last_syscall, thread->proc->variant_num, -1, -1);
        if (show_backtrace)
            show_backtrace(thread->proc->pid);
        mv_abort_execution();
    }
}

static void save_and_compare(mv_thread_t thread, struct syscall_args *syscall,
        struct syscall **syscall_var0)
{
    *syscall_var0 = NULL;
    if (thread->proc->variant_num == 0)
    {
        thread->last_syscall = ringbuffer_get_new(&thread->ringbuffer);

        __sync_add_and_fetch(thread->var_id_pre, 1);
        thread->last_syscall->var_id_pre = *thread->var_id_pre;

        save_args(thread->proc->pid, syscall, thread->last_syscall, alloc_mem,
                realloc_mem);

        thread->last_syscall->is_lockstep = sec_is_unsafe(syscall);
        ringbuffer_mark_saved(&thread->ringbuffer);

        if (thread->last_syscall->is_lockstep)
            ringbuffer_wait_compared(&thread->ringbuffer);
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
        *syscall_var0 = ringbuffer_get_saved(&thread->ringbuffer);

        compare_syscall_to_var0(thread, *syscall_var0);

        if ((*syscall_var0)->is_lockstep)
        {
            ringbuffer_mark_compared(&thread->ringbuffer);
            ringbuffer_wait_compared(&thread->ringbuffer);
        }
    }
}



void syscall_order_pre(mv_thread_t thread, struct syscall *syscall_var0)
{
    register unsigned long expected_id = syscall_var0->var_id_pre;
    register unsigned long *check_id = thread->var_id_pre;
    while (expected_id != *check_id + 1)
        asm volatile("pause\n" ::: "memory");
    __sync_add_and_fetch(thread->var_id_pre, 1);
    thread->last_syscall->var_id_pre = *thread->var_id_pre;
}

void syscall_order_post(mv_thread_t thread, struct syscall *syscall_var0)
{
    register unsigned long expected_id = syscall_var0->var_id_post;
    register unsigned long *check_id = thread->var_id_post;
    while (expected_id != *check_id + 1)
        asm volatile("pause\n" ::: "memory");
    __sync_add_and_fetch(thread->var_id_post, 1);
    thread->last_syscall->var_id_post = *thread->var_id_post;
}

/*
 * Called from the front-end when a syscall is called from the monitored
 * application, but has not yet been executed (i.e., forwarded to the kernel).
 *
 * This function returns actions for the front-end to perform, which can
 * include:
 *  - MV_ACTION_CONTINUE: Continue execution? (always set for blocking mode)
 *  - MV_ACTION_FAKE: Do not forward execution to the kernel, libmv will
 *                    simulate the syscall. Must call mv_syscall_exit
 *                    immidiately afterwards.
 *  - MV_REWRITEARG: Rewrite arguments before passing the syscall along to the
 *                   kernel. Use mv_thread_getrewriteargs to get the arguments
 *                   and values to be rewritten.
 *  For non-blocking mode only:
 *  - MV_ACTION_WAKE_VARS: Wake (i.e., retry) other variants.
 *  - MV_ACTION_WAKE_THREADS: Wake (i.e., retry) other threads in the same
 *                            variant as this thread is from. Used for syscall
 *                            ordering of followers.
 */
int mv_syscall_enter(mv_thread_t thread, struct syscall_args *syscall)
{
    struct syscall *syscall_var0 = NULL;

    CHECK_ABORTED_EXECUTION();

    assert(thread);
    if (thread->syscall_entered)
    {
        print("ERR T%d\n", thread->tid);
        syscall_print_args(syscall, thread->tid);
        assert(!thread->syscall_entered);
    }

#if DEBUG_PRINT_PRE
    syscall_print_args(syscall, thread->tid);
#endif

    if (sec_is_safe(syscall))
    {
        thread->actions_pre = MV_ACTION_CONTINUE | MV_ACTION_SAFE;
        return thread->actions_pre;
    }

    thread->actions_pre = 0;
    if (unlikely(non_blocking)) /* e.g., ptrace */
    {
        if (save_and_compare_nonblocking(thread, syscall, &syscall_var0))
        {
            if (thread->waiting_othervar)
                return 0;
            thread->waiting_othervar = 1;
            return MV_ACTION_WAKE_VARS;
        }
        thread->waiting_othervar = 0;
    }
    else
        save_and_compare(thread, syscall, &syscall_var0);

    CHECK_ABORTED_EXECUTION();

#if SYSCALL_ORDERING
    if (thread->proc->variant_num > 0)
    {
        if (syscall_var0 == NULL)
            syscall_var0 = ringbuffer_get_prev(&thread->ringbuffer);

        if (unlikely(non_blocking))
        {
            if (syscall_order_pre_nonblocking(thread, syscall_var0))
            {

                thread->waiting_otherthread = 1;
                return MV_ACTION_WAKE_THREADS;
            }
            thread->waiting_otherthread = 0;
        }
        else
            syscall_order_pre(thread, syscall_var0);
    }
#endif

    thread->non_blocking_ret_during_thread_sync_pre = 0;
    thread->syscall_entered = 1;
    if (thread->proc->variant_num > 0)
        thread->last_syscall->var_id_pre = syscall_var0->var_id_pre;

#if DEBUG_PRINT_PRE_POSTCOPY
    syscall_print_saved(thread->last_syscall, thread->tid, -1, -1);
#endif

    syscall_pre(thread, thread->last_syscall, syscall_var0);

    /* HACK for exit(group) syscalls */
    if (thread->last_syscall->nr == SYS_exit_group ||
        thread->last_syscall->nr == SYS_exit)
    {
        if (thread->proc->variant_num == 0)
            ringbuffer_mark_result(&thread->ringbuffer);
    }

    CHECK_ABORTED_EXECUTION();

    return thread->actions_pre;
}

/*
 * Called from the front-end when a syscall is finished executing: either it has
 * been forwarded to the real kernel, emulated by the front-end, or the return
 * value from mv_syscall_enter included FAKE. In case of the latter this
 * function will emulate the operation of the syscall (e.g., copy results from
 * the leader).
 *
 * This function returns actions for the front-end to perform, which can
 * include:
 *  - MV_ACTION_CONTINUE: Continue execution? (always set for blocking mode)
 *  - MV_ACTION_FAKE: Use the fake return value as set in the provided fake_rv.
 *  For non-blocking mode only:
 *  - MV_ACTION_WAKE_VARS: Wake (i.e., retry) other variants.
 *  - MV_ACTION_WAKE_THREADS: Wake (i.e., retry) other threads in the same
 *                            variant as this thread is from. Used for syscall
 *                            ordering of followers.
 */
int mv_syscall_exit(mv_thread_t thread, long rv, long *fake_rv)
{
    struct syscall *syscall_var0;
    assert(thread);
    assert(thread->syscall_entered);
    assert(thread->last_syscall);

    CHECK_ABORTED_EXECUTION();

    if (thread->proc->variant_num == 0)
        syscall_var0 = thread->last_syscall;
    else
    {
        syscall_var0 = ringbuffer_get_prev(&thread->ringbuffer);
        if (unlikely(non_blocking))
        {
            if (!ringbuffer_check_result(&thread->ringbuffer))
            {
                if (thread->waiting_othervar)
                    return 0;
                thread->waiting_othervar = 1;
                return MV_ACTION_WAKE_VARS;
            }
            thread->waiting_othervar = 0;
        }
        else
            ringbuffer_wait_result(&thread->ringbuffer);
    }

    thread->last_syscall->rv = rv;

    if (likely(!thread->non_blocking_ret_during_thread_sync_post))
        syscall_post(thread, thread->last_syscall, syscall_var0);

    if (thread->proc->variant_num == 0)
    {
        __sync_add_and_fetch(thread->var_id_post, 1);
        thread->last_syscall->var_id_post = *thread->var_id_post;
        ringbuffer_mark_result(&thread->ringbuffer);
    }
    else
    {
        thread->last_syscall->var_id_post = syscall_var0->var_id_post;
#if SYSCALL_ORDERING
        if (unlikely(non_blocking))
        {
            if (syscall_order_post_nonblocking(thread, syscall_var0))
            {
                thread->waiting_otherthread = 1;
                return MV_ACTION_WAKE_THREADS;
            }
            thread->waiting_otherthread = 0;
        }
        else
            syscall_order_post(thread, syscall_var0);
#endif
        ringbuffer_mark_complete(&thread->ringbuffer);
    }

    thread->syscall_entered = 0;
    *fake_rv = thread->last_syscall->fake_rv;

#if DEBUG_PRINT_POST
    if (thread->actions_post & MV_ACTION_FAKE)
        syscall_print_saved(thread->last_syscall, thread->tid, *fake_rv, rv);
    else
        syscall_print_saved(thread->last_syscall, thread->tid, rv, rv);
#endif

    CHECK_ABORTED_EXECUTION();

    return thread->actions_post;
}

int mv_rdtsc(mv_thread_t thread, unsigned long *ret_cycles)
{
    struct syscall_args syscall;
    register unsigned _a, _d;
    unsigned long cycles;
    int post_actions;
    syscall.nr = SYSCALL_RDTSC;
    mv_syscall_enter(thread, &syscall);
    __asm__ __volatile__ (
            "rdtsc \n\t"
            : "=a"(_a), "=d"(_d));
    cycles = (long)(((uint64_t)_d << 32) | _a);
    post_actions = mv_syscall_exit(thread, cycles, (long*)ret_cycles);
    if ((post_actions & MV_ACTION_FAKE) == 0)
        *ret_cycles = cycles;
    return 0;
}

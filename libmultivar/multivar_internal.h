#ifndef MULTIVAR_INTERNAL_H
#define MULTIVAR_INTERNAL_H

#include "multivar.h"

#ifndef ENABLE_ASSERT
#define ENABLE_ASSERT 1
#endif

/* Assert that bypasses libc. */
#ifndef assert
#if ENABLE_ASSERT
#define assert(expr) \
    do { \
        if (!(expr)) { \
            print("ASSERT(" #expr ") at %s:%d in function %s\n", \
                    __FILE__, __LINE__, __func__); \
            asm volatile("movq $60, %rax\n" \
                    "vmcall\n");\
        } \
    } while (0)
#else /* ENABLE_ASSERT */
#define assert(expr) \
    do {\
    } while (0)
#endif
#endif

#ifndef likely
# define likely(x)  __builtin_expect((!!(x)),1)
#endif
#ifndef unlikely
# define unlikely(x)    __builtin_expect((!!(x)),0)
#endif

#define HIDDEN __attribute__ ((visibility ("hidden")))

/* Internally used syscall representation - contains saved arguments etc. */
struct syscall
{
    unsigned nr;
    uint64_t orig_args[6]; /* Arguments to syscall (raw values registers). */
    uint64_t *arg_data[6]; /* Local pointer to copied data (or NULL). */
    long rv, fake_rv;
    void *data_area, *ret_area;
    size_t data_size, ret_size;
    unsigned long var_id_pre, var_id_post; /* For syscall ordering */

    /* Ringbuffer entry data */
    unsigned rb_completed, rb_compared;
    int rb_sleeping; /* Fed to futex so must be (size of) int */
    char rb_has_saved, rb_has_result;
    char is_lockstep;

    char padding[8]; /* Fit exactly in cachelines to prevent false sharing. */
};

/* Defined in multivar.c, passed from user in mv_functions struct. */
extern print_func_t             print               HIDDEN;
extern alloc_mem_func_t         alloc_mem           HIDDEN;
extern free_mem_func_t          free_mem            HIDDEN;
extern realloc_mem_func_t       realloc_mem         HIDDEN;
extern alloc_mem_func_t         alloc_mem_local     HIDDEN;
extern free_mem_func_t          free_mem_local      HIDDEN;
extern realloc_mem_func_t       realloc_mem_local   HIDDEN;
extern copy_from_user_func_t    copy_from_user      HIDDEN;
extern copy_to_user_func_t      copy_to_user        HIDDEN;
extern backtrace_func_t         show_backtrace      HIDDEN;

extern int *mv_aborted_execution HIDDEN;

/* Some events we monitor are not syscalls per-se, but we treat them the same
 * internally. These numbers are used as syscall number values for such fake
 * events. */
#define SYSCALL_RDTSC 500

/* Type of system calls (as specified further in syscall_types.c. */
#define TODO 0
#define FAKE 1
#define ONE  2
#define ALL  3

/* debugging.c */
void syscall_print_args(struct syscall_args *syscall, pid_t pid);
void syscall_print_saved(struct syscall *syscall, pid_t pid, long rv, long orig_rv);

/* save_args.c */
void save_args(pid_t pid, struct syscall_args *syscall,
        struct syscall *syscall_save, alloc_mem_func_t alloc_mem,
        realloc_mem_func_t realloc_mem);

/* compare_args.c */
int compare_args(struct syscall *syscall1, struct syscall *syscall2);

/* syscall_types.c */
extern char syscall_type[];
int syscall_type_is_one_to_all(mv_thread_t thread, struct syscall *syscall,
        struct syscall *syscall0);

/* syscall_pre.c */
void syscall_pre(mv_thread_t thread, struct syscall *syscall,
        struct syscall *syscall0);

/* syscall_post.c */
void syscall_post(mv_thread_t thread, struct syscall *syscall,
        struct syscall *syscall0);

/* security.c */
int sec_is_safe(struct syscall_args *syscall);
int sec_is_unsafe(struct syscall_args *syscall);

/* multivar.c */
void compare_syscall_to_var0(mv_thread_t thread, struct syscall *syscall_var0);

/* multivar_sync_nonblocking.c */
int save_and_compare_nonblocking(mv_thread_t thread,
        struct syscall_args *syscall, struct syscall **syscall_var0);
int syscall_order_pre_nonblocking(mv_thread_t thread,
        struct syscall *syscall_var0);
int syscall_order_post_nonblocking(mv_thread_t thread,
        struct syscall *syscall_var0);

#endif

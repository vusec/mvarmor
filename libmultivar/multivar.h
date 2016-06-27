#ifndef MULTIVAR_H
#define MULTIVAR_H

#include <stdint.h>
#include <unistd.h>

/* Information about a system call - contians the syscall number and all
 * argument registers (regardless of which ones are actually used by the system
 * call).
 */
struct syscall_args
{
    unsigned nr;
    uint64_t orig_args[6];

};

typedef struct variant_thread *mv_thread_t;

/* libmv needs a number of function pointers during initialization to know eg
 * how to access the address space of the monitored process or how to allocate
 * memory.
 */
typedef void *(*alloc_mem_func_t)(size_t size);
typedef void (*free_mem_func_t)(void *ptr);
typedef void *(*realloc_mem_func_t)(void *ptr, size_t size, size_t old_size);
typedef void *(*copy_from_user_func_t)(pid_t pid, void *dest, void *src,
        size_t size);
typedef void *(*copy_to_user_func_t)(pid_t pid, void *dest, void *src,
        size_t size);
typedef int (*print_func_t)(const char *fmt, ...);
typedef void (*backtrace_func_t)(pid_t pid);

struct mv_functions
{
    /* Manage memory visible to all monitors. */
    alloc_mem_func_t alloc_mem_shared;
    free_mem_func_t free_mem_shared;
    realloc_mem_func_t realloc_mem_shared;

    /* Manage memory only visible locally to the calling monitor. */
    alloc_mem_func_t alloc_mem_local;
    free_mem_func_t free_mem_local;
    realloc_mem_func_t realloc_mem_local;

    /* How to access the memory of the monitored application. */
    copy_from_user_func_t copy_from_user;
    copy_to_user_func_t copy_to_user;

    /* How to print to stdout/stderr/logfile, for debug and errors. */
    print_func_t print;

    /* Print backtrace information from the monitored process. */
    backtrace_func_t backtrace;
};

/* Bit-flags returned by enter/exit to indicate what action the monitor should
 * take.
 */
#define MV_ACTION_CONTINUE      (1 << 0)
#define MV_ACTION_FAKE          (1 << 1)
#define MV_ACTION_REWRITEARG    (1 << 2)
#define MV_ACTION_SAFE          (1 << 3)
#define MV_ACTION_WAKE_VARS     (1 << 4)
#define MV_ACTION_WAKE_THREADS  (1 << 5)
#define MV_ACTION_ABORT         (1 << 6)

extern unsigned mv_num_variants;

int mv_init(unsigned num_variants, int non_blocking,
        struct mv_functions *functions);

/* To preserve monitor state across exec's. */
void *mv_state_alloc(void);
void mv_state_inherit(void *state);

/* Called for every system call on entry (immidiately after call, before passing
 * to kernel) and exit (after execution in kernel or after enter returned FAKE).
 */
int mv_syscall_enter(mv_thread_t thread, struct syscall_args *syscall);
int mv_syscall_exit(mv_thread_t thread, long rv, long *fake_rv);

int mv_rdtsc(mv_thread_t thread, unsigned long *ret_cycles);

/* Management of threads, processes and variants. */
int mv_proc_new(pid_t pid, pid_t ptid, int var_num);
int mv_proc_exit(pid_t pid);
mv_thread_t mv_thread_new(pid_t tid, pid_t pid, pid_t ptid);
int mv_thread_exit(mv_thread_t thread);
mv_thread_t mv_thread_get(pid_t tid);
mv_thread_t mv_thread_get_wait(pid_t tid);
int mv_thread_in_syscall(mv_thread_t thread);
int mv_proc_varpids(pid_t pid, pid_t *buf);
int mv_thread_vartids(pid_t pid, pid_t *buf);
int mv_var_tids(unsigned var_num, pid_t *buf, size_t buf_size);
int mv_var_tids_by_thread(mv_thread_t thread, pid_t *buf, size_t buf_size);
int mv_waiting_var_tids_by_thread(mv_thread_t thread, pid_t *buf);
int mv_waiting_thread_tids_by_thread(mv_thread_t thread, pid_t *buf,
        size_t buf_size);
pid_t mv_proc_var0_pid(pid_t pid);
int mv_thread_getrewriteargs(mv_thread_t thread, char *mask[6],
        unsigned long *vals[6]);
long mv_thread_getlastsyscall(mv_thread_t thread);
pid_t mv_proc_getvpid(pid_t pid);
pid_t mv_thread_getvtid(mv_thread_t thread);
pid_t mv_thread_getpgid(mv_thread_t thread);
pid_t mv_thread_getvpid(mv_thread_t thread);
pid_t mv_thread_gettid(mv_thread_t thread);
void mv_abort_execution(void);

#endif

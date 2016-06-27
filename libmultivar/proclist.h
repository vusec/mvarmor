#ifndef PROCLIST_H
#define PROCLIST_H

#include "ringbuffer.h"

struct variant;

struct fd
{
    int real_fd;
    int close_on_exec:1;
};

/* Keep track of the data set per-process for every fd registered to epoll. The
 * program could dump pointers in here which are only valid to that process. */
struct mv_epoll_data
{
    int epfd;
    int fd;
    uint64_t data;
};

typedef struct variant_thread
{
    struct variant_thread *next;
    struct variant_proc *proc;

    pid_t tid, vtid;
    int actions_pre, actions_post;
    struct syscall *last_syscall;
    char syscall_entered:1;
    char waiting_othervar:1; /* Waiting on (matching) tid in other var. */
    char waiting_otherthread:1; /* Waiting on other tid in same var. */
    char non_blocking_ret_during_lockstep:1;
    char non_blocking_ret_during_thread_sync_pre:1;
    char non_blocking_ret_during_thread_sync_post:1;
    int num_children;
    unsigned long *var_id_pre, *var_id_post;

    struct ringbuffer ringbuffer;
    char rewriteargs_mask[6];
    unsigned long rewriteargs_vals[6];
} variant_thread_t;

typedef struct variant_proc
{
    pid_t pid, ppid, vpid, vppid;
    struct variant_proc *next;
    struct variant *variant;
    struct variant_thread *threads;
    int variant_num;

    void *userdata;

    struct fd *fds;
    struct mv_epoll_data *epoll_data;
    size_t fds_size, epoll_data_size;
} variant_proc_t;

typedef struct variant
{
    variant_proc_t *procs;
    /* Per-variant for ordering. */
    unsigned long last_syscall_id_pre, last_syscall_id_post;
    unsigned num;
    char padding[36];
} variant_t;

/* Public interface */
int mv_proc_new(pid_t pid, pid_t ptid, int var_num);
int mv_proc_exit(pid_t pid);
variant_thread_t *mv_thread_new(pid_t tid, pid_t pid, pid_t ptid);
int mv_thread_exit(variant_thread_t *thread);
variant_thread_t *mv_thread_get(pid_t tid);
variant_thread_t *mv_thread_get_wait(pid_t tid);
int mv_thread_in_syscall(variant_thread_t *thread);
int mv_proc_varpids(pid_t pid, pid_t *buf);
int mv_thread_vartids(pid_t pid, pid_t *buf);
int mv_var_tids(unsigned var_num, pid_t *buf, size_t buf_size);
int mv_var_tids_by_thread(variant_thread_t *thread, pid_t *buf,
        size_t buf_size);
int mv_waiting_var_tids_by_thread(variant_thread_t *thread, pid_t *buf);
int mv_waiting_thread_tids_by_thread(variant_thread_t *thread, pid_t *buf,
        size_t buf_size);
pid_t mv_proc_var0_pid(pid_t pid);
int mv_thread_getrewriteargs(variant_thread_t *thread, char *mask[6],
        unsigned long *vals[6]);
long mv_thread_getlastsyscall(variant_thread_t *thread);
pid_t mv_proc_getvpid(pid_t pid);
pid_t mv_thread_getvtid(mv_thread_t thread);
pid_t mv_thread_getpgid(mv_thread_t thread);
pid_t mv_thread_getvpid(mv_thread_t thread);
pid_t mv_thread_gettid(mv_thread_t thread);

void mv_proc_userdata_set(pid_t pid, void *data);
void *mv_proc_userdata_get(pid_t pid);
void mv_proc_userdata_get_var(pid_t pid, void **buf);

void mv_abort_execution(void);

/* Internal functions */
int proclist_init(void);
void *proclist_alloc_base(void);
void proclist_inherit_base(void *base);
variant_proc_t *find_proc_in_list(variant_proc_t *list, pid_t pid);
variant_thread_t *find_thread_in_list(variant_proc_t *list, pid_t tid);
variant_proc_t *find_proc_in_list_by_vpid(variant_proc_t *list, pid_t fpid);
variant_thread_t *find_thread_in_list_by_vtid(variant_proc_t *list, pid_t vtid);
variant_proc_t *add_proc_to_list(variant_proc_t **list, variant_proc_t *proc);
variant_proc_t *new_proc(pid_t pid, pid_t ppid, pid_t vpid);
variant_proc_t *find_proc(pid_t pid);
variant_thread_t *find_thread(pid_t tid);
variant_thread_t *find_thread_in_proc(variant_proc_t *proc, pid_t tid);
variant_thread_t *find_thread_in_proc_by_vtid(variant_proc_t *proc, pid_t vtid);
int find_procs_by_vpid(pid_t vpid, variant_proc_t **buf);
int find_threads_by_vtid(pid_t vtid, variant_thread_t **buf);
pid_t find_pid_by_vpid(variant_proc_t *proc, pid_t vpid);
variant_t *find_proc_variant(pid_t pid);
variant_t *find_empty_variant(void);
variant_proc_t *pop_proc_from_list(variant_proc_t **list, pid_t pid);

void thread_rewriteargs_clear(variant_thread_t *proc);
void thread_rewriteargs_add(variant_thread_t *proc, unsigned arg,
        unsigned long val);

void fd_add(variant_proc_t *proc, int rfd, int ffd);
void fd_rm(variant_proc_t *proc, int ffd);
int fd_get(variant_proc_t *proc, int ffd);

void epoll_data_add(variant_proc_t *proc, int epfd, int fd, uint64_t data);
void epoll_data_mod(variant_proc_t *proc, int epfd, int fd, uint64_t data);
void epoll_data_rm(variant_proc_t *proc, int epfd, int fd);
void epoll_data_close_fd(variant_proc_t *proc, int fd);
uint64_t epoll_data_get(variant_proc_t *proc, int epfd, int fd);
int epoll_data_to_fd(variant_proc_t *proc, int epfd, uint64_t data);

pid_t vtid_generate(variant_thread_t *pproc);
void thread_increase_childcount(variant_thread_t *proc);

/* Internal debugging */
void print_list(variant_proc_t *list);
void print_lists(void);

#endif

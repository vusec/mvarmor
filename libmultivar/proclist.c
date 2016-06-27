/*
 * proclist.c - Administration of processes in variants.
 *
 * Every variant has a number of processes in a linked list.
 * Every process has one or more threads (where one will have the same tid as
 * the process' pid).
 * Every process and thread has a unique pid/tid (as assigned by the kernel) and
 * a virtual pid/tid.
 * Virtual pids (vpids) are unique per variant, but shared among variants. That
 * is, equivalent processes among variants (e.g. all first processes, all second
 * processes, ...) share the same vpid. vpids are used to compare the behavior
 * among variants: all processes having the same vpid should have identical
 * behavior.
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <syscall.h>

#include "multivar_internal.h"
#include "proclist.h"

static variant_t *variants;
static int proclist_is_locked;

#define MAX_PROCS_PER_VAR 100
#define MAX_CHILDS_PER_PROC 20

struct vpid_data
{
    pid_t vpid_map[MAX_PROCS_PER_VAR][MAX_CHILDS_PER_PROC];
    pid_t last_pid;
};
static struct vpid_data *vpid_data;
static void **ringbuffers_data;

/* Returned to user so another process can attach to this instance. Used for
 * shared mem across exec calls.
 */
struct admin_base
{
    variant_t *variants;
    struct vpid_data *vpid_data;
    void **ringbuffers_data;
    int abort_execution;
};

void proclist_lock(void)
{
    while (!__sync_bool_compare_and_swap(&proclist_is_locked, 0, 1))
        asm volatile ("pause\n" ::: "memory");
}

void proclist_unlock(void)
{
    char succes = __sync_bool_compare_and_swap(&proclist_is_locked, 1, 0);
    if (!succes)
        print("Proclist locking error!!\n");
    assert(succes);
}

variant_proc_t *find_proc_in_list(variant_proc_t *list, pid_t pid)
{
    variant_proc_t *p = list;
    if (!p)
        return NULL;
    do
    {
        if (p->pid == pid)
            return p;
    } while ((p = p->next));
    return NULL;
}

variant_thread_t *find_thread_in_list(variant_proc_t *list, pid_t tid)
{
    variant_thread_t *t;
    variant_proc_t *p = list;
    if (!p)
        return NULL;
    do
    {
        if ((t = find_thread_in_proc(p, tid)))
            return t;
    } while ((p = p->next));
    return NULL;
}

variant_proc_t *find_proc_in_list_by_vpid(variant_proc_t *list, pid_t vpid)
{
    variant_proc_t *p = list;
    if (!p)
        return NULL;
    do
    {
        if (p->vpid == vpid)
            return p;
    } while ((p = p->next));
    return NULL;
}

variant_thread_t *find_thread_in_list_by_vtid(variant_proc_t *list, pid_t vtid)
{
    variant_thread_t *t;
    variant_proc_t *p = list;
    if (!p)
        return NULL;
    do
    {
        if ((t = find_thread_in_proc_by_vtid(p, vtid)))
            return t;
    } while ((p = p->next));
    return NULL;
}

variant_proc_t *add_proc_to_list(variant_proc_t **list, variant_proc_t *proc)
{
    if (*list == NULL)
        *list = proc;
    else
    {
        variant_proc_t *p = *list;
        while (p->next)
            p = p->next;
        p->next = proc;
    }
    return proc;
}

/*
 * Allocated a new proc object and initializes it to be empty.
 */
variant_proc_t *new_proc(pid_t pid, pid_t ptid, pid_t vpid)
{
    unsigned i;
    variant_proc_t *proc, *pproc;
    pproc = NULL;
    if (ptid != -1)
        pproc = find_thread(ptid)->proc;
    proc = alloc_mem(sizeof(variant_proc_t));
    assert(proc);
    proc->pid = pid;
    proc->ppid = pproc ? pproc->pid : -1;
    proc->vpid = vpid;
    proc->vppid = pproc ? pproc->vpid : -1;
    proc->next = NULL;
    proc->variant = NULL;
    proc->variant_num = -1;
    proc->userdata = NULL;
    proc->threads = NULL;

    if (pproc)
    {
        proc->fds_size = pproc->fds_size;
        proc->epoll_data_size = pproc->epoll_data_size;
    }
    else
    {
        proc->fds_size = 128;
        proc->epoll_data_size = 128;
    }
    proc->fds = alloc_mem(proc->fds_size * sizeof(struct fd));
    proc->epoll_data = alloc_mem(proc->epoll_data_size *
            sizeof(struct mv_epoll_data));
    if (pproc)
    {
        for (i = 0; i < proc->fds_size; i++)
        {
            proc->fds[i].real_fd = pproc->fds[i].real_fd;
            proc->fds[i].close_on_exec = pproc->fds[i].close_on_exec;
        }
        for (i = 0; i < proc->epoll_data_size; i++)
        {
            proc->epoll_data[i].epfd = pproc->epoll_data[i].epfd;
            proc->epoll_data[i].fd = pproc->epoll_data[i].fd;
            proc->epoll_data[i].data = pproc->epoll_data[i].data;
        }
    }
    else
    {
        for (i = 0; i < proc->fds_size; i++)
            proc->fds[i].real_fd = -1;
        for (i = 0; i < proc->epoll_data_size; i++)
        {
            proc->epoll_data[i].epfd = -1;
            proc->epoll_data[i].fd = -1;
        }
    }


    return proc;
}

/*
 * Allocated a new thread object and initializes it to be empty.
 */
variant_thread_t *new_thread(pid_t tid, pid_t vtid)
{
    variant_thread_t *thread;
    thread = alloc_mem(sizeof(variant_thread_t));
    assert(thread);
    thread->tid = tid;
    thread->vtid = vtid;
    thread->next = NULL;
    thread->proc = NULL;
    thread->syscall_entered = 0;
    thread->waiting_othervar = 0;
    thread->waiting_otherthread = 0;
    thread->non_blocking_ret_during_lockstep = 0;
    thread->non_blocking_ret_during_thread_sync_pre = 0;
    thread->non_blocking_ret_during_thread_sync_post = 0;
    thread->last_syscall = NULL;
    thread->actions_pre = 0;
    thread->actions_post = 0;
    thread->num_children = 0;
    thread->var_id_pre = NULL;
    thread->var_id_post = NULL;

    thread_rewriteargs_clear(thread);

    return thread;
}

variant_proc_t *find_proc(pid_t pid)
{
    unsigned i;
    variant_proc_t *p;
    for (i = 0; i < mv_num_variants; i++)
        if ((p = find_proc_in_list(variants[i].procs, pid)))
            return p;
    return NULL;
}

variant_thread_t *find_thread(pid_t tid)
{
    unsigned i;
    variant_thread_t *p;
    for (i = 0; i < mv_num_variants; i++)
        if ((p = find_thread_in_list(variants[i].procs, tid)))
            return p;
    return NULL;
}

int find_procs_by_vpid(pid_t vpid, variant_proc_t **buf)
{
    int ret = 1;
    unsigned i;
    for (i = 0; i < mv_num_variants; i++)
    {
        buf[i] = find_proc_in_list_by_vpid(variants[i].procs, vpid);
        if (buf[i] == NULL)
            ret = 0;
    }
    return ret;
}

int find_threads_by_vtid(pid_t vtid, variant_thread_t **buf)
{
    int ret = 1;
    unsigned i;
    for (i = 0; i < mv_num_variants; i++)
    {
        buf[i] = find_thread_in_list_by_vtid(variants[i].procs, vtid);
        if (buf[i] == NULL)
            ret = 0;
    }
    return ret;
}

pid_t find_pid_by_vpid(variant_proc_t *proc, pid_t vpid)
{
    variant_proc_t *vpid_proc;
    assert(proc);
    vpid_proc = find_proc_in_list_by_vpid(proc->variant->procs, vpid);
    assert(vpid_proc);
    return vpid_proc->pid;
}

variant_t *find_proc_variant(pid_t pid)
{
    unsigned i;
    for (i = 0; i < mv_num_variants; i++)
        if (find_proc_in_list(variants[i].procs, pid))
            return &variants[i];
    return NULL;
}

variant_t *find_empty_variant(void)
{
    unsigned i;
    for (i = 0; i < mv_num_variants; i++)
        if (variants[i].procs == NULL)
            return &variants[i];
    return NULL;
}

variant_thread_t *find_thread_in_proc(variant_proc_t *proc, pid_t tid)
{
    variant_thread_t *t;
    assert(proc);
    t = proc->threads;
    while (t)
    {
        if (t->tid == tid)
            return t;
        t = t->next;
    }
    return NULL;
}

variant_thread_t *find_thread_in_proc_by_vtid(variant_proc_t *proc, pid_t vtid)
{
    variant_thread_t *t;
    assert(proc);
    t = proc->threads;
    while (t)
    {
        if (t->vtid == vtid)
            return t;
        t = t->next;
    }
    return NULL;
}

variant_proc_t *pop_proc_from_list(variant_proc_t **list, pid_t pid)
{
    variant_proc_t *p = *list, *prev = *list;
    if (!p)
        return NULL;
    if (p->pid == pid)
    {
        *list = p->next;
        p->next = NULL;
        return p;
    }
    while ((p = p->next))
    {
        if (p->pid == pid)
        {
            prev->next = p->next;
            p->next = NULL;
            return p;
        }
        prev = p;
    }
    return NULL;
}

void print_list(variant_proc_t *list)
{
    variant_proc_t *p = list;
    print("List: ");
    if (!p)
    {
        print("<empty>\n");
        return;
    }
    do
    {
        print("%d, ", p->pid);
    } while ((p = p->next));
    print("\n");
}

void print_lists(void)
{
    unsigned i;
    for (i = 0; i < mv_num_variants; i++)
    {
        print("variant %d: ", i);
        print_list(variants[i].procs);
    }
}


int proclist_init(void)
{
    proclist_is_locked = 0;
    return 0;
}

void *proclist_alloc_base(void)
{
    unsigned i, j;
    struct admin_base *ret;

    variants = alloc_mem(sizeof(variant_t) * mv_num_variants);
    for (i = 0; i < mv_num_variants; i++)
    {
        variants[i].num = i;
        variants[i].procs = NULL;
        variants[i].last_syscall_id_pre = 0;
        variants[i].last_syscall_id_post = 0;
    }

    ringbuffers_data = alloc_mem(sizeof(void *) * MAX_PROCS_PER_VAR);
    vpid_data = alloc_mem(sizeof(struct vpid_data));
    vpid_data->last_pid = 1;
    for (i = 0; i < MAX_PROCS_PER_VAR; i++)
    {
        for (j = 0; j < MAX_CHILDS_PER_PROC; j++)
            vpid_data->vpid_map[i][j] = -1;
        ringbuffers_data[i] = NULL;
    }

    ret = alloc_mem(sizeof(struct admin_base));
    ret->variants = variants;
    ret->ringbuffers_data = ringbuffers_data;
    ret->vpid_data = vpid_data;
    ret->abort_execution = 0;

    mv_aborted_execution = &ret->abort_execution;

    return ret;
}

void proclist_inherit_base(void *base)
{
    struct admin_base *b = base;
    variants = b->variants;
    ringbuffers_data = b->ringbuffers_data;
    vpid_data = b->vpid_data;
    mv_aborted_execution = &b->abort_execution;
}

/*
 * Registers a new process with a certain parent. If the parent pid is -1 then
 * this process is the first one of a variant (during startup). If this is the
 * case, the proc will be assigned to variant var_num, unless it is -1 (in which
 * case the first empty variant will be used). If the process is not a new
 * variant var_num is ignored.
 */
int mv_proc_new(pid_t pid, pid_t ptid, int var_num)
{
    variant_t *var = NULL;
    variant_proc_t *proc = NULL;
    variant_thread_t *pthread = NULL;
    pid_t vpid;

    if (find_proc(pid))
    {
        print("proc %d already exists\n", pid);
        return 1;
    }

    if (ptid != -1 && !find_thread(ptid))
    {
        print("Parent thread %d %x does not exist\n", ptid, ptid);
        return 1;
    }

    if (ptid == -1)
    {
        if (var_num != -1)
        {
            if (variants[var_num].procs)
            {
                print("New var %d (pid %d) already has procs!\n", var_num, pid);
                return 1;
            }
            var = &variants[var_num];
        }
        else if (!(var = find_empty_variant()))
        {
            print("No empty variants left for proc %d\n", pid);
            return 1;
        }
    }
    else
    {
        pthread = find_thread(ptid);
        var = pthread->proc->variant;
    }

    vpid = ptid == -1 ? 1 : vtid_generate(pthread);
    proc = new_proc(pid, ptid, vpid);

    assert(var);
    assert(proc);

    add_proc_to_list(&var->procs, proc);
    proc->variant = var;
    proc->variant_num = var->num;


    print("New proc %d in var %d (ptid %d, vpid %d)\n", pid, var->num, ptid,
            proc->vpid);

    return 0;
}

/*
 * Should be called when a process exits.
 */
int mv_proc_exit(pid_t pid)
{
    variant_t *var;
    variant_proc_t *proc;

    var = find_proc_variant(pid);
    assert(var);
    proc = pop_proc_from_list(&var->procs, pid);
    assert(proc);
    print("Exit proc %d in var %d\n", pid, var->num);
    free(proc);

    return 0;
}

/*
 * Create a new thread in a process. Should be called for every thread,
 * including the default one (e.g. in a single-threaded proc. Returns a thread
 * object that should be passed to e.g. the syscall_enter and exit functions.
 */
variant_thread_t *mv_thread_new(pid_t tid, pid_t pid, pid_t ptid)
{
    variant_proc_t *proc;
    variant_thread_t *thread;
    pid_t vtid;

    assert((tid == pid && ptid == -1) || (tid != pid && ptid != -1));

    proclist_lock();
    proc = find_proc(pid);
    assert(proc);
    thread = find_thread_in_proc(proc, tid);
    assert(!thread);
    proclist_unlock();

    if (pid == tid)
        vtid = proc->vpid;
    else
    {
        variant_thread_t *pthread = find_thread(ptid);
        assert(pthread);
        vtid = vtid_generate(pthread);
    }
    assert(vtid < MAX_PROCS_PER_VAR);
    thread = new_thread(tid, vtid);
    thread->proc = proc;
    thread->var_id_pre = &proc->variant->last_syscall_id_pre;
    thread->var_id_post = &proc->variant->last_syscall_id_post;

    proclist_lock();
    if (proc->threads == NULL)
        proc->threads = thread;
    else
    {
        variant_thread_t *t = proc->threads;
        while (t->next)
            t = t->next;
        t->next = thread;
    }

    if (!ringbuffers_data[thread->vtid])
        ringbuffers_data[thread->vtid] = ringbuffer_new(&thread->ringbuffer);
    else
        ringbuffer_attach(&thread->ringbuffer, ringbuffers_data[thread->vtid]);

    proclist_unlock();

    print("New thread %d in proc %d (var %d, vtid %d, vpid %d)\n", tid, pid,
            proc->variant_num, vtid, proc->vpid);

    return thread;
}

/*
 * Should be called when a thread exits.
 */
int mv_thread_exit(variant_thread_t *thread)
{
    variant_proc_t *proc;
    assert(thread);
    proc = thread->proc;
    assert(proc);

    proclist_lock();

    /* Remove from process' linked list of threads. */
    if (proc->threads == thread)
        proc->threads = thread->next;
    else
    {
        variant_thread_t *t = proc->threads;
        while (t)
        {
            if (t->next == thread)
                t->next = thread->next;
            t = t->next;
        }
    }

    print("Exit thread %d in proc %d in var %d\n", thread->tid,
            thread->proc->pid, thread->proc->variant_num);
    if (proc->threads == NULL)
        mv_proc_exit(proc->pid);

    proclist_unlock();

    free(thread);
    return 0;
}

/*
 * Returns the thread object associated with a tid.
 */
variant_thread_t *mv_thread_get(pid_t tid)
{
    variant_thread_t *thread = find_thread(tid);
    assert(thread);
    return thread;
}

/*
 * Returns the thread object associated with a tid, and waits for the thread to
 * be created if it does not exist yet.
 */
variant_thread_t *mv_thread_get_wait(pid_t tid)
{
    variant_thread_t *thread;
    while (!(thread = find_thread(tid)))
        asm volatile("pause\n" ::: "memory");
    return thread;
}


/*
 * Returns whether the given proc has indicated it is in a system call.
 */
int mv_thread_in_syscall(variant_thread_t *thread)
{
    assert(thread);
    return thread->syscall_entered;
}

/*
 * Returns the number of the last system call performed by pid.
 */
long mv_thread_getlastsyscall(variant_thread_t *thread)
{
    assert(thread);
    assert(thread->last_syscall);
    return thread->last_syscall->nr;
}

pid_t mv_proc_getvpid(pid_t pid)
{
    variant_proc_t *proc = find_proc(pid);
    assert(proc);
    return proc->vpid;
}

pid_t mv_thread_getvtid(mv_thread_t thread)
{
    assert(thread);
    return thread->vtid;
}

pid_t mv_thread_getpgid(mv_thread_t thread)
{
    assert(thread);
    return thread->proc->pid;
}

pid_t mv_thread_getvpid(mv_thread_t thread)
{
    assert(thread);
    return thread->proc->vpid;
}

pid_t mv_thread_gettid(mv_thread_t thread)
{
    assert(thread);
    return thread->tid;
}

/*
 * Returns the pids of all processes in the same group (all equivalent procs in
 * other variants) into buf.
 *
 * Buf is assumed to be an array of size (mv_num_variants - 1) pid_t entries.
 */
int mv_proc_varpids(pid_t pid, pid_t *buf)
{
    int rv;
    unsigned i, var;
    variant_proc_t *buf2[mv_num_variants];
    variant_proc_t *proc = find_proc(pid);
    assert(proc);
    rv = find_procs_by_vpid(proc->vpid, buf2);
    i = 0;
    for (var = 0; var < mv_num_variants; var++)
    {
        pid_t varpid = buf2[var] ? buf2[var]->pid : -1;
        if (varpid == proc->pid)
            continue;
        buf[i++] = varpid;
    }
    return rv && i != mv_num_variants - 1;
}

/*
 * Returns the tids of all processes in the same group (all equivalent procs in
 * other variants) into buf.
 *
 * Buf is assumed to be an array of size (mv_num_variants - 1) pid_t entries.
 */
int mv_thread_vartids(pid_t tid, pid_t *buf)
{
    int rv;
    unsigned i, var;
    variant_thread_t *thread = find_thread(tid);
    variant_thread_t *buf2[mv_num_variants];
    rv = find_threads_by_vtid(thread->vtid, buf2);
    i = 0;
    for (var = 0; var < mv_num_variants; var++)
    {
        pid_t varpid = buf2[var] ? buf2[var]->tid : -1;
        if (varpid == tid)
            continue;
        buf[i++] = varpid;
    }
    return rv && i != mv_num_variants - 1;
}

/*
 * Returns the tids of all threads of all procs in the variant of the given
 * thread.
 */
int mv_var_tids_by_thread(variant_thread_t *thread, pid_t *buf, size_t buf_size)
{
    return mv_var_tids(thread->proc->variant->num, buf, buf_size);
}

int mv_var_tids(unsigned var_num, pid_t *buf, size_t buf_size)
{
    size_t i;
    variant_t *var;
    variant_proc_t *p;
    variant_thread_t *t;
    assert(var_num < mv_num_variants);
    var = &variants[var_num];

    for (i = 0; i < buf_size; i++)
        buf[i] = -1;

    i = 0;
    for (p = var->procs; p; p = p->next)
        for (t = p->threads; t; t = t->next)
        {
            if (i == buf_size - 1)
                return 1;
            buf[i++] = t->tid;
        }
    return 0;
}


int mv_waiting_var_tids_by_thread(variant_thread_t *thread, pid_t *buf)
{
    int rv;
    unsigned i, var;
    variant_thread_t *buf2[mv_num_variants];
    rv = find_threads_by_vtid(thread->vtid, buf2);
    for (i = 0; i < mv_num_variants; i++)
        buf[i] = -1;
    i = 0;
    for (var = 0; var < mv_num_variants; var++)
    {
        pid_t vartid = buf2[var] ? buf2[var]->tid : -1;
        if (vartid == thread->tid || vartid == -1)
            continue;
        if (!buf2[var]->waiting_othervar)
            continue;
        buf[i++] = vartid;
    }
    return rv;
}
int mv_waiting_thread_tids_by_thread(variant_thread_t *thread, pid_t *buf,
        size_t buf_size)
{
    size_t i;
    variant_t *var = thread->proc->variant;
    variant_proc_t *p;
    variant_thread_t *t;

    for (i = 0; i < buf_size; i++)
        buf[i] = -1;

    i = 0;
    for (p = var->procs; p; p = p->next)
        for (t = p->threads; t; t = t->next)
        {
            if (i == buf_size - 1)
                return 1;
            if (t->tid == thread->tid)
                continue;
            if (!t->waiting_otherthread)
                continue;
            buf[i++] = t->tid;
        }
    return 0;
}

/* Returns the pid of var0 given a pid in the same group. */
pid_t mv_proc_var0_pid(pid_t pid)
{
    variant_proc_t *proc0;
    variant_proc_t *proc = find_proc(pid);
    assert(proc);
    proc0 = find_proc_in_list_by_vpid(variants[0].procs, proc->vpid);
    assert(proc0);
    return proc0->pid;
}

void fd_add(variant_proc_t *proc, int rfd, int ffd)
{
    assert(proc);
    assert(ffd >= 0);
    assert(rfd >= 0);
    assert(proc->fds[ffd].real_fd == -1);
    assert(proc->variant->num != 0 || rfd == ffd);
    if ((size_t)ffd >= proc->fds_size)
    {
        size_t oldsize = proc->fds_size;
        do {
            proc->fds_size *= 2;
        } while ((size_t)ffd >= proc->fds_size);
        proc->fds = realloc_mem(proc->fds, proc->fds_size, oldsize);
        assert(proc->fds);
    }
    proc->fds[ffd].real_fd = rfd;
}

void fd_rm(variant_proc_t *proc, int ffd)
{
    assert(proc);
    assert(ffd >= 0);
    assert((size_t)ffd < proc->fds_size);
    assert(proc->fds[ffd].real_fd != -1);
    proc->fds[ffd].real_fd = -1;
}

int fd_get(variant_proc_t *proc, int ffd)
{
    assert(proc);
    if (ffd == -1)
        return -1;
    if ((size_t)ffd >= proc->fds_size)
        return -1;
    assert(ffd >= 0);
    return proc->fds[ffd].real_fd;
}

void epoll_data_add(variant_proc_t *proc, int epfd, int fd, uint64_t data)
{
    unsigned i;
    assert(proc);
    for (i = 0; i < proc->epoll_data_size; i++)
    {
        assert(!(proc->epoll_data[i].epfd == epfd &&
                 proc->epoll_data[i].fd == fd));
        /* nginx actually this, and it *should* work out fine... */
        /*
        assert(!(proc->epoll_data[i].epfd == epfd &&
                 proc->epoll_data[i].data == data));
        */
        if (proc->epoll_data[i].epfd == -1)
            break;
    }
    if (i == proc->epoll_data_size)
    {
        size_t oldsize = proc->epoll_data_size;
        proc->epoll_data_size *= 2;
        proc->epoll_data = realloc_mem(proc->epoll_data, proc->epoll_data_size,
                oldsize);
        assert(proc->epoll_data);
    }
    proc->epoll_data[i].epfd = epfd;
    proc->epoll_data[i].fd = fd;
    proc->epoll_data[i].data = data;
}

void epoll_data_mod(variant_proc_t *proc, int epfd, int fd, uint64_t data)
{
    unsigned i;
    assert(proc);
    for (i = 0; i < proc->epoll_data_size; i++)
        if (proc->epoll_data[i].epfd == epfd && proc->epoll_data[i].fd == fd)
            break;
    assert(i != proc->epoll_data_size);
    proc->epoll_data[i].data = data;
}

void epoll_data_rm(variant_proc_t *proc, int epfd, int fd)
{
    unsigned i;
    assert(proc);
    for (i = 0; i < proc->epoll_data_size; i++)
        if (proc->epoll_data[i].epfd == epfd && proc->epoll_data[i].fd == fd)
            break;
    assert(i != proc->epoll_data_size);
    proc->epoll_data[i].epfd = -1;
    proc->epoll_data[i].fd = -1;
}

void epoll_data_close_fd(variant_proc_t *proc, int fd)
{
    unsigned i;
    assert(proc);
    for (i = 0; i < proc->epoll_data_size; i++)
        if (proc->epoll_data[i].fd == fd)
        {
            proc->epoll_data[i].fd = -1;
            proc->epoll_data[i].epfd = -1;
        }
}

uint64_t epoll_data_get(variant_proc_t *proc, int epfd, int fd)
{
    unsigned i;
    assert(proc);
    for (i = 0; i < proc->epoll_data_size; i++)
        if (proc->epoll_data[i].epfd == epfd && proc->epoll_data[i].fd == fd)
            return proc->epoll_data[i].data;
    assert(!"epoll entry not found");
    return 0;
}

int epoll_data_to_fd(variant_proc_t *proc, int epfd, uint64_t data)
{
    unsigned i;
    assert(proc);
    for (i = 0; i < proc->epoll_data_size; i++)
        if (proc->epoll_data[i].epfd == epfd &&
            proc->epoll_data[i].data == data)
            return proc->epoll_data[i].fd;
    assert(!"epoll entry not found");
    return 0;
}

int mv_thread_getrewriteargs(variant_thread_t *thread, char *mask[6],
        unsigned long *vals[6])
{
    assert(thread);
    *mask = thread->rewriteargs_mask;
    *vals = thread->rewriteargs_vals;
    return thread->actions_pre & MV_ACTION_REWRITEARG;
}

void thread_rewriteargs_clear(variant_thread_t *thread)
{
    unsigned i;
    assert(thread);
    for (i = 0; i < 6; i++)
        thread->rewriteargs_mask[i] = 0;
}

void thread_rewriteargs_add(variant_thread_t *thread, unsigned arg,
        unsigned long val)
{
    assert(thread);
    assert(arg < 6);
    thread->rewriteargs_mask[arg] = 1;
    thread->rewriteargs_vals[arg] = val;
}

pid_t vtid_generate(variant_thread_t *pthread)
{
    if (pthread == NULL)
        return 1;

    proclist_lock();

    pid_t rv = vpid_data->vpid_map[pthread->vtid][pthread->num_children - 1];
    if (rv == -1)
    {
        rv = ++vpid_data->last_pid;
        vpid_data->vpid_map[pthread->vtid][pthread->num_children - 1] = rv;
    }

    proclist_unlock();

    return rv;
}

void thread_increase_childcount(variant_thread_t *thread)
{
    assert(thread);
    proclist_lock();
    thread->num_children++;
    assert(thread->num_children < MAX_CHILDS_PER_PROC);
    proclist_unlock();
}

void mv_proc_userdata_set(pid_t pid, void *data)
{
    variant_proc_t *proc = find_proc(pid);
    assert(proc);
    proc->userdata = data;
}

void *mv_proc_userdata_get(pid_t pid)
{
    variant_proc_t *proc = find_proc(pid);
    assert(proc);
    return proc->userdata;
}

void mv_proc_userdata_get_var(pid_t pid, void **buf)
{
    unsigned i, var;
    variant_proc_t *buf2[mv_num_variants];
    variant_proc_t *proc = find_proc(pid);
    assert(proc);
    find_procs_by_vpid(proc->vpid, buf2);
    i = 0;
    for (var = 0; var < mv_num_variants; var++)
    {
        if (buf2[var]->pid == proc->pid)
            continue;
        buf[i++] = buf2[var]->userdata;
    }
}

void mv_abort_execution(void)
{
    *mv_aborted_execution = 1;
}

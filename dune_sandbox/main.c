#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <linux/sched.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <asm/prctl.h>

#include <libdune/dune.h>
#include <boxer.h>
#include "libmultivar/multivar.h"
#include "shmem.h"
#include "mv_user_kernel_shareddefs.h"

pid_t proc_pid;
__thread pid_t proc_tid;
__thread mv_thread_t thread;
int *whitelist_level = NULL;
int whitelist_level_l = 0;
int loader_done = 0;

int entered_dune = 0;
__thread int last_syscall_was_safe;
__thread struct dune_tf *last_tf;
__thread char has_overwritten_libc_pid;

static int syscall_monitor(struct dune_tf *tf);
static void syscall_monitor_post(struct dune_tf *tf, uint64_t syscall_no);
static get_backtrace_for_context_t get_userspace_backtrace;

/*
 * Print function which works for both non-dune and dune mode. For the former,
 * it simply prints to stderr as it normally would. For dune-mode, we circumvent
 * a lot of libc code by doing a write syscall (via vmcall) directly. Also, the
 * dune-version prints to another fd (a copy of stderr) so the running process
 * cannot manipulate it accidentally.
 */
int print(const char *fmt, ...)
{
    va_list args;
    long rv;
    va_start(args, fmt);
    shmem_lock();
    if (entered_dune)
    {
        char buf[1024];
        vsnprintf(buf, 1024, fmt, args);
        asm volatile("movq $1, %%rax \n\t" /* SYS_write */
                     "movq $100, %%rdi \n\t" /* fd, we duped stderr->100 */
                     "movq %1, %%rsi \n\t" /* buf */
                     "movq %2, %%rdx \n\t" /* buf strlen */
                     "vmcall \n\t"
                     "movq %%rax, %0 \n\t" :
                     "=r" (rv) :
                     "r" (buf), "r" (strlen(buf)) :
                     "rax", "rdi", "rsi", "rdx");
    }
    else
        rv = vfprintf(stderr, fmt, args);
    va_end(args);
    shmem_unlock();
    return (int)rv;
}

void print_userspace_backtrace(struct dune_tf *tf)
{
    struct backtrace_info bt[32];
    ucontext_t uc;
    int i;

    print(" == Backtrace ==  %p\n", get_userspace_backtrace);

    if (!get_userspace_backtrace)
        return;

    dune_getcontext(&uc, tf);
    get_userspace_backtrace(&uc, bt, 32);
    for (i = 0; i < 32; i++)
    {
        if (bt[i].ip == 0)
            break;
        print(" ip = %lx sp = %lx. %s+%lu\n", bt[i].ip, bt[i].sp,
                bt[i].proc_name, bt[i].proc_off);
    }
}

void print_userspace_backtrace_last(pid_t pid)
{
    (void)pid;
    print_userspace_backtrace(last_tf);
}

void *realloc_oldsize(void *ptr, size_t size, size_t old_size)
{
    (void)old_size;
    return realloc(ptr, size);
}

void *copy_from_user(pid_t pid, void *dest, void *src, size_t size)
{
    assert(pid == proc_pid);
    memcpy(dest, src, size);
    return dest;
}

void *copy_to_user(pid_t pid, void *dest, void *src, size_t size)
{
    assert(pid == proc_pid);
    memcpy(dest, src, size);
    return dest;
}

unsigned long long sc(unsigned long nr)
{
    return syscall(nr);
}

static int syscall_monitor(struct dune_tf *tf)
{
    struct syscall_args syscall;
    int actions;
    char *fs_base;

    if (tf->rax == MV_UNWIND_PASS_SYSCALL)
    {
        get_userspace_backtrace = (void*)ARG0(tf);
        return 0;
    }
    else if (tf->rax == MV_LOADER_DONE_SYSCALL)
    {
        print("%d: loader done\n", proc_tid);
        loader_done = 1;
        return 0;
    }
    else if (tf->rax == MV_WHITELIST_PASS_SYSCALL)
    {
        whitelist_level = (int*)ARG0(tf);
        return 0;
    }
    else if (tf->rax == MV_WHITELIST_INC_SYSCALL)
    {
        whitelist_level_l++;
        return 0;
    }
    else if (tf->rax == MV_WHITELIST_DEC_SYSCALL)
    {
        whitelist_level_l--;
        return 0;
    }

    if (!loader_done)
        return 1;

    if (whitelist_level && *whitelist_level)
        return 1;

    if (whitelist_level_l)
        return 1;

#if NO_MV
    return 1;
#endif

    /* Overwrite the cached pid(/tid) of glibc. XXX hacky */
    if (!has_overwritten_libc_pid)
    {
        fs_base = (char *)dune_get_user_fs();
        if (fs_base)
        {
            pid_t *pid_tls_loc = (int *)(fs_base + 0x2d4);
            pid_t *tid_tls_loc = (int *)(fs_base + 0x2d0);
            *pid_tls_loc = mv_thread_getvpid(thread);
            if (*tid_tls_loc)
                *tid_tls_loc = mv_thread_getvtid(thread);
            has_overwritten_libc_pid = 1;
        }
    }

    syscall.nr = tf->rax;
    syscall.orig_args[0] = ARG0(tf);
    syscall.orig_args[1] = ARG1(tf);
    syscall.orig_args[2] = ARG2(tf);
    syscall.orig_args[3] = ARG3(tf);
    syscall.orig_args[4] = ARG4(tf);
    syscall.orig_args[5] = ARG5(tf);

    last_tf = tf;

    actions = mv_syscall_enter(thread, &syscall);
    if (actions & MV_ACTION_ABORT)
    {
        print("Aborting T%d\n", proc_tid);
        dune_die();
    }
    assert(actions & MV_ACTION_CONTINUE);
    assert(!((actions & MV_ACTION_FAKE) && (actions & MV_ACTION_REWRITEARG)));

    last_syscall_was_safe = (actions & MV_ACTION_SAFE);

    if (actions & MV_ACTION_REWRITEARG)
    {
        unsigned i;
        char *mask;
        unsigned long *vals;
        unsigned long *arg_regs[] =
                { &tf->rdi, &tf->rsi, &tf->rdx, &tf->r10, &tf->r8, &tf->r9 };
        mv_thread_getrewriteargs(thread, &mask, &vals);
        for (i = 0; i < 6; i++)
            if (mask[i])
                *(arg_regs[i]) = vals[i];

    }

    if (actions & MV_ACTION_FAKE)
    {
        syscall_monitor_post(tf, tf->rax);
        return 0;
    }

    return 1;
}

static void syscall_monitor_post(struct dune_tf *tf, uint64_t syscall_no)
{
    long fake_rv;
    int actions;
    pid_t new_child_tid = tf->rax;

    if (syscall_no == MV_LOADER_DONE_SYSCALL ||
        syscall_no == MV_WHITELIST_PASS_SYSCALL ||
        syscall_no == MV_WHITELIST_INC_SYSCALL ||
        syscall_no == MV_WHITELIST_DEC_SYSCALL ||
        syscall_no == MV_UNWIND_PASS_SYSCALL)
        return;

    if (!loader_done)
        return;

    if (whitelist_level && *whitelist_level)
        return;

    if (whitelist_level_l)
        return;

    if (syscall_no == SYS_clone && proc_pid != syscall(SYS_getpid))
    {
        pid_t ptid = tf->r10;
        proc_pid = syscall(SYS_getpid);
        proc_tid = syscall(SYS_gettid);
        assert(proc_tid == proc_pid);
        shmem_lock_proclist();
        mv_proc_new(proc_pid, ptid, -1);
        thread = mv_thread_new(proc_tid, proc_pid, -1);
        shmem_unlock_proclist();
        if (ARG0(tf) & CLONE_CHILD_SETTID)
        {
            pid_t *ctid = (pid_t *)ARG3(tf);
            print("ctid %p\n", ctid);
            *ctid = mv_proc_getvpid(proc_pid);
        }
        return;
    }
    else if (syscall_no == SYS_clone && proc_tid != syscall(SYS_gettid))
    {
        pid_t ptid = tf->r10;
        has_overwritten_libc_pid = 0;
        proc_tid = syscall(SYS_gettid);
        shmem_lock_proclist();
        thread = mv_thread_new(proc_tid, proc_pid, ptid);
        shmem_unlock_proclist();
        if (ARG0(tf) & CLONE_CHILD_SETTID)
        {
            pid_t *ctid = (pid_t *)ARG3(tf);
            print("ctid %p, val %d\n", ctid, mv_thread_getvtid(thread));
            *ctid = mv_thread_getvtid(thread);
        }

        if (ARG0(tf) & CLONE_PARENT_SETTID)
        {
            pid_t *ptid = (pid_t *)ARG2(tf);
            print("ptid %p, val %d\n", ptid, mv_thread_getvtid(thread));
            *ptid = mv_thread_getvtid(thread);
        }
        return;
    }

#if NO_MV
    return 1;
#endif

    if (last_syscall_was_safe)
        return;


    actions = mv_syscall_exit(thread, tf->rax, &fake_rv);
    if (actions & MV_ACTION_ABORT)
    {
        print("Aborting T%d\n", proc_tid);
        dune_die();
    }
    assert(actions & MV_ACTION_CONTINUE);
    assert(!(actions & MV_ACTION_REWRITEARG));
    if (actions & MV_ACTION_FAKE)
        tf->rax = fake_rv;

    if (syscall_no == SYS_clone)
        mv_thread_get_wait(new_child_tid);

    return;
}

void handle_gpfault(struct dune_tf *tf)
{
    const char *code = (char *)tf->rip;

    /* Check for rdtsc by reading opcode at insruction pointer. */
    if (code[0] == 0x0f && code[1] == 0x31)
    {
        unsigned long cycles;
        mv_rdtsc(thread, &cycles);
        tf->rip += 2;
        tf->rax = cycles & 0xffffffff;
        tf->rdx = cycles >> 32;
        return;
    }

    dune_dump_trap_frame(tf);
    dune_die();
}

void sigterm_handler(int sig)
{
    pid_t pid;
    int status;
    unsigned i, j;
    pid_t tids[128];
    (void)sig;
    for (i = 0; i < mv_num_variants; i++)
    {
        assert(mv_var_tids(i, tids, 128) == 0);
        for (j = 0; j < 128; j++)
        {
            if (tids[j] == -1)
                break;
            kill(tids[j], SIGKILL);
            fprintf(stderr, " sigkill %d\n", tids[j]);
        }
    }
    while ((pid = wait(&status)) != -1)
        print("quitting %d (in sigterm_handler)\n", pid);
}

struct mv_functions mv_functions_dunesb = {
    .alloc_mem_shared = shmem_alloc,
    .free_mem_shared = shmem_free,
    .realloc_mem_shared = shmem_realloc,
    .alloc_mem_local = malloc,
    .free_mem_local = free,
    .realloc_mem_local = realloc_oldsize,
    .copy_from_user = copy_from_user,
    .copy_to_user = copy_to_user,
    .print = print,
    .backtrace = print_userspace_backtrace_last,
};

/* Sets up administration shared by all processes and start them. */
int main(int argc, char *argv[])
{
    int i;
    int nvar = 2, dont_detach = 0, out_to_file = 0;

    if (getenv("MV_NUM_PROC"))
        nvar = atoi(getenv("MV_NUM_PROC"));
    if (getenv("MV_DONT_DETACH"))
        dont_detach = atoi(getenv("MV_DONT_DETACH"));
    if (getenv("MV_OUT_TO_FILE"))
        out_to_file = atoi(getenv("MV_OUT_TO_FILE"));

    shmem_init();
    mv_init(nvar, 0, &mv_functions_dunesb);

    /* We exec this program twice, once to init and fork all variants, then
     * again per variant to force ASLR and allow for per-variant envvars. This
     * also allows us to keep this `master process' alive for runs that should't
     * detach (eg SPEC). So we must detect which execution path this is.
     */
    if (!getenv("MV_VAR_NUM"))
    {
        /* Initial path (first invocation) - create a process per variant. */
        shmem_exec_pre();
        shmem_barrier_init(nvar + 1);
        shmem_mvstate_set(mv_state_alloc());

        /* Create all procs for variants, and exec to re-execute the monitor.
         * This triggers ASLR for every variant.
         */
        for (i = 0; i < nvar; i++)
        {
            pid_t pid = fork();
            if (pid < 0)
                perror("fork");
            else if (pid == 0)
            {
                char buf[128];
                snprintf(buf, 128, "%d", i);
                setenv("MV_VAR_NUM", buf, 1);
                execvp(argv[0], argv);
            }
        }

        /* Wait for all procs to start up. This is mostly so we wait for procs
         * to attach to the shmem before we exit.
         */
        shmem_barrier_wait();
        shmem_barrier_destroy();
    }
    else
    {
        char **new_argv;
        char buf[128];
        int var_num, fd;

        var_num = atoi(getenv("MV_VAR_NUM"));
        fprintf(stderr, "Var %d reporting in\n", var_num);
        unsetenv("MV_VAR_NUM");
        unsetenv("MV_NUM_PROC");

        if (getenv("MV_UMEM") || getenv("MV_SLAB_MAX") || getenv("MV_SLAB_PAD"))
        {
            char *ld_lib;

            unsetenv("MV_UMEM");

            if (var_num == 0)
                ld_lib = LIBMEM_PATH;
            else
                ld_lib = LIBUMEM_MALLOC_PATH;
            setenv("LD_PRELOAD", ld_lib, 1);
            fprintf(stderr, "V%d: Using LD_PRELOAD=%s\n", var_num, ld_lib);

            if (getenv("MV_SLAB_MAX") || getenv("MV_SLAB_PAD"))
            {
                int slab_max = 10000;
                char *slab_pad = "0";
                if (getenv("MV_SLAB_MAX"))
                    slab_max = atoi(getenv("MV_SLAB_MAX"));
                if (getenv("MV_SLAB_PAD"))
                    slab_pad = getenv("MV_SLAB_PAD");
                unsetenv("MV_SLAB_MAX");
                unsetenv("MV_SLAB_PAD");
                if (var_num > 0)
                {
                    snprintf(buf, 128, "slabmax=%d,slabpad=%s", slab_max,
                            slab_pad);
                    setenv("UMEM_DEBUG", buf, 1);
                    fprintf(stderr, "set slabmax=%d,slabpad=%s for %d\n", slab_max,
                            slab_pad, (pid_t)syscall(SYS_getpid));
                }
            }
        }
        else
        {
            char *ld_lib = LIBMEM_PATH;
            setenv("LD_PRELOAD", ld_lib, 1);
            fprintf(stderr, "V%d: Using LD_PRELOAD=%s\n", var_num, ld_lib);
        }

        shmem_exec_post();
        shmem_barrier_wait();
        mv_state_inherit(shmem_mvstate_get());

        /*
         * Construct new argv to execute in child proc. The loader present in
         * boxer is really limited, and therefore we make that loader load the
         * default system loader, which in turn can load the actual binary.
         */
        new_argv = malloc(sizeof(char *) * (argc + 2));
        new_argv[0] = argv[0];
        new_argv[1] = "/lib64/ld-linux-x86-64.so.2";
        for (i = 1; i < argc; i++)
            new_argv[i + 1] = argv[i];
        new_argv[argc + 1] = NULL;

        if (out_to_file)
        {
            /* Connect the output of the print function (used by libmv) etc to a
             * file. */
            snprintf(buf, 128, "out.%d", var_num);
            fd = open(buf, O_CREAT | O_WRONLY | O_APPEND | O_TRUNC, S_IRUSR | S_IWUSR);
            assert(fd != -1);
            assert(dup2(fd, 100) == 100);
        }
        else
        {
            /* Copy stderr to another fd, so our prints keep working even if the
             * process itself closes the shell steams. */
            assert(dup2(2, 100) == 100);
        }
        proc_pid = (pid_t)syscall(SYS_getpid);
        proc_tid = (pid_t)syscall(SYS_gettid);
        shmem_lock_proclist();
        mv_proc_new(proc_pid, -1, var_num);
        thread = mv_thread_new(proc_tid, proc_pid, -1);
        shmem_unlock_proclist();

        entered_dune = 1;
        has_overwritten_libc_pid = 0;

        boxer_set_sandbox_path(argv[0]);
        boxer_register_syscall_monitor(syscall_monitor);
        boxer_register_syscall_monitor_post(syscall_monitor_post);
        dune_register_intr_handler(13, handle_gpfault);
        return boxer_main(argc + 2, new_argv);
    }

    if (dont_detach)
    {
        struct sigaction sa;
        pid_t pid;
        int status;

        sa.sa_flags = 0;
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = sigterm_handler;
        sigaction(SIGTERM, &sa, NULL);

        while ((pid = wait(&status)) != -1)
            print("quitting %d\n", pid);
    }

    return 0;

}

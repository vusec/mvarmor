#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/limits.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include <pthread.h>
#include <libunwind-ptrace.h>

#include <libmultivar/multivar.h>

//#define DEBUG
#ifdef DEBUG
#define debug_print(...) fprintf(stderr, " # " __VA_ARGS__)
#else
#define debug_print(...) do { } while(0)
#endif

static unsigned num_variants;
static int is_aborting = 0;

int handle_syscall(pid_t pid, int new_syscall);
void *copy_to_user(pid_t pid, void *dest, void *src, size_t size);
int printa(const char *fmt, ...);

void print_backtrace(pid_t pid)
{
    unw_cursor_t cursor;
    unsigned long ip, sp, proc_off;
    char proc_name[32];
    static unw_addr_space_t as;
    static struct UPT_info *ui;
    as = unw_create_addr_space(&_UPT_accessors, 0);
    ui = _UPT_create(pid);

    fprintf(stderr, " == Backtrace ==\n");
    unw_init_remote (&cursor, as, ui);

    do
    {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);
        unw_get_proc_name(&cursor, proc_name, 32, &proc_off);
        fprintf(stderr, " ip = %lx sp = %lx. %s+%lu\n", ip, sp, proc_name, proc_off);
    } while (unw_step(&cursor) > 0);
}


void setup(int nvar, char **program)
{
    char exe_dir[PATH_MAX], preload[PATH_MAX], *last_slash = NULL, *tmp;
    ssize_t ret;
    int i;
    pid_t pid;
    int status;
    struct user_regs_struct regs;
    pid_t pids[nvar];
    num_variants = nvar;

    ret = readlink("/proc/self/exe", exe_dir, sizeof(exe_dir) - 1);
    if (ret < 0)
    {
        perror("readlink");
        exit(1);
    }
    exe_dir[ret] = '\0';
    tmp = &exe_dir[0];
    while (*tmp)
    {
        if (*tmp == '/')
            last_slash = tmp;
        tmp++;
    }
    *last_slash = '\0';
    snprintf(preload, PATH_MAX, "%s/libpreload.so", exe_dir);
    fprintf(stderr, "Using LD_PRELOAD=%s\n", preload);

    for (i = 0; i < nvar; i++)
    {
        pid = fork();

        if (pid < 0)
            perror("fork");

        if (pid == 0)
        {
            char buf[100];
            snprintf(buf, 100, "VAR%d", i);
            //setenv("MV_VARIANT", buf, 1);
            setenv("LD_PRELOAD", preload, 1);
            debug_print("ptrace child running, pid=%d\n", getpid());
            debug_print("Starting %s\n", program[0]);
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
                perror("ptrace");

            execvp(program[0], program);
            perror("execve");
        }
        else
        {
            mv_proc_new(pid, -1, i);
            mv_thread_new(pid, pid, -1);

            pid_t pid2 = waitpid(pid, &status, 0);
            assert(pid == pid2);
            assert(WIFSTOPPED(status));
            ptrace(PTRACE_SETOPTIONS, pid, NULL,
                    PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                    PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK |
                    PTRACE_O_TRACEEXEC);
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            assert(regs.orig_rax == SYS_execve);
            pids[i] = pid;
        }
    }

    for (i = 0; i < nvar; i++)
        ptrace(PTRACE_SYSCALL, pids[i], NULL, NULL);
}

void check_wakeups_vars(mv_thread_t thread)
{
    unsigned i;
    debug_print("check wake var\n");
    pid_t tids[num_variants - 1];
    mv_waiting_var_tids_by_thread(thread, tids);

    for (i = 0; i < num_variants - 1 && tids[i] != -1; i++)
    {
        debug_print("trying wake %d\n", tids[i]);
        if (handle_syscall(tids[i], 0))
        {
            debug_print("wakeup succes %d\n", tids[i]);
            return;
        }
    }
}

void check_wakeups_threads(mv_thread_t thread)
{
    unsigned i;
    pid_t tids[128];
    mv_waiting_thread_tids_by_thread(thread, tids, 128);
    debug_print("wakeup_threads\n");

    for (i = 0; tids[i] != -1 && i < 128; i++)
    {
        debug_print("trying wake %d\n", tids[i]);
        if (handle_syscall(tids[i], 0))
        {
            debug_print("wakeup succes %d\n", tids[i]);
            return;
        }
    }
}

int do_actions_pre(int actions, pid_t pid, mv_thread_t thread)
{
    debug_print("%d  C %d F %d R %d WV %d WT %d A %d\n", pid,
            !!(actions & MV_ACTION_CONTINUE),
            !!(actions & MV_ACTION_FAKE),
            !!(actions & MV_ACTION_REWRITEARG),
            !!(actions & MV_ACTION_WAKE_VARS),
            !!(actions & MV_ACTION_WAKE_THREADS);
            !!(actions & MV_ACTION_ABORT));
    assert(!((actions & MV_ACTION_FAKE) && (actions & MV_ACTION_REWRITEARG)));
    assert(!((actions & MV_ACTION_ABORT) && (actions & ~MV_ACTION_ABORT)));

    if (actions & MV_ACTION_ABORT)
    {
        fprintf(stderr, "Aborting %d\n", pid);
        is_aborting = 1;
        kill(pid, SIGKILL);
        check_wakeups_vars(thread);
        check_wakeups_threads(thread);
        return 1;
    }

    if (actions & MV_ACTION_FAKE)
    {
        /* We cannot cancel a syscall, but we can replace it with something
        * which has no side effects, like getpid. We will replace the
        * return value (rax) later. */
        ptrace(PTRACE_POKEUSER, pid, 8 * ORIG_RAX, SYS_getpid);
    }
    else if (actions & MV_ACTION_REWRITEARG)
    {
        unsigned i;
        char *mask;
        unsigned long *vals;
        unsigned long arg_regs[] = { RDI, RSI, RDX, R10, R8, R9 };
        mv_thread_getrewriteargs(thread, &mask, &vals);
        for (i = 0; i < 6; i++)
            if (mask[i])
            {
                debug_print("%d  rewriting arg %d into %lu\n", pid, i, vals[i]);
                ptrace(PTRACE_POKEUSER, pid, 8 * arg_regs[i], vals[i]);
            }

    }

    if (actions & MV_ACTION_WAKE_VARS)
        check_wakeups_vars(thread);

    if (actions & MV_ACTION_WAKE_THREADS)
        check_wakeups_threads(thread);

    if (actions & MV_ACTION_CONTINUE)
    {
        /* Let the syscall go through */
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        return 1;
    }
    return 0;
}

int do_actions_post(int actions, long rv, pid_t pid, mv_thread_t thread)
{
    debug_print("%d  C %d F %d R %d WV %d WT %d A %d  rv %ld\n", pid,
            !!(actions & MV_ACTION_CONTINUE),
            !!(actions & MV_ACTION_FAKE),
            !!(actions & MV_ACTION_REWRITEARG),
            !!(actions & MV_ACTION_WAKE_VARS),
            !!(actions & MV_ACTION_WAKE_THREADS),
            !!(actions & MV_ACTION_WAKE_ABORT),
            rv);
    assert(!(actions & MV_ACTION_REWRITEARG));
    assert(!((actions & MV_ACTION_ABORT) && (actions & ~MV_ACTION_ABORT)));

    if (actions & MV_ACTION_ABORT)
    {
        fprintf(stderr, "Aborting %d\n", pid);
        is_aborting = 1;
        kill(pid, SIGKILL);
        check_wakeups_vars(thread);
        check_wakeups_threads(thread);
        return 1;
    }

    if (actions & MV_ACTION_FAKE)
    {
        /* Overwrite the result of the fake getpid. */
        ptrace(PTRACE_POKEUSER, pid, 8 * RAX, rv);
        /* Overwrite orig_rax with the original syscall nr, so that in the
         * case it is restarted, we don't restart a getpid inserted by the
         * FAKE option on syscall-enter. */
        ptrace(PTRACE_POKEUSER, pid, 8 * ORIG_RAX,
                mv_thread_getlastsyscall(thread));
    }

    if (actions & MV_ACTION_WAKE_VARS)
        check_wakeups_vars(thread);

    if (actions & MV_ACTION_WAKE_THREADS)
        check_wakeups_threads(thread);

    if (actions & MV_ACTION_CONTINUE)
    {
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        return 1;
    }
    return 0;
}

/*
 * Gets called for every system call event processes generate. This means
 * seperate events (and thus calls) for both system call entries (user->kernel)
 * and exits (kernel->user).
 */
int handle_syscall(pid_t pid, int new_syscall)
{
    struct user_regs_struct regs;
    int actions;
    mv_thread_t thread = mv_thread_get(pid);

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (new_syscall)
        debug_print("syscall %d %lld (%lld)\n", pid, regs.orig_rax, regs.rax);
    else
        debug_print("retrying syscall %d %lld (%lld)\n", pid, regs.orig_rax, regs.rax);

#if NO_MV
    return 1;
#endif

    if (!mv_thread_in_syscall(thread))
    {
        /* New system call, keep track of the syscall nr and arguments. */
        struct syscall_args syscall_info;
        int cont;
        syscall_info.nr = regs.orig_rax;
        syscall_info.orig_args[0] = regs.rdi;
        syscall_info.orig_args[1] = regs.rsi;
        syscall_info.orig_args[2] = regs.rdx;
        syscall_info.orig_args[3] = regs.r10;
        syscall_info.orig_args[4] = regs.r8;
        syscall_info.orig_args[5] = regs.r9;
        actions = mv_syscall_enter(thread, &syscall_info);
        cont = do_actions_pre(actions, pid, thread);
        return cont;
    }
    else
    {
        /* System call return from kernel. */
        long rv;
        int cont;
        actions = mv_syscall_exit(thread, regs.rax, &rv);
        cont = do_actions_post(actions, rv, pid, thread);
        return cont;
    }
    return 1;
}

/*
 * Waits for activity from any child process, and handle that activity
 * correctly. Will stop if there are no child processes left.
 *
 * It will keep track of all procs, updating the list of processes for newly
 * created and exiting processes. In the case of a system call, the seperate
 * system call handler is called.
 */
void wait_for_procs()
{
    pid_t orphans[128] = { 0 };
    int status, event, sig;
    pid_t pid;
    while (1)
    {
        if ((pid = waitpid(-1, &status, __WALL)) == -1)
            break;

        event = status >> 16;
        sig = WSTOPSIG(status);

        if (WIFSTOPPED(status) && sig == (SIGTRAP | 0x80))
        {
            handle_syscall(pid, 1);
        }
        else if (WIFEXITED(status))
        {
            mv_thread_t thread = mv_thread_get(pid);
            debug_print("%d exited normally\n", pid);
            check_wakeups_vars(thread);
            check_wakeups_threads(thread);
            mv_thread_exit(thread);
        }
        else if (WIFSTOPPED(status) && sig == SIGSTOP)
        {
            unsigned i;
            debug_print("%d SIGSTOP\n", pid);

            /* Sometimes we get the sigstop before the FORK event of newly
             * created children. */
            for (i = 0; i < 128 && orphans[i]; i++);
            assert(i < 128 - 2);
            orphans[i] = pid;
            orphans[i + 1] = 0;

            //ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            /* TODO: cont proc if not the inital SIGSTOP */
        }
        else if (sig == SIGTRAP && event == PTRACE_EVENT_EXEC)
        {
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        }
        else if (sig == SIGTRAP &&
                (event == PTRACE_EVENT_FORK ||
                 event == PTRACE_EVENT_VFORK ||
                 event == PTRACE_EVENT_CLONE))
        {
            struct user_regs_struct regs;
            unsigned i;
            int orphan_index = -1;
            pid_t new_pid, vtid;
            mv_thread_t thread, new_thread;
            thread = mv_thread_get(pid);
            ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid);
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);

            /* If this is not an orphan we will wait for a SIGSTOP explicitly
             * here so we know the process has started. If it is an orphan, we
             * recceived this SIGSTOP earlier, before the EVENT_FORK. */
            for (i = 0; i < 128 && orphans[i]; i++)
                if (orphans[i] == new_pid)
                    orphan_index = i;

            if (orphan_index != -1)
            {
                for (i = 0; i < 128 && orphans[i]; i++);
                orphans[orphan_index] = orphans[i - 1];
                orphans[i - 1] = 0;
            }
            else
            {
                waitpid(new_pid, &status, __WALL);
                assert(WIFSTOPPED(status));
            }


            if (regs.rdi & CLONE_THREAD)
                new_thread = mv_thread_new(new_pid, mv_thread_getpgid(thread), pid);
            else
            {
                mv_proc_new(new_pid, pid, -1);
                new_thread = mv_thread_new(new_pid, new_pid, -1);
            }

            if (regs.rdi & CLONE_CHILD_SETTID)
            {
                vtid = mv_thread_getvtid(new_thread);
                copy_to_user(new_pid, (void *)regs.r10, &vtid, sizeof(pid_t));
            }
            if (regs.rdi & CLONE_PARENT_SETTID)
            {
                vtid = mv_thread_getvtid(new_thread);
                copy_to_user(new_pid, (void *)regs.rdx, &vtid, sizeof(pid_t));
            }

            debug_print("%d forked into %d\n", pid, new_pid);
            ptrace(PTRACE_SETOPTIONS, new_pid, NULL,
                    PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                    PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK |
                    PTRACE_O_TRACEEXEC);
            ptrace(PTRACE_SYSCALL, new_pid, NULL, NULL);
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        }
        else if (WIFSTOPPED(status))
        {
            debug_print("%d signal %d\n", pid, sig);
            ptrace(PTRACE_SYSCALL, pid, NULL, sig);
        }
        else if (WIFSIGNALED(status))
        {
            mv_thread_t thread = mv_thread_get(pid);
            fprintf(stderr, "%d got terminated by signal %s\n", pid,
                    strsignal(WTERMSIG(status)));
            check_wakeups_vars(thread);
            check_wakeups_threads(thread);
            mv_thread_exit(thread);
        }
        else if (is_aborting)
        {
            /* Just continue on. */
        }
        else
        {
            fprintf(stderr, "%d stopped due to %d\n", pid, status);
            fprintf(stderr, "%d ifstopped: %d\n", pid, WIFSTOPPED(status));
            fprintf(stderr, "%d ifsignalled: %d\n", pid, WIFSIGNALED(status));
            fprintf(stderr, "%d term sig: %s (%d)\n", pid, strsignal(WTERMSIG(status)), WTERMSIG(status));
            fprintf(stderr, "%d stopping sig: %s (%d)\n", pid, strsignal(sig), sig);
            print_backtrace(pid);
            break;
        }
    }
}

int printa(const char *fmt, ...)
{
    va_list args;
    int rv;
    va_start(args, fmt);
    rv = vfprintf(stderr, fmt, args);
    va_end(args);
    return rv;
}

void *copy_from_user(pid_t pid, void *dest, void *src, size_t size)
{
    int fd;
    char procpath[128];
    assert(dest);
    assert(src);
    snprintf(procpath, 128, "/proc/%d/mem", pid);
    if ((fd = open(procpath, O_RDONLY)) < 0)
    {
        perror("copy_from_user: open");
        fprintf(stderr, "copy_from_user: could not open '%s' for %p %p %zu\n",
                procpath, dest, src, size);
        exit(1);
    }
    if (pread(fd, dest, size, (off_t)src) == -1)
        perror("copy_from_user: pread");
    close(fd);
    return dest;
}
void *copy_to_user(pid_t pid, void *dest, void *src, size_t size)
{
    int fd;
    char procpath[128];
    assert(dest);
    assert(src);
    snprintf(procpath, 128, "/proc/%d/mem", pid);
    if ((fd = open(procpath, O_WRONLY)) < 0)
    {
        perror("copy_to_user: open");
        fprintf(stderr, "copy_to_user: could not open '%s' for %p %p %zu\n",
                procpath, dest, src, size);
        while ((fd = open(procpath, O_WRONLY)) < 0);
        fprintf(stderr, "copy_to_user: opened '%s'\n", procpath);
    }
    if (pwrite(fd, src, size, (off_t)dest) == -1)
    {
        perror("copy_to_user: pwrite");
        fprintf(stderr, "copy_to_user failed for %d %p %p %zu\n", pid, dest,
                src, size);
    }
    close(fd);
    return dest;
}

void *realloc_oldsize(void *ptr, size_t size, size_t old_size)
{
    (void)old_size;
    return realloc(ptr, size);
}

void sigterm_handler(int sig)
{
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
            kill(tids[j], SIGTERM);
            fprintf(stderr, " sigterm %d\n", tids[j]);
        }
    }
    wait_for_procs();
}

struct mv_functions mv_functions_dunesb = {
    .alloc_mem_shared = malloc,
    .free_mem_shared = free,
    .realloc_mem_shared = realloc_oldsize,
    .alloc_mem_local = malloc,
    .free_mem_local = free,
    .realloc_mem_local = realloc_oldsize,
    .copy_from_user = copy_from_user,
    .copy_to_user = copy_to_user,
    .print = printa,
    .backtrace = print_backtrace,
};

int main(int argc, char **argv)
{
    struct sigaction sa;
    int nvar = 2;
    (void)argc;
    debug_print("ptrace monitor running, pid=%d\n", getpid());

    if (getenv("MV_NUM_PROC"))
        nvar = atoi(getenv("MV_NUM_PROC"));

    mv_init(nvar, 1, &mv_functions_dunesb);
    mv_state_alloc();

    setup(nvar, &argv[1]);

    /*
    close(fileno(stdout));
    close(fileno(stderr));
    close(fileno(stdin));
    */

    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigterm_handler;
    sigaction(SIGTERM, &sa, NULL);

    wait_for_procs();

    return 0;
}

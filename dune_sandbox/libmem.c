#define _GNU_SOURCE
#include <sys/syscall.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <assert.h>

#include "dune_unwind_user.h"
#include "mv_user_kernel_shareddefs.h"

//#define ALLOC_ENTER(where) syscall(MV_WHITELIST_INC_SYSCALL, where)
#define ALLOC_ENTER(where) in_libumem_level++
//#define ALLOC_EXIT(where) syscall(MV_WHITELIST_DEC_SYSCALL, where)
#define ALLOC_EXIT(where) in_libumem_level--
#define ALLOC_ENTERED_REG() syscall(MV_WHITELIST_PASS_SYSCALL, &in_libumem_level)
#define LOADER_DONE() syscall(MV_LOADER_DONE_SYSCALL)

int in_libumem_level = 0;

#if 1
/* Interpose all mem management function to whitelist the allocator. */
typedef void *(*orig_malloc_t)(size_t);
void *malloc(size_t s)
{
    static orig_malloc_t orig_malloc = NULL;
    void *p;
    ALLOC_ENTER(1);
    if (!orig_malloc)
    {
        ALLOC_ENTERED_REG();
        orig_malloc = (orig_malloc_t)dlsym(RTLD_NEXT, "malloc");
    }
    p = orig_malloc(s);
    ALLOC_EXIT(1);
    return p;
}

typedef void (*orig_free_t)(void *);
void free(void *p)
{
    static orig_free_t orig_free = NULL;
    ALLOC_ENTER(2);
    if (!orig_free)
        orig_free = (orig_free_t)dlsym(RTLD_NEXT, "free");

    orig_free(p);
    ALLOC_EXIT(2);
}


extern void *__libc_calloc(size_t, size_t);
void *calloc(size_t nelem, size_t elsize)
{
    void *p;
    ALLOC_ENTER(3);
    p = __libc_calloc(nelem, elsize);
    ALLOC_EXIT(3);
    return p;
}

typedef void *(*orig_memalign_t)(size_t, size_t);
void *memalign(size_t align, size_t size_arg)
{
    static orig_memalign_t orig_memalign = NULL;
    void *p;
    ALLOC_ENTER(4);
    if (!orig_memalign)
        orig_memalign = (orig_memalign_t)dlsym(RTLD_NEXT, "memalign");

    p = orig_memalign(align, size_arg);
    ALLOC_EXIT(4);
    return p;
}

typedef int (*orig_posix_memalign_t)(void **, size_t, size_t);
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    static orig_posix_memalign_t orig_posix_memalign = NULL;
    int ret;
    ALLOC_ENTER(5);
    if (!orig_posix_memalign)
        orig_posix_memalign =
            (orig_posix_memalign_t)dlsym(RTLD_NEXT, "posix_memalign");

    ret = orig_posix_memalign(memptr, alignment, size);
    ALLOC_EXIT(5);
    return ret;
}

typedef void *(*orig_valloc_t)(size_t);
void *valloc(size_t size)
{
    static orig_valloc_t orig_valloc = NULL;
    void *p;
    ALLOC_ENTER(6);
    if (!orig_valloc)
        orig_valloc = (orig_valloc_t)dlsym(RTLD_NEXT, "valloc");

    p = orig_valloc(size);
    ALLOC_EXIT(6);
    return p;
}

typedef void *(*orig_realloc_t)(void *, size_t);
void *realloc(void *buf_arg, size_t newsize)
{
    static orig_realloc_t orig_realloc = NULL;
    void *p;
    ALLOC_ENTER(7);
    if (!orig_realloc)
        orig_realloc = (orig_realloc_t)dlsym(RTLD_NEXT, "realloc");

    p = orig_realloc(buf_arg, newsize);
    ALLOC_EXIT(7);
    return p;
}
#endif

/* Disable the silly pid caching of glibc. */
pid_t getpid(void)
{
    return syscall(SYS_getpid);
}


/*
 * Tell monitor when the loader is done. We don't want to run mv on the loader,
 * as it may differ depending on different preloads.
 */
typedef int (*main_t)(int, char **, char **);
typedef int (*libc_start_main_t)(main_t main, int argc, char **ubp_av,
        void (*init)(void), void (*fini)(void), void (*rtld_fini)(void),
        void (*stack_end));
main_t main_orig;
int main_override(int argc, char **argv, char **envp)
{
    LOADER_DONE();
    return main_orig(argc, argv, envp);
}
int __libc_start_main( main_t main, int argc, char **ubp_av, void (*init)(void),
        void (*fini)(void), void (*rtld_fini)(void), void *stack_end)
{

    libc_start_main_t orig_libc_start_main;
    main_orig = main;

    pass_backtrace_to_kernel();

    orig_libc_start_main =
        (libc_start_main_t)dlsym(RTLD_NEXT, "__libc_start_main");
    (*orig_libc_start_main)(&main_override, argc, ubp_av, init, fini, rtld_fini,
            stack_end);

    exit(EXIT_FAILURE); /* This is never reached. */
}

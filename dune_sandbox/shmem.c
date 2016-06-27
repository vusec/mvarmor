#include <pthread.h>
#include <shalloc/shalloc.h>

#include "shmem.h"

struct shared
{
    pthread_mutex_t mutex, mutex_proclist;
    pthread_barrier_t barrier;
    shalloc_region_t *heap;
    int initialized;
    void *mv_state;
};

struct shared *shared;

extern pid_t proc_pid;
int print(const char *fmt, ...);

#define CHECK(x) \
    do { \
        int rc; \
        if ((rc = (x))) \
            print("ERROR: %d: %s: " #x ": %s\n", proc_pid, __func__, \
                    strerror(rc)); \
    } while (0);

void shmem_init()
{
    pthread_mutexattr_t attr;
    shalloc_region_t *heap;

    shalloc_space_init();
    shared = (struct shared *)SHALLOC_INHERIT_DATA;
    if (shared->initialized)
    {
        shalloc_space_freeze();
        return;
    }
    heap = shalloc_heap_to_region(shalloc_heap_create(SHALLOC_SPACE_SIZE,
                SHALLOC_MAP_INHERIT | MAP_ANONYMOUS, 0));
    assert(heap);
    shared->heap = heap;
    shared->initialized = 1;
    shared->mv_state = NULL;
    CHECK(pthread_mutexattr_init(&attr));
    CHECK(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
    CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL));
    CHECK(pthread_mutex_init(&shared->mutex, &attr));
    CHECK(pthread_mutex_init(&shared->mutex_proclist, &attr));
    CHECK(pthread_mutexattr_destroy(&attr));

    shalloc_space_freeze();
}

void shmem_lock()
{
    CHECK(pthread_mutex_lock(&shared->mutex));
}

void shmem_unlock()
{
    CHECK(pthread_mutex_unlock(&shared->mutex));
}

void shmem_lock_proclist()
{
    CHECK(pthread_mutex_lock(&shared->mutex_proclist));
}

void shmem_unlock_proclist()
{
    CHECK(pthread_mutex_unlock(&shared->mutex_proclist));
}

void *shmem_alloc(size_t size)
{
    void *rv;
    shmem_lock();
    rv = shalloc_malloc(shared->heap, size);
    shmem_unlock();
    return rv;
}

void shmem_free(void *ptr)
{
    shmem_lock();
    shalloc_free(shared->heap, ptr);
    shmem_unlock();
}

void *shmem_realloc(void *ptr, size_t new_size, size_t old_size)
{
    void *rv;
    shmem_lock();
    rv = shalloc_orealloc(shared->heap, ptr, new_size, old_size);
    shmem_unlock();
    return rv;
}

void shmem_exec_pre(void)
{
    /* For support across exec calls. */
    putenv(SHALLOC_GET_EXEC_ENVP()[0]);
}
void shmem_exec_post(void)
{
    unsetenv(SHALLOC_INHERIT_ID);
}

void shmem_barrier_init(int n)
{
    pthread_barrierattr_t attr;
    CHECK(pthread_barrierattr_init(&attr));
    CHECK(pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
    CHECK(pthread_barrier_init(&shared->barrier, &attr, n));
    CHECK(pthread_barrierattr_destroy(&attr));
}

void shmem_barrier_wait()
{
    int rc = pthread_barrier_wait(&shared->barrier);
    if (rc != 0 && rc != PTHREAD_BARRIER_SERIAL_THREAD)
        print("ERROR: %d: %s: pthread_barrier_wait: %s\n", proc_pid, __func__,
                strerror(rc));
}

void shmem_barrier_destroy()
{
    CHECK(pthread_barrier_destroy(&shared->barrier));
}

void shmem_mvstate_set(void *state)
{
    shared->mv_state = state;
}

void *shmem_mvstate_get(void)
{
    return shared->mv_state;
}

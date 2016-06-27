#ifndef SHMEM_H
#define SHMEM_H

#include <pthread.h>

void shmem_init();
void shmem_exec_pre(void);
void shmem_exec_post(void);

void shmem_lock();
void shmem_unlock();
void shmem_lock_proclist();
void shmem_unlock_proclist();
void shmem_barrier_init(int n);
void shmem_barrier_wait();
void shmem_barrier_destroy();

void *shmem_alloc(size_t size);
void shmem_free(void *ptr);
void *shmem_realloc(void *ptr, size_t new_size, size_t old_size);

void shmem_mvstate_set(void *state);
void *shmem_mvstate_get(void);

#endif

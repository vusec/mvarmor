#include <linux/futex.h>
#include <sys/syscall.h>

#include "multivar_internal.h"
#include "ringbuffer.h"


#define rdtsc_start(cycles) \
    do { \
        register unsigned _a, _d; \
        __asm__ __volatile__ ( \
                "rdtsc \n\t" \
                : "=a"(_a), "=d"(_d) \
                : \
                : "%rax", "%rdx"); \
        (cycles) = ((uint64_t)_d << 32) | _a; \
    } while (0)
#define rdtsc_end(cycles) \
    do { \
        register unsigned _a, _d; \
        __asm__ __volatile__ ( \
                "rdtscp \n\t" \
                : "=a"(_a), "=d"(_d) \
                : \
                : "%rax", "%rdx"); \
        (cycles) = ((uint64_t)_d << 32) | _a; \
    } while (0)


#define MAX_SPINLOCK_COUNT 100000000

static unsigned nreaders;
#ifdef RINGBUFFER_BENCH
static uint64_t cc_times, cc_lastid, cc_cyc;
#endif

int ringbuffer_init(unsigned nreaders_)
{
    nreaders = nreaders_;
#ifdef RINGBUFFER_BENCH
    cc_times = 0;
    cc_cyc = 0;
    cc_lastid = 43423432L;
#endif

    return 0;
}

/*
 * Creates a new shared ringbuffer and local ringbuffer state.
 */
void *ringbuffer_new(struct ringbuffer *ringbuffer)
{
#define ALIGN 64
    unsigned i;
    char *a = alloc_mem(sizeof(struct syscall) * RINGBUFFER_SIZE + ALIGN);
    ringbuffer->data = (void *)(a + (ALIGN - (uint64_t)a % ALIGN));
    ringbuffer->idx = 0;
    ringbuffer->last_var_id = 0;
    for (i = 0; i < RINGBUFFER_SIZE; i++)
    {
        ringbuffer->data[i].var_id_pre = 0;
        ringbuffer->data[i].var_id_post = 0;
        ringbuffer->data[i].nr = 39; /* getpid, has no args to free */
        ringbuffer->data[i].data_area = NULL;
        ringbuffer->data[i].data_size = 0;
        ringbuffer->data[i].ret_area = NULL;
        ringbuffer->data[i].ret_size = 0;

        ringbuffer->data[i].rb_completed = nreaders; /* get_new can grab it. */
        ringbuffer->data[i].rb_compared = 0;
        ringbuffer->data[i].rb_has_result = 0;
        ringbuffer->data[i].rb_has_saved = 0;
        ringbuffer->data[i].rb_sleeping = 0;
        ringbuffer->data[i].is_lockstep = 0;
    }
    return ringbuffer->data;
#undef ALIGN
}

/*
 * Creates a new ringbuffer state part of a shared ringbuffer.
 */
void ringbuffer_attach(struct ringbuffer *ringbuffer, void *orig_rb_data)
{
    assert(ringbuffer);
    assert(orig_rb_data);
    ringbuffer->idx = 0;
    ringbuffer->data = orig_rb_data;
    ringbuffer->last_var_id = 0;
}

/*
 * Claims the entry at ringbuffer->idx for filling of a task. Will spinlock
 * until ringbuffer->data[idx].reads == nreaders, meaning the previous task in
 * this slot is executed by all readers. This function will not change any of
 * the state; calling it twice will return the same ringbuffer entry. Use
 * mark_filled to mark the entry as ready after all data is placed in, and it
 * can be consumed by readers. This will also progress the state so the next
 * call to this function will try to get the next entry in the ringbuffer.
 */
struct syscall *ringbuffer_get_new(struct ringbuffer *ringbuffer)
{
    unsigned *r;
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);
    r = &ringbuffer->data[ringbuffer->idx].rb_completed;
    while (*r != nreaders)
        asm volatile("pause\n" ::: "memory");
    ringbuffer->data[ringbuffer->idx].rb_completed = 0;
    ringbuffer->data[ringbuffer->idx].rb_has_saved = 0;
    ringbuffer->data[ringbuffer->idx].rb_has_result = 0;
    ringbuffer->data[ringbuffer->idx].rb_compared = 0;
    ringbuffer->data[ringbuffer->idx].is_lockstep = 0;
    __sync_synchronize();
    return &ringbuffer->data[ringbuffer->idx];
}

void ringbuffer_mark_complete(struct ringbuffer *ringbuffer)
{
    unsigned *r;
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);
    assert(ringbuffer->data[ringbuffer->idx].rb_has_saved == 1);
    assert(ringbuffer->data[ringbuffer->idx].rb_has_result == 1);
    r = &ringbuffer->data[ringbuffer->idx].rb_completed;
    __sync_add_and_fetch(r, 1);
    ringbuffer->idx = (ringbuffer->idx + 1) % RINGBUFFER_SIZE;
}

struct syscall *ringbuffer_get_saved(struct ringbuffer *ringbuffer)
{
    char *rb_has_saved;
    unsigned long *rb_last_var_id, *rb_cur_var_id;
    unsigned *rb_completed;
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);

    rb_has_saved = &ringbuffer->data[ringbuffer->idx].rb_has_saved;
    rb_last_var_id = &ringbuffer->last_var_id;
    rb_cur_var_id = &ringbuffer->data[ringbuffer->idx].var_id_pre;
    rb_completed = &ringbuffer->data[ringbuffer->idx].rb_completed;
    while (*rb_completed == nreaders || *rb_last_var_id >= *rb_cur_var_id || *rb_has_saved == 0)
        asm volatile("pause\n" ::: "memory");
    assert(ringbuffer->data[ringbuffer->idx].rb_has_saved == 1);
    *rb_last_var_id = *rb_cur_var_id;
    return &ringbuffer->data[ringbuffer->idx];
}
void ringbuffer_mark_saved(struct ringbuffer *ringbuffer)
{
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);
    assert(ringbuffer->data[ringbuffer->idx].rb_has_saved == 0);
    assert(ringbuffer->data[ringbuffer->idx].rb_completed == 0);
    assert(ringbuffer->data[ringbuffer->idx].rb_compared == 0);
    assert(ringbuffer->data[ringbuffer->idx].rb_has_result == 0);

    ringbuffer->data[ringbuffer->idx].rb_has_saved = 1;
}
struct syscall *ringbuffer_get_prev(struct ringbuffer *ringbuffer)
{
    char *rb_has_saved;
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);

    rb_has_saved = &ringbuffer->data[ringbuffer->idx].rb_has_saved;
    while (*rb_has_saved == 0)
        asm volatile("pause\n" ::: "memory");
    return &ringbuffer->data[ringbuffer->idx];
}

void ringbuffer_wait_result(struct ringbuffer *ringbuffer)
{
    char *rb_has_result;
#if RINGBUFFER_SLEEP
    int *rb_sleeping;
    unsigned spinlock_counter = 0;
#endif
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);
    assert(ringbuffer->data[ringbuffer->idx].rb_has_saved);
    assert(ringbuffer->data[ringbuffer->idx].rb_completed != nreaders);

    rb_has_result = &ringbuffer->data[ringbuffer->idx].rb_has_result;
#if !RINGBUFFER_SLEEP
    while (*rb_has_result == 0)
        asm volatile("pause\n" ::: "memory");
#else
    while (*rb_has_result == 0 && spinlock_counter < MAX_SPINLOCK_COUNT)
    {
        spinlock_counter++;
        asm volatile("pause\n" ::: "memory");
    }

    if (*rb_has_result == 0)
    {
        rb_sleeping = &ringbuffer->data[ringbuffer->idx].rb_sleeping;
        *rb_sleeping = 1;
        if (*rb_has_result == 0)
            syscall(SYS_futex, rb_sleeping, FUTEX_WAIT, 1, NULL);
        else
            assert(!"ringbuffer: edge condition TODO");
        assert(*rb_has_result == 1);
    }
#endif
}
void ringbuffer_mark_result(struct ringbuffer *ringbuffer)
{
    struct syscall *s;
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);
    assert(ringbuffer->data[ringbuffer->idx].rb_has_saved);

    s = &ringbuffer->data[ringbuffer->idx];
    s->rb_has_result = 1;

#if RINGBUFFER_SLEEP
    if (s->rb_sleeping)
    {
        s->rb_sleeping = 0;
        syscall(SYS_futex, &s->rb_sleeping, FUTEX_WAKE, nreaders);
    }
#endif
    ringbuffer->idx = (ringbuffer->idx + 1) % RINGBUFFER_SIZE;
}


/* For lockstep-mode, where variants need 2 sync points per syscall. */
void ringbuffer_wait_compared(struct ringbuffer *ringbuffer)
{
    unsigned *rb_compared;
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);
    assert(ringbuffer->data[ringbuffer->idx].rb_has_saved);
    assert(ringbuffer->data[ringbuffer->idx].rb_completed != nreaders);

    rb_compared = &ringbuffer->data[ringbuffer->idx].rb_compared;
    while (*rb_compared != nreaders)
        asm volatile("pause\n" ::: "memory");
}
void ringbuffer_mark_compared(struct ringbuffer *ringbuffer)
{

    unsigned *r;
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);
    assert(ringbuffer->data[ringbuffer->idx].rb_has_saved);
    assert(ringbuffer->data[ringbuffer->idx].rb_completed != nreaders);
    assert(ringbuffer->data[ringbuffer->idx].rb_has_result == 0);
    r = &ringbuffer->data[ringbuffer->idx].rb_compared;
    __sync_add_and_fetch(r, 1);
}


/*
 * ===========================
 * == Non-blocking versions ==
 * ===========================
 */

struct syscall *ringbuffer_try_get_new(struct ringbuffer *ringbuffer)
{
    unsigned *r;
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);
    r = &ringbuffer->data[ringbuffer->idx].rb_completed;
    if (*r != nreaders)
        return NULL;
    ringbuffer->data[ringbuffer->idx].rv = 0;
    ringbuffer->data[ringbuffer->idx].rb_completed = 0;
    ringbuffer->data[ringbuffer->idx].rb_has_saved = 0;
    ringbuffer->data[ringbuffer->idx].rb_has_result = 0;
    ringbuffer->data[ringbuffer->idx].rb_compared = 0;
    ringbuffer->data[ringbuffer->idx].is_lockstep = 0;
    return &ringbuffer->data[ringbuffer->idx];
}

struct syscall *ringbuffer_try_get_saved(struct ringbuffer *ringbuffer)
{
    char *rb_has_saved;
    unsigned long *rb_last_var_id, *rb_cur_var_id;
    unsigned *rb_completed;
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);

    rb_has_saved = &ringbuffer->data[ringbuffer->idx].rb_has_saved;
    rb_last_var_id = &ringbuffer->last_var_id;
    rb_cur_var_id = &ringbuffer->data[ringbuffer->idx].var_id_pre;
    rb_completed = &ringbuffer->data[ringbuffer->idx].rb_completed;
    if (*rb_completed == nreaders || *rb_last_var_id == *rb_cur_var_id || *rb_has_saved == 0)
        return NULL;
    *rb_last_var_id = *rb_cur_var_id;
    return &ringbuffer->data[ringbuffer->idx];
}

int ringbuffer_check_result(struct ringbuffer *ringbuffer)
{
    char *rb_has_result;
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);
    assert(ringbuffer->data[ringbuffer->idx].rb_has_saved);
    assert(ringbuffer->data[ringbuffer->idx].rb_completed != nreaders);

    rb_has_result = &ringbuffer->data[ringbuffer->idx].rb_has_result;
    if (*rb_has_result == 0)
        return 0;
    return 1;
}

/* For lockstep-mode, where variants need 2 sync points per syscall. */
int ringbuffer_check_compared(struct ringbuffer *ringbuffer)
{
    unsigned *rb_compared;
    assert(ringbuffer);
    assert(ringbuffer->data);
    assert(ringbuffer->idx <= RINGBUFFER_SIZE);
    assert(ringbuffer->data[ringbuffer->idx].rb_has_saved);

    rb_compared = &ringbuffer->data[ringbuffer->idx].rb_compared;
    if (*rb_compared != nreaders)
        return 0;
    return 1;
}

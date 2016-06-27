#ifndef RINGBUFFER_H
#define RINGBUFFER_H

#include <stdint.h>

#ifndef RINGBUFFER_SIZE
#define RINGBUFFER_SIZE 1
#endif
#ifndef RINGBUFFER_SLEEP
#define RINGBUFFER_SLEEP 1
#endif

/* Thread-local info about (their) state of the ringbuffer. Thus, the index is
 * per-thread but but points to the shared ringbuffer. */
struct ringbuffer
{
    struct syscall *data; /* First elem of ringbuffer. */
    unsigned idx;
    unsigned long last_var_id;
};

/*
 * General operation of the ringbuffer, and mv-execution in general. Functions
 * starting with rb_ indicate ringbuffer interactions (replacing ringbuffer_
 * with rb_), others are pseudo-ops executed by multivar.c.
 *
 *   NORMAL (without lockstep):
 *
 *  LEADER              FOLLOWER
 *  rb_get_new          save
 *  save                rb_get_saved
 *  ...                 ...
 *  rb_mark_saved    -> .w.
 *  order_pre           compare
 *  pre, EXEC, post     order_pre
 *  ...                 pre, EXEC, post
 *  ...                 rb_wait_res
 *  ...                 post
 *  rb_mark_res      -> .w.
 *  order post          order post
 *                      rb_mark_handled
 *
 *
 *   LOCKSTEP (rb_wait_varn, rb_wait_all before EXEC):
 *
 *  LEADER              FOLLOWER
 *  rb_get_new          save
 *  save                rb_get_saved
 *  ...                 ...
 *  rb_mark_saved    -> .w.
 *  rb_wait_varn        compare
 *  ...                 ...
 *  .w.             <-> rb_wait_all
 *  order pre           order pre
 *  pre, EXEC, post     pre, EXEC, post
 *  ...                 rb_wait_res
 *  ...                 post
 *  ...                 ...
 *  rb_mark_res      -> .w.
 *  order post          order post
 *                      rb_mark_handled
 */


/* Ringbuffer creation/setup. */
int ringbuffer_init(unsigned nreaders);
void *ringbuffer_new(struct ringbuffer *ringbuffer);
void ringbuffer_attach(struct ringbuffer *ringbuffer, void *orig_rb_data);

/* Normal synchronization, see above for how these are used. */
struct syscall *ringbuffer_get_new(struct ringbuffer *ringbuffer);
void ringbuffer_mark_complete(struct ringbuffer *ringbuffer);

struct syscall *ringbuffer_get_saved(struct ringbuffer *ringbuffer);
void ringbuffer_mark_saved(struct ringbuffer *ringbuffer);
struct syscall *ringbuffer_get_prev(struct ringbuffer *ringbuffer);

void ringbuffer_wait_result(struct ringbuffer *ringbuffer);
void ringbuffer_mark_result(struct ringbuffer *ringbuffer);

/* For lockstep-mode, where variants need 2 sync points per syscall. */
void ringbuffer_wait_compared(struct ringbuffer *ringbuffer);
void ringbuffer_mark_compared(struct ringbuffer *ringbuffer);

/* Non-blocking versions of retrieval functions. */
struct syscall *ringbuffer_try_get_new(struct ringbuffer *ringbuffer);
struct syscall *ringbuffer_try_get_saved(struct ringbuffer *ringbuffer);
int ringbuffer_check_result(struct ringbuffer *ringbuffer);
int ringbuffer_check_compared(struct ringbuffer *ringbuffer);

#endif

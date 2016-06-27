# libmultivar (libmv)
Portable multi-variant execution library.

This library provides the back-end of the MVX system, and takes care of all MVX
operations such as syscall comparison, emulation in variants, synchronization,
etc. It is implemented in a front-end agnostic way, and thus communicates with
the application and environment via a set of provided functions.

## Usage
The public interface is defined in `multivar.h`. A front-end using this library
should link against this library, include the header file. Then, it should
expose a number of functions that the library should use to interact with the
environment. This keeps the library portable, to allow e.g. the Dune and ptrace
front-ends.

 - `alloc_mem_shared`: Allocate memory visible to all monitors (in case of
   multiple processes each running their own libmv, e.g. a monitor per process).
 - `free_mem_shared`: Free mem allocated with `alloc_mem_shared`.
 - `realloc_mem_shared`: Realloc (resize) mem allocated with `alloc_mem_shared`.
   This will also receive the old size of the allocated memory.
 - `alloc_mem_local`: Allocate memory local to variant (can be more efficient
   than `alloc_mem_shared`, usually this is the normal `malloc`).
 - `free_mem_local`: Free mem allocated with `alloc_mem_local`.
 - `realloc_mem_local`: Resize memory allocated with `alloc_mem_local`.
 - `copy_from_user`: Perform a copy from the address space of the application
   being monitored, to the monitor. In case the monitor runs in the same address
   space, this can be a simple `memcpy`, but for `ptrace` this requires access
   to another address space.
 - `copy_to_user`: Same as `copy_from_user` but the opposite direction.
 - `print`: Print messages (errors, warnings, optionally debugging).
 - `backtrace`: Print a backtrace of the current location of the program being
   monitored, used for debugging.

The front-end should initialize libmv using `mv_init`, providing these
functions, the number of variants running (including the leader), and whether
the monitor should operate in non-blocking or blocking mode. In **blocking
mode** the synchronization between variants blocks inside libmv (using for
instance spinlocks of futexes). This is generally more performant, but can only
be used when there is a monitor/libmv per thread running. **Non-blocking mode**
on the other hand leaves the waiting to the front-end, which means hooks
(discussed later) can return before they complete (which is indicated by their
return value. This mode is currently used for the `ptrace` front-end, where
there is a single monitor controlling all the variant processes.

After initialization, the front-end should inform libmv when certain events
occur, which can be classified as into two categories: sync points (syscalls,
`rdtsc`) and process management.

The library keeps an internal representation of all variants, processes and
threads, which should be kept up-to-date with the actual state of the system.
Thus, when a process or thread gets created or killed, the front-end should
inform libmv. These is also quite a number of function to access to internal
state later on for the front-end. For a complete list, see `multivar.h`.

The most important task of libmv is to handle synchronization points, primarily
syscalls. The library has two hooks for this: `mv_syscall_enter` and
`mv_syscall_exit`. These should be called when the syscall is first observed and
after it finished executing (and the return value is known) respectively. These
calls should **always** come in pairs. These calls can return a number of
actions, encoded as bits in the return value. The exact possible return values
depend on the function and whether libmv is in blocking or non-blocking mode.
For full explanation of these actions, see `multivar.c` for now.

## Internal workings
Internally, libmv consists of several components to achieve all actions required
for MVX. As discussed in the Usage section, there is only a limited number of
entry points into libmv. Most components are only used internally, often by the
`mv_syscall_enter` and `mv_syscall_exit` calls. These calls are implemented in
`multivar.c`, which acts as the global entry point to coordinate the operation
of all other components. A list of all components is as follows:

 - `proclist`: The internal administration of variants, processes and threads.
   These are all stored as linked lists representing the trees (i.e., there is a
   global list of all variants, each having one or more processes, each having
   one or more threads). Part of this component is exposed to the front-end with
   the function in `multivar.h`.
 - `save_args`: Saves all arguments of a syscall into the address space of the
   monitor. In the case of simple arguments, this just involved copying the
   value of the registers. However, when points to buffers and structs are
   passed to a syscall, this component will copy all of this into the local
   address space.
 - `compare_args`: After the syscall arguments have been copied, this component
   can determine whether two syscalls are equivalent. It will ignore pointer
   values (as those should be different), but it will do a semantic comparison
   of any buffer/struct passed to a syscall.
 - `debugging`: An strace-like debugging component, which can print a
   human-readable version of most syscalls, including buffers/structs.
 - `syscall_types`: Determines the *type* of any syscall. This can be any of
   four types: *one* (only leader can execute the syscall for real), *all* (all
   variants execute the syscall), *fake* (all variants should not execute the
   syscall) and *todo* (syscall not implemented by libmv yet). Some types are
   dynamic based on the arguments at run-time, in particular *one* syscalls can
   become *all* syscalls, which is also determined by this component.
 - `syscall_pre`: Determines the syscall-specific actions that should be
   performed, based also on the *type*. This includes mostly argument
   rewriting (for file descriptor and pid virtualization).
 - `syscall_post`: Same as `syscall_pre`, but then after the syscall has been
   performed(/faked). This mostly involves copying return values passed in
   buffers/structs to the leader (in the case of *one* syscalls) to the shared
   address space of the monitors, and then back into all the followers.
 - `ringbuffer`: Implements all synchronization of the monitor(s). While
   `multivar.c` determines when programs should sync (e.g., "wait for leader to
   have a return value"), this component implements the underlying conditions to
   satisfy this. This component tries to use spinlocks as much as possible for
   performance, but will sleep if this takes too long (which happens when a
   syscall itself blocks for a longer time). The component has both blocking and
   non-blocking versions of all sync actions, which are distinguished between
   `wait_` and `try_` prefixes.
 - `security`: Implements the security policies per syscall, determining whether
   the syscall is safe (ignored by the monitor), normal or unsafe (requiring
   lockstep, meaning more synchronization points).
 - `multivar_sync_nonblocking`: The normal/simple case of non-blocking
   high-level synchronization, as previously discussed, is implemented in
   `multivar.c`. However, the more complicated, and normally not used,
   non-blocking implementations are found in this component.

## Adding a syscall
While libmv already supports a large number of syscalls, the implementation is
not complete. Luckily, the process of adding support for a syscall is trivial in
most cases. It does require some knowledge about the syscall and its parameters
however, which in most cases can be found in the respectively manpage. However,
note that in some cases the libc wrapper described in manpages does not match
the syscall signature. Moreover, note that sometimes the libc data structures do
not match the data structures that are passed to the kernel.

 - Add the arguments that are buffers/structs to `save_args.c`, by indicating
   their size. This works for most (simple) cases, but syscalls that require
   complex data structures with nested pointers may require manual serializing,
   see examples in the same file.
 - Compare both arguments in `compare_args.c`. There are two sycalls as inputs
   (var 0 and var n), and for each variant there are two arrays: `orig_args` and
   `arg_data`. The former contains the raw arguments that were passed by the
   application, whereas the latter are only filled when instructed to by
   `save_args.c`. They will point to a buffer in the address space of the
   monitor, the size of which is set in `save_args.c`.
 - Define the type in `syscall_types.c`, and optionally add more dynamic type
   into in the function at the end of the same file.
 - If a syscall requires arg rewriting (deals with PIDs or FDs) add this in
   `syscall_pre.c`.
 - If a syscall requires a fake return value (but is not ONE), requires buffers
   that contain return values to be copied to followers, or can create new file
   descriptors, add this logic to `syscall_post.c`.
 - *Optional:* Add nicer debug output to `debugging.c`.

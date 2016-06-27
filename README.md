# MvArmor
Multi-variant execution (MVX) source code. MvArmor aims to provide both high
performance and security, and was published at the DSN'16 conference:

*Secure and Efficient Multi-variant Execution Using Hardware-assisted Process
Virtualization* by Koen Koning, Herbert Bos and Cristiano Giuffrida.

The MVX engine consists of two parts: the *back-end* providing all MVX-related
semantics such as copying and comparing system calls, and the *front-end*
intercepting all system calls and other behavior of a program.

The *back-end* is implemented as a shared library and can be found in the
`libmultivar` directory. It contains a number of call-backs that the front-end
must invoke, for instance when a system call is executed. A front-end must also
provide some information and function-pointers to the library during
initialization, which may differ per front-end. This includes how to allocate
memory, how to allocate shared memory (visible to all variants) and how to
access the address space of the variants.

This repository contains several *front-end* implementations:

 - `ptrace`: slow implementation using a `ptrace` monitor, for debugging. Does
             currently not support full variant-generation and intercepting
             `rdtsc`.
 - `dune_sandbox`: efficient implementation using Dune. Only front-end that
                   supports full variant generation.

## Setup and usage
### Dependencies:
MvArmor requires a 64-bit Linux, and has been tested on Debian Jessie (with 3.2
kernel) and Ubuntu 14.04.  Especially for Dune, the Linux and glibc versions
installed may not be supported. Linux 3.19 should work, higher versions most
likely won't compile the Dune kernel module.

External dependencies include libcap, libunwind and Linux headers. On
Debian, use:
```sudo apt-get install build-essential libcap-dev linux-headers-amd64 libunwind-dev```
Or on Ubuntu:
```sudo apt-get install build-essential libcap-dev linux-headers-generic libunwind8-dev liblzma-dev```

Furthermore, there are several dependency projects. All of these can be
automatically downloaded and compiled using `make deps`. These are currently
only required when using the **Dune**-based front-end.

 - libumem fork: sparse heap for variant generation (https://github.com/vusec/libumem-mvx)
 - shalloc: simple allocator for shared memory regions (https://github.com/vusec/shalloc)
 - dune fork: mvarmor-specific compatibility patches (https://github.com/vusec/dune)

### Compiling
(*Optional*: set up dependencies for Dune front-end using `make deps`, or set
them up manualy and modify `config.mk`).

Running `make` should build the MVX library and all fronte-ends.

### Usage
For the Dune frontend, insert the kernel module with `deps/dune/dune_ins.sh`.

Test with `make -C test test_ptrace` or `make -C test test_dunesb`. This
executes a number of small test cases, and should complete within a few seconds.
Note that the `rdtsc` test case fails for ptrace.

Configure the number of variants (default 2):
```export MV_NUM_PROC=2```

When running testcases where the monitor should stay attached to all procs
(i.e., normally the process used to start MVX will exit once all variants are
running, with this option set it will wait until all variants have exited).
This is useful also when benchmarking SPEC for instance.
```export MV_DONT_DETACH=1```

Use `libumem` (different allocator) for **followers**:
```export MV_UMEM=1```
Optionally, configure slab behavior of `libumem`:
```
export MV_SLAB_MAX=1   # max objects per slab
export MV_SLAB_PAD=1K  # padding per slab
```

Then prepend the binary of the choosen front-end to normal execution, e.g.:
```
cd dune_sandbox
./multivar_dune_sandbox /bin/ls
```

## Configuration
### Compilation
When compiling libmultivar:
```
cd libmultivar
make clean
make OPT=val OPT2=val2 ...
```
Valid options are:

 - `RINGBUFFER_SIZE`: Size of ringbuffer (how much leader and followers can
   deviate when there are no `unsafe` syscalls. (default: 10)
 - `RINGBUFFER_SLEEP`: Are processes waiting for the ringbuffer allowed to sleep
   (instead of spinlock) after a while? Going to sleep (using `futex`) is a
   relatively expensive operation (so the time after which they do this should
   be finetuned too), but it does free up a core for other executions. (default:
   1)
 - `SYSCALL_ORDERING`: Force ordering of system calls between different
   processes/threads across variants. (default: 1)
 - `TIMING_ENABLE`: Enable timing (benchmarking) of regions of the monitor.
   (default: 0)
 - `ENABLE_ASSERT`: When disabled, any assert statement in the code will be
   removed by the preprocessor. (default: 1)
 - `VARN_OPEN_RO`: Allow followers to open their own files when they are
   read-only. (default: 1)
 - `SEC_POL`: Security policy to use (i.e., which system calls are unsafe).
   (default: 2)
    * 0 = all regular (*performance*, no lockstep at all)
    * 1 = all unsafe (*comprehensive*)
    * 2 = exec-related unsafe (*code execution*)
    * 3 = write and similar unsafe (*information leakage*)

Additionally, the following command can be used to force recompilation of the
security component:
```
cd libmultivar
make secpol SEC_POL=n
```

### Execution
When starting the application, the monitor will read the environment for some
additional options. Some may not be available for all front-ends.

 - `MV_NUM_PROC`: Number of variant to run. E.g., a value of 2 will result in 1
   leader and 1 follower. (default: 2)
 - `MV_DONT_DETACH`: When set, the process which starts all variants will stay
   attached. Useful when running or benchmarking non-server applications such as
   SPEC or the testcases. (default: 0)
 - `MV_OUT_TO_FILE`: Send all debug-output of libmultivar (enabled in
   `multivar.c`) to variant-specific files. Normally, all output is sent to
   stderr, which may result in overlapping of messages. (default: 0)
 - `MV_UMEM`: Enable the alternative `libumem` heap allocator for followers.
   (default: 0)
 - `MV_SLAB_MAX`: *(implies `MV_UMEM`)* Maximum objects allowed in a slab.
   (default: 10000)
 - `MV_SLAB_PAD`: *(implies `MV_UMEM`)* Size of the guard-zone after every slab.
   Can be a string such as "128K" or "4G". (default: 0)
 - `MV_VAR_NUM`: **used internally** When spawning the variants, this variable
   is temporarily set to indicate what variant each process is. It is unset
   before the actual application is started, to provide an identical environment
   to every variant.

## Troubleshooting

error while loading shared libraries: libmultivar.so: cannot open shared object
file: No such file or directory
```
 $ export LD_LIBRARY_PATH=/path/to/libmultivar
```

---

Permission errors with ptrace frontend (e.g., failed to open `/proc/<pid>/mem`
or ptrace errors in dmesg):
```
 $ echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

---

Assertion `inherit_mem_id != -1' failed.
```
 $ sudo sysctl -w kernel.shmmax=1073717248
```

---

segfault at 0 before dune-mode:
Does the shalloc region overlap with Dune sandbox memory layout?
```
include/shalloc/shalloc.h:
 -#    define SHALLOC_BASE_ADDR               ((unsigned) 0x60000000)
 -#    define SHALLOC_LAST_ADDR               ((unsigned) 0x9FFFFFFF)
 +#    define SHALLOC_BASE_ADDR               ((unsigned) 0x80000000)
 +#    define SHALLOC_LAST_ADDR               ((unsigned) 0xBFFFFFFF)
```



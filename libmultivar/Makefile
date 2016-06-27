# Size of the ringbuffer; the maximum distance var0 and varn can deviate
RINGBUFFER_SIZE = 10

# Whether the ringbuffer can cause processes to sleep
RINGBUFFER_SLEEP = 1

# Security policy, 0=no unsafe, 1=all unsafe, 2=exec, 3=info leak
SEC_POL = 2

# System call ordering ensures multi-process/multi-threaded applications execute
# system calls in the same order as the leader-variant.
SYSCALL_ORDERING = 1

# Keep track of timing info to profile part of the code
TIMING_ENABLE = 0

# Enable/disable assert() macro's which check for consistency
ENABLE_ASSERT = 1

# Allow varn procs to open read-only files, or copy read data from var0?
VARN_OPEN_RO = 1

include ../config.mk

CFLAGS = -Wall -Wextra -O2 -g -fpic -MD -DTIMING_ENABLE=$(TIMING_ENABLE) \
		 -DENABLE_ASSERT=$(ENABLE_ASSERT) -DVARN_OPEN_RO=$(VARN_OPEN_RO) \
		 -DRINGBUFFER_SIZE=$(RINGBUFFER_SIZE) \
		 -DRINGBUFFER_SLEEP=$(RINGBUFFER_SLEEP) -DSEC_POL=$(SEC_POL) \
		 -DSYSCALL_ORDERING=$(SYSCALL_ORDERING)
LDFLAGS = -O2

all: libmultivar.so

clean:
	rm -f *.d *.o *.so *.a

# Triggers regen of syscall_signatures.h
cleanall:
	rm -f *.d *.o *.so *.a *.tmp syscall_signatures.h

libmultivar.so: multivar.o proclist.o debugging.o save_args.o compare_args.o \
			    syscall_types.o syscall_pre.o syscall_post.o ringbuffer.o \
				security.o multivar_sync_nonblocking.o
	$(CC) -shared -o $@ $^ $(LDFLAGS)

ringbuffer.o: ringbuffer.c
	$(CC) $(CFLAGS)   -c -o ringbuffer.o ringbuffer.c

# Forces to rebuild security.o (and relinks library) for updating security
# policies (e.g. do ``make secpol SEC_POL=1'').
secpol:
	$(CC) $(CFLAGS) -c -o security.o security.c
	make libmultivar.so


# Generate all syscall type info from current linux sources etc.
syscall_nrs.tmp:
	echo "#include <sys/syscall.h>" | gcc - -E -dM | grep "#define __NR_" \
		> syscall_nrs.tmp
rebuild_syscall_signatures.h: syscall_nrs.tmp generate_syscall_info.py
	python3 generate_syscall_info.py

-include *.d

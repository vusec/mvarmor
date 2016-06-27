include ../config.mk

MV_DUNESB = $(MVX_DIR)/dune_sandbox/multivar_dune_sandbox
MV_PTRACE = $(MVX_DIR)/ptrace/multivar_ptrace

CFLAGS  = -Wall -O2 -g -pthread
PROGS = gettid getpid fork env fstat pipe signals epoll gettimeofday getpid_libc recvmsg futex
PROGS_DUNE = rdtsc


all: $(PROGS) $(PROGS_DUNE)
test: $(PROGS) $(PROGS_DUNE)
	./run_tests.sh "" $(PROGS) $(PROGS_DUNE)
test_dunesb: $(PROGS) $(PROGS_DUNE)
	./run_tests.sh $(MV_DUNESB) $(PROGS) $(PROGS_DUNE)
test_ptrace: $(PROGS)
	./run_tests.sh $(MV_PTRACE) $(PROGS)


%: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)


clean:
	rm -f *.o *.d *.out $(PROGS) $(PROGS_DUNE)


# For benchmarking the baseline of system call interposing, disable MV behavior.
NO_MV = 0

include ../config.mk

CFLAGS = -Wall -Wextra -g -O2 -I.. -DNO_MV=$(NO_MV)
LDFLAGS = -O2 -L../libmultivar -Wl,-rpath=$(MVX_DIR)/libmultivar -lmultivar \
		  -lunwind-ptrace -lunwind-generic

OSNAME := $(shell command -v lsb_release >/dev/null && lsb_release -si)

ifeq ($(OSNAME),Ubuntu)
# Ubuntu requires this explicitly for libunwind
LDFLAGS += -llzma
endif

all: multivar_ptrace libpreload.so

multivar_ptrace: main.o
	$(CC) -o $@ $^ $(LDFLAGS)

libpreload.so: libpreload.c
	$(CC) -o $@ $^ $(CFLAGS) -fpic -shared

../libmultivar/libmultivar.so:
	make -C ../libmultivar libmultivar.so

clean:
	rm *.o multivar_ptrace

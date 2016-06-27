# For benchmarking the baseline of system call interposing, disable MV behavior.
NO_MV = 0

include ../config.mk

LIBMEM_PATH = $(MVX_DIR)/dune_sandbox/libmem.so

CFLAGS = -Wall -Wextra -g -O2 -I.. -I $(DUNE_DIR) -I ${DUNE_DIR}/apps/sandbox \
		 -I $(SHALLOC_DIR)/include -DNO_MV=$(NO_MV) \
		 -DLIBMEM_PATH=\"$(LIBMEM_PATH)\" \
		 -DLIBUMEM_MALLOC_PATH=\"$(LIBUMEM_MALLOC_PATH)\"
LDFLAGS = -O2 -L../libmultivar -Wl,-rpath=$(MVX_DIR)/libmultivar -lmultivar \
			-L${DUNE_DIR}/libdune -L${DUNE_DIR}/apps/sandbox -lsandbox -ldune \
			$(SHALLOC_DIR)/shalloc.so -lpthread \
			-Wl,-T${DUNE_DIR}/apps/sandbox/sandbox.ld -fuse-ld=bfd

all: multivar_dune_sandbox libmem.so
mv:
	make -C ../libmultivar libmultivar.so

multivar_dune_sandbox: main.o shmem.o ../libmultivar/libmultivar.so
	$(CC) -o $@ main.o shmem.o $(LDFLAGS)

libmem.so: libmem.c
	$(CC) $(CFLAGS) -fno-builtin-malloc $^ -o $@ -shared -fPIC -ldl -lunwind

../libmultivar/libmultivar.so:
	make -C ../libmultivar libmultivar.so

clean:
	rm -f *.o multivar_dune_sandbox *.so

# Machine dependent paths for external dependencies
# Note that these must be absolute paths (e.g., no ~)
#
# These can be automatically configured by running `make deps`

MVX_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Libumem's malloc library (for LD_PRELOADing)
LIBUMEM_MALLOC_PATH = $(MVX_DIR)/deps/libumem/install/lib/libumem_malloc.so.0

# Top level of Dune repo
DUNE_DIR = $(MVX_DIR)/deps/dune

# Top level of shalloc
SHALLOC_DIR = $(MVX_DIR)/deps/shalloc

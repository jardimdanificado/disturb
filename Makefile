CC = gcc
DISABLE_IO ?= 0
UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
IS_WINDOWS := $(findstring MINGW,$(UNAME_S))

# --- Optimization feature flags (all optional, off by default) -----------
# DISTURB_ENABLE_SIMD=1      → compile with SIMD intrinsics (AVX2/SSE/NEON)
# DISTURB_ENABLE_PARALLEL=1  → compile thread pool / task module (requires pthreads)
# DISTURB_ENABLE_GPU=1       → compile OpenCL compute module
# DISTURB_ENABLE_LTO=1       → link-time optimisation
# DISTURB_ENABLE_PGO_GEN=1   → PGO: generate profile data  (-fprofile-generate)
# DISTURB_ENABLE_PGO_USE=1   → PGO: use profile data       (-fprofile-use)
DISTURB_ENABLE_SIMD     ?= 0
DISTURB_ENABLE_PARALLEL ?= 0
DISTURB_ENABLE_GPU      ?= 0
DISTURB_ENABLE_LTO      ?= 0
DISTURB_ENABLE_PGO_GEN  ?= 0
DISTURB_ENABLE_PGO_USE  ?= 0

# Optimization level: -O3 for desktop, -Os for embedded (size-optimized)
ifeq ($(DISABLE_IO),1)
  BASE_OPT = -Os
else
  BASE_OPT = -O3
endif

CFLAGS = $(BASE_OPT) -std=c99 -Wall -Wextra -pedantic -Iinclude -Ilib/libregexp -Ilib/
LIBREGEXP_CFLAGS = -Wno-unused-parameter -Wno-sign-compare -Wno-pedantic
LDFLAGS = -lm

# --- SIMD ---------------------------------------------------------------
ifeq ($(DISTURB_ENABLE_SIMD),1)
	CFLAGS += -DDISTURB_ENABLE_SIMD
	# Auto-detect best x86 SIMD level the host supports
	HAS_AVX2 := $(shell $(CC) -mavx2 -dM -E - < /dev/null 2>/dev/null | grep -c __AVX2__)
	HAS_SSE42 := $(shell $(CC) -msse4.2 -dM -E - < /dev/null 2>/dev/null | grep -c __SSE4_2__)
	ifneq ($(HAS_AVX2),0)
		CFLAGS += -mavx2 -mfma
	else ifneq ($(HAS_SSE42),0)
		CFLAGS += -msse4.2
	endif
	# ARM NEON is typically on by default for aarch64
endif

# --- Parallelism (pthreads) ---------------------------------------------
ifeq ($(DISTURB_ENABLE_PARALLEL),1)
	CFLAGS += -DDISTURB_ENABLE_PARALLEL
	LDFLAGS += -lpthread
endif

# --- GPU (OpenCL) -------------------------------------------------------
ifeq ($(DISTURB_ENABLE_GPU),1)
	CFLAGS += -DDISTURB_ENABLE_GPU
	LDFLAGS += -lOpenCL
endif

# --- LTO ----------------------------------------------------------------
ifeq ($(DISTURB_ENABLE_LTO),1)
	CFLAGS  += -flto
	LDFLAGS += -flto
endif

# --- PGO ----------------------------------------------------------------
ifeq ($(DISTURB_ENABLE_PGO_GEN),1)
	CFLAGS  += -fprofile-generate
	LDFLAGS += -fprofile-generate
endif
ifeq ($(DISTURB_ENABLE_PGO_USE),1)
	CFLAGS  += -fprofile-use -fprofile-correction
	LDFLAGS += -fprofile-use
endif

# --- Embedded / IO ------------------------------------------------------
ifeq ($(DISABLE_IO),1)
	CFLAGS += -DDISTURB_EMBEDDED
endif

ifeq ($(DISABLE_IO),0)
	CFLAGS += -DDISTURB_ENABLE_IO
endif

CFLAGS += -DDISTURB_ENABLE_FFI
ifeq ($(DISABLE_IO),0)
	CFLAGS += -DDISTURB_ENABLE_FFI_CALLS
	LDFLAGS += -lffi
ifeq ($(IS_WINDOWS),)
ifneq ($(UNAME_S),Darwin)
	LDFLAGS += -ldl
endif
endif
endif

# --- Sources ------------------------------------------------------------
SRC = lib/libregexp/cutils.c lib/libregexp/libunicode.c lib/libregexp/libregexp.c \
      src/vm.c src/bytecode.c src/syntax.c src/functions.c src/papagaio.c src/cli.c src/ffi.c

ifeq ($(DISTURB_ENABLE_PARALLEL),1)
	SRC += src/parallel.c
endif
ifeq ($(DISTURB_ENABLE_GPU),1)
	SRC += src/gpu.c
endif

OBJ = $(SRC:.c=.o)

all: disturb

disturb: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

test-raylib: disturb
	sh tests/run_raylib_examples.sh

lib/libregexp/%.o: lib/libregexp/%.c
	$(CC) $(CFLAGS) $(LIBREGEXP_CFLAGS) -c $< -o $@

%.o: %.c include/vm.h include/papagaio.h include/bytecode.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) disturb

# --- PGO targets ---------------------------------------------------------
# Usage:
#   make pgo          — full PGO cycle (gen → train → use)
#   make pgo-gen       — build instrumented binary
#   make pgo-use       — build optimised binary from profile data
PGO_FLAGS_GEN = -fprofile-generate
PGO_FLAGS_USE = -fprofile-use -fprofile-correction

pgo-gen:
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) $(PGO_FLAGS_GEN)" LDFLAGS="$(LDFLAGS) $(PGO_FLAGS_GEN)"
	@echo "=== PGO: running training workload ==="
	-./disturb tests/run.sh 2>/dev/null || true
	@echo "=== PGO: profile data generated ==="

pgo-use:
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) $(PGO_FLAGS_USE)" LDFLAGS="$(LDFLAGS) $(PGO_FLAGS_USE)"
	@echo "=== PGO: optimised build complete ==="

pgo: pgo-gen pgo-use

.PHONY: all clean test-raylib pgo pgo-gen pgo-use

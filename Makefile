CC = gcc
DISABLE_IO ?= 0
UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
IS_WINDOWS := $(findstring MINGW,$(UNAME_S))

# --- Optimization feature flags ------------------------------------------
# Set to 0 to explicitly disable. By default, each feature is auto-detected:
#   SIMD     — enabled if the compiler supports AVX2, SSE4.2, or NEON
#   PARALLEL — enabled if pthreads is available
#   GPU      — enabled if OpenCL headers + library are available
# Override: make DISTURB_ENABLE_SIMD=0  (force off)
#           make DISTURB_ENABLE_GPU=1   (force on)
# DISTURB_ENABLE_LTO=1       → link-time optimisation
# DISTURB_ENABLE_PGO_GEN=1   → PGO: generate profile data  (-fprofile-generate)
# DISTURB_ENABLE_PGO_USE=1   → PGO: use profile data       (-fprofile-use)

# --- Auto-detect SIMD ----------------------------------------------------
ifndef DISTURB_ENABLE_SIMD
  _HAS_AVX2  := $(shell $(CC) -mavx2 -mfma -x c -c /dev/null -o /dev/null 2>/dev/null && echo 1 || echo 0)
  _HAS_SSE42 := $(shell $(CC) -msse4.2 -x c -c /dev/null -o /dev/null 2>/dev/null && echo 1 || echo 0)
  _HAS_NEON  := $(shell $(CC) -x c -E -dM - < /dev/null 2>/dev/null | grep -c __ARM_NEON)
  ifneq ($(_HAS_AVX2)$(_HAS_SSE42)$(_HAS_NEON),000)
    DISTURB_ENABLE_SIMD := 1
  else
    DISTURB_ENABLE_SIMD := 0
  endif
endif

# --- Auto-detect pthreads ------------------------------------------------
ifndef DISTURB_ENABLE_PARALLEL
  _HAS_PTHREAD := $(shell printf '\043include <pthread.h>\nint main(){return 0;}' | $(CC) -x c -c - -o /dev/null 2>/dev/null && echo 1 || echo 0)
  ifeq ($(_HAS_PTHREAD),1)
    DISTURB_ENABLE_PARALLEL := 1
  else
    DISTURB_ENABLE_PARALLEL := 0
  endif
endif

# --- Auto-detect OpenCL --------------------------------------------------
ifndef DISTURB_ENABLE_GPU
  _HAS_OPENCL := $(shell printf '\043ifdef __APPLE__\n\043include <OpenCL/opencl.h>\n\043else\n\043include <CL/cl.h>\n\043endif\nint main(){return 0;}' | $(CC) -x c - -lOpenCL -o /dev/null 2>/dev/null && echo 1 || echo 0)
  ifeq ($(_HAS_OPENCL),1)
    DISTURB_ENABLE_GPU := 1
  else
    DISTURB_ENABLE_GPU := 0
  endif
endif

DISTURB_ENABLE_LTO      ?= 1
DISTURB_ENABLE_PGO_GEN  ?= 0
DISTURB_ENABLE_PGO_USE  ?= 0

# Optimization level: -O3 for desktop, -Os for embedded (size-optimized)
ifeq ($(DISABLE_IO),1)
  BASE_OPT = -Os
else
  BASE_OPT = -O3
endif

# Auto-detect -march=native support
_HAS_MARCH_NATIVE := $(shell $(CC) -march=native -x c -c /dev/null -o /dev/null 2>/dev/null && echo 1 || echo 0)
ifeq ($(_HAS_MARCH_NATIVE),1)
  ARCH_FLAG = -march=native
else
  ARCH_FLAG =
endif

CFLAGS = $(BASE_OPT) $(ARCH_FLAG) -funroll-loops -std=c99 -Wall -Wextra -pedantic -Iinclude -Ilib/libregexp -Ilib/
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

all: disturb disturb-minimal

disturb: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

# Minimal build: no SIMD, no parallel, no GPU — scalar baseline for benchmarks
disturb-minimal:
	@echo "=== Building disturb-minimal (no SIMD/parallel/GPU) ==="
	$(MAKE) -f $(firstword $(MAKEFILE_LIST)) disturb-minimal-bin \
		DISTURB_ENABLE_SIMD=0 \
		DISTURB_ENABLE_PARALLEL=0 \
		DISTURB_ENABLE_GPU=0 \
		OBJDIR_SUFFIX=_minimal

# Internal target: builds the minimal binary using a separate object directory
OBJDIR_SUFFIX ?=
MINIMAL_OBJ = $(SRC:.c=.minimal.o)

disturb-minimal-bin: $(MINIMAL_OBJ)
	$(CC) $(CFLAGS) -o disturb-minimal $(MINIMAL_OBJ) $(LDFLAGS)

# Pattern rules for .minimal.o (separate object files for minimal build)
lib/libregexp/%.minimal.o: lib/libregexp/%.c
	$(CC) $(CFLAGS) $(LIBREGEXP_CFLAGS) -c $< -o $@

src/%.minimal.o: src/%.c include/vm.h include/papagaio.h include/bytecode.h
	$(CC) $(CFLAGS) -c $< -o $@

test-raylib: disturb
	sh tests/run_raylib_examples.sh

lib/libregexp/%.o: lib/libregexp/%.c
	$(CC) $(CFLAGS) $(LIBREGEXP_CFLAGS) -c $< -o $@

%.o: %.c include/vm.h include/papagaio.h include/bytecode.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(MINIMAL_OBJ) disturb disturb-minimal

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

.PHONY: all clean test-raylib pgo pgo-gen pgo-use disturb-minimal disturb-minimal-bin

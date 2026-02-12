CC = gcc
ENABLE_IO ?= 1
ENABLE_FFI ?= 1
ENABLE_FFI_CALLS ?= 1
ENABLE_EMBEDDED ?= 0
UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
IS_WINDOWS := $(findstring MINGW,$(UNAME_S))

CFLAGS = -O2 -std=c99 -Wall -Wextra -pedantic -Iinclude -Ilib/libregexp -Ilib/
LIBREGEXP_CFLAGS = -Wno-unused-parameter -Wno-sign-compare -Wno-pedantic
LDFLAGS = -lm

ifeq ($(ENABLE_EMBEDDED),1)
	ENABLE_IO := 0
	ENABLE_FFI := 1
	ENABLE_FFI_CALLS := 0
	CFLAGS += -DDISTURB_EMBEDDED
endif

ifeq ($(ENABLE_IO),1)
	CFLAGS += -DDISTURB_ENABLE_IO
endif

ifeq ($(ENABLE_FFI),1)
	CFLAGS += -DDISTURB_ENABLE_FFI
ifeq ($(ENABLE_FFI_CALLS),1)
	CFLAGS += -DDISTURB_ENABLE_FFI_CALLS
	LDFLAGS += -lffi
ifeq ($(IS_WINDOWS),)
ifneq ($(UNAME_S),Darwin)
	LDFLAGS += -ldl
endif
endif
endif
endif

SRC = lib/libregexp/cutils.c lib/libregexp/libunicode.c lib/libregexp/libregexp.c \
      src/vm.c src/bytecode.c src/syntax.c src/functions.c src/papagaio.c src/cli.c
ifeq ($(ENABLE_FFI),1)
	SRC += src/ffi.c
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

.PHONY: all clean test-raylib

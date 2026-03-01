CC = gcc
DISABLE_IO ?= 0
ENABLE_FFI ?= 1
UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
IS_WINDOWS := $(findstring MINGW,$(UNAME_S))

CFLAGS = -O2 -std=c99 -Wall -Wextra -pedantic -Iinclude
LDFLAGS = -lm

ifeq ($(DISABLE_IO),1)
	CFLAGS += -DDISTURB_EMBEDDED
override ENABLE_FFI = 0
endif

ifeq ($(ENABLE_FFI),1)
	CFLAGS += -DDISTURB_ENABLE_FFI
endif

ifeq ($(DISABLE_IO),0)
	CFLAGS += -DDISTURB_ENABLE_IO
endif


ifeq ($(ENABLE_FFI),1)
	ifeq ($(DISABLE_IO),0)
	CFLAGS += -DDISTURB_ENABLE_FFI_CALLS
	LDFLAGS += -lffi
ifeq ($(IS_WINDOWS),)
ifneq ($(UNAME_S),Darwin)
	LDFLAGS += -ldl
endif
endif
endif
endif

SRC = src/vm.c src/bytecode.c src/syntax.c src/functions.c src/papagaio.c src/cli.c src/ffi.c
OBJ = $(SRC:.c=.o)

all: disturb

disturb: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

test: disturb
	sh tests/run.sh
	sh tests/run_examples.sh

test-raylib: disturb
	sh tests/run_raylib_examples.sh

%.o: %.c include/vm.h include/papagaio.h include/bytecode.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) disturb

.PHONY: all clean test test-raylib

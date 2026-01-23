CC = cc
ENABLE_IO ?= 1
ENABLE_SYSTEM ?= 1
ENABLE_FFI ?= 1

CFLAGS = -std=c99 -Wall -Wextra -pedantic -Iinclude -Ilib/libregexp
LIBREGEXP_CFLAGS = -Wno-unused-parameter -Wno-sign-compare -Wno-pedantic
LDFLAGS = -lm

ifeq ($(ENABLE_IO),1)
	CFLAGS += -DDISTURB_ENABLE_IO
endif

ifeq ($(ENABLE_SYSTEM),1)
	CFLAGS += -DDISTURB_ENABLE_SYSTEM
endif

ifeq ($(ENABLE_FFI),1)
	CFLAGS += -DDISTURB_ENABLE_FFI
	LDFLAGS += -ldl -lffi
endif

SRC = lib/libregexp/cutils.c lib/libregexp/libunicode.c lib/libregexp/libregexp.c \
      src/vm.c src/bytecode.c src/asm.c src/syntax.c src/functions.c src/papagaio.c src/cli.c
ifeq ($(ENABLE_FFI),1)
	SRC += src/ffi.c
endif
OBJ = $(SRC:.c=.o)

all: disturb

disturb: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

lib/libregexp/%.o: lib/libregexp/%.c
	$(CC) $(CFLAGS) $(LIBREGEXP_CFLAGS) -c $< -o $@

%.o: %.c include/vm.h include/urb.h include/papagaio.h include/bytecode.h include/asm.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) disturb

.PHONY: all clean

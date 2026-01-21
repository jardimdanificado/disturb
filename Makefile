CC = cc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -Iinclude -Ilib/libregexp
LIBREGEXP_CFLAGS = -Wno-unused-parameter -Wno-sign-compare -Wno-pedantic
LDFLAGS = -lm

SRC = lib/libregexp/cutils.c lib/libregexp/libunicode.c lib/libregexp/libregexp.c \
      src/vm.c src/bytecode.c src/asm.c src/syntax.c src/functions.c src/papagaio.c src/cli.c
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

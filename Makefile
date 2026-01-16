CC = cc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -Iinclude
LDFLAGS = -lm

SRC = src/vm.c src/bytecode.c src/asm.c src/syntax.c src/functions.c src/cli.c
OBJ = $(SRC:.c=.o)

all: disturb

disturb: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c include/vm.h include/urb.h include/papagaio.h include/bytecode.h include/asm.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) disturb

.PHONY: all clean

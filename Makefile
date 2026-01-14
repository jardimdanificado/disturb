CC = cc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -Iinclude
LDFLAGS =

SRC = src/vm.c src/syntax.c src/functions.c src/cli.c
OBJ = $(SRC:.c=.o)

all: vm

vm: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c include/vm.h include/urb.h include/papagaio.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) vm

.PHONY: all clean

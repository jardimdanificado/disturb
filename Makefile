CC = gcc
DISABLE_SYSTEM ?= 0
DISABLE_FFI_CALLS ?= 0
UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
IS_WINDOWS := $(findstring MINGW,$(UNAME_S))
TARGET ?= disturb
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL) -m 755

EMCC ?= emcc

# Native build flags (gcc/clang)
CFLAGS = -O2 -std=c99 -Wall -Wextra -pedantic -Iinclude
CFLAGS += -DDISTURB_ENABLE_FFI
LDFLAGS = -lm

# WebAssembly build flags (Emscripten)
WASM_TARGET ?= disturb.js
WASM_CFLAGS = -O2 -std=c99 -Wall -Wextra -pedantic -Iinclude
WASM_EMFLAGS = -s WASM=1 -s ALLOW_MEMORY_GROWTH=1 -s MODULARIZE=1 -s EXPORT_NAME=createDisturbModule \
	-s EXPORTED_FUNCTIONS=['_disturb_wasm_init','_disturb_wasm_eval','_disturb_wasm_free','_disturb_md_extract_urb','_malloc','_free'] \
	-s EXPORTED_RUNTIME_METHODS=['cwrap','UTF8ToString','stringToUTF8']

ifeq ($(DISABLE_SYSTEM),1)
	CFLAGS += -DDISTURB_EMBEDDED
endif

ifeq ($(DISABLE_SYSTEM),0)
	CFLAGS += -DDISTURB_ENABLE_IO
	ifeq ($(DISABLE_FFI_CALLS),0)
		CFLAGS += -DDISTURB_ENABLE_FFI_CALLS
		LDFLAGS += -lffi
		ifeq ($(IS_WINDOWS),)
		ifneq ($(UNAME_S),Darwin)
			LDFLAGS += -ldl
		endif
		endif
	endif
endif

SRC = src/vm.c src/bytecode.c src/syntax.c src/functions.c src/host_io.c src/disturb_wasm.c src/papagaio.c src/cli.c src/ffi.c
OBJ = $(SRC:.c=.o)
INSTALL_TARGET ?= $(notdir $(TARGET))

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

test: $(TARGET)
	sh tests/run.sh
	sh tests/run_examples.sh

test-raylib: $(TARGET)
	sh tests/run_raylib_examples.sh

install: $(TARGET)
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL_PROGRAM) $(TARGET) $(DESTDIR)$(BINDIR)/$(INSTALL_TARGET)

%.o: %.c include/vm.h include/papagaio.h include/bytecode.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET) disturb.js disturb.wasm
	rm -f examples/web/disturb.js examples/web/disturb.wasm
	rm -f examples/obsidian-plugin/disturb.js examples/obsidian-plugin/disturb.wasm
	rm -rf disturb-obsidian

OBSIDIAN_PLUGIN_DIR ?= disturb-obsidian
OBSIDIAN_PLUGIN_SRC = examples/obsidian-plugin

# WASM build target (builds disturb.js + disturb.wasm)
$(WASM_TARGET): $(SRC)
	$(EMCC) $(WASM_CFLAGS) $(WASM_EMFLAGS) -o $@ $(SRC)

wasm: $(WASM_TARGET)
	mkdir -p examples/web
	cp -f disturb.js disturb.wasm examples/web/

obsidian: $(WASM_TARGET) $(OBSIDIAN_PLUGIN_DIR)

$(OBSIDIAN_PLUGIN_DIR):
	rm -rf $@
	mkdir -p $@
	cp -r $(OBSIDIAN_PLUGIN_SRC)/manifest.json $(OBSIDIAN_PLUGIN_SRC)/main.js $(OBSIDIAN_PLUGIN_SRC)/output-modal.js $@
	cp -r disturb.js disturb.wasm $@

.PHONY: all clean test test-raylib install obsidian wasm

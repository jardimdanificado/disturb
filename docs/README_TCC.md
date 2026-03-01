# libs/tcc.urb - TinyCC FFI Module

Pure-Disturb module for Just-In-Time C compilation using TinyCC (libtcc).

## Requirements

- Disturb with FFI enabled (`ENABLE_FFI=1`, default)
- `libtcc` shared library available in your system's dynamic loader path
  - Linux: `libtcc.so` or `libtcc.so.1`
  - macOS: `libtcc.dylib`
  - Windows: `libtcc.dll`

## Quick Start

```urb
tcc = import("libs/tcc")

// Auto-load libtcc from system paths
mod = tcc.auto()
if (mod == null) {
  println("libtcc not found")
  return 0
}

// Compile and use C code
lib = mod.compile("int add(int a, int b) { return a + b; }")
add = ffi.bind(lib.sym("add"), "i32 add(i32, i32)")
println(add(10, 20))  // Output: 30
lib.close()
```

## API Reference

### Module Loading

#### `tcc.auto()` → module | null
Auto-detect and load libtcc from standard system paths.
Returns module instance or `null` if not found.

#### `tcc.load(path)` → module | null
Load libtcc from explicit path.
```urb
mod = tcc.load("/usr/local/lib/libtcc.so")
```

#### `tcc.open([path])` → TCCState | null
Convenience: load module and create a new compilation context in one call.
```urb
ctx = tcc.open()  // Auto-detect libtcc and create context
```

### High-Level APIs (Module Methods)

#### `mod.cdef(src)` → null
Register C declarations (typedefs, structs, etc.) for use in future compilations.
These declarations form a "prelude" that is automatically prepended to code in `compile()` and `eval()`.

```urb
mod.cdef("typedef int myint;")
mod.cdef("typedef struct { int x; int y; } Point;")
```

#### `mod.compile(src)` → handle | null
Compile C source code to memory. Returns a handle compatible with `ffi.sym()` and `ffi.bind()`.
Automatically includes all declarations from previous `cdef()` calls.

```urb
lib = mod.compile("myint multiply(myint a, myint b) { return a * b; }")
if (lib == null) {
  println("Compilation failed")
  return 0
}

multiply = ffi.bind(lib.sym("multiply"), "i32 multiply(i32, i32)")
println(multiply(6, 7))  // Output: 42
lib.close()
```

The returned handle provides:
- `handle.sym(name)` - resolve symbol to pointer
- `handle.close()` - free compiled code

#### `mod.eval(expr)` → number | null
Evaluate a C expression and return the result as a number.
Automatically includes prelude from `cdef()` calls.

```urb
size = mod.eval("sizeof(int)")
println(size)  // Output: 4 (on most systems)

result = mod.eval("2 + 3 * 4")
println(result)  // Output: 14
```

### Low-Level APIs (TCCState Methods)

For advanced use cases, you can work directly with TCC compilation contexts:

#### `mod.new()` → ctx | null
Create a new TCC compilation context.

```urb
ctx = mod.new()
if (ctx == null) {
  println("Failed to create TCC state")
  return 0
}
```

#### Context Methods

```urb
ctx.setOutputType(TYPE)     // mod.OUTPUT_MEMORY, OUTPUT_EXE, OUTPUT_OBJ, OUTPUT_DLL
ctx.compile(src)            // Compile C source string → status code
ctx.relocate()              // Finalize and relocate compiled code → status code
ctx.getSymbol(name)         // Get symbol address → pointer
ctx.close()                 // Free context

// Configuration
ctx.setLibPath(path)
ctx.addIncludePath(path)
ctx.addSysincludePath(path)
ctx.define(name, value)
ctx.undefine(name)

// Additional compilation
ctx.addFile(path)           // Add C file
ctx.addLibraryPath(path)
ctx.addLibrary(name)
ctx.addSymbol(name, addr)   // Add external symbol
ctx.outputFile(path)        // Write compiled output to file

// Query
ctx.isOpen()                // Check if context is valid
```

### Constants

- `mod.OUTPUT_MEMORY` (1) - Compile to memory (for JIT execution)
- `mod.OUTPUT_EXE` (2) - Generate executable file
- `mod.OUTPUT_OBJ` (3) - Generate object file
- `mod.OUTPUT_DLL` (4) - Generate shared library
- `mod.OUTPUT_PREPROCESS` (5) - Preprocessor only

## Examples

### Example 1: Simple Compilation

```urb
tcc = import("libs/tcc")
mod = tcc.auto()

lib = mod.compile("int square(int x) { return x * x; }")
square = ffi.bind(lib.sym("square"), "i32 square(i32)")
println(square(7))  // Output: 49
lib.close()
```

### Example 2: Using Prelude (cdef)

```urb
tcc = import("libs/tcc")
mod = tcc.auto()

// Define types
mod.cdef("typedef unsigned int uint;")
mod.cdef("typedef struct { uint x, y; } Vec2;")

// Use types in compilation
lib = mod.compile(r"
  uint distance_sq(Vec2 a, Vec2 b) {
    uint dx = (a.x > b.x) ? (a.x - b.x) : (b.x - a.x);
    uint dy = (a.y > b.y) ? (a.y - b.y) : (b.y - a.y);
    return dx*dx + dy*dy;
  }
")

// Note: This example would require struct support in ffi.bind
// For actual use, you'd need to work with pointers
```

### Example 3: Evaluating Expressions

```urb
tcc = import("libs/tcc")
mod = tcc.auto()

// Include standard headers for sizeof
mod.cdef("#include <stddef.h>")
mod.cdef("#include <stdint.h>")

println("sizeof(int) = " + mod.eval("sizeof(int)"))
println("sizeof(void*) = " + mod.eval("sizeof(void*)"))
println("sizeof(size_t) = " + mod.eval("sizeof(size_t)"))
println("__SIZEOF_INT128__ = " + mod.eval("__SIZEOF_INT128__"))
```

### Example 4: Low-Level Context Usage

```urb
tcc = import("libs/tcc")
mod = tcc.auto()

ctx = mod.new()
ctx.setOutputType(mod.OUTPUT_MEMORY)
ctx.addIncludePath("/usr/include")
ctx.define("MY_CONST", "42")

rc = ctx.compile("int get_const() { return MY_CONST; }")
if (rc != 0) {
  println("Compilation failed")
  ctx.close()
  return 0
}

rc = ctx.relocate()
if (rc != 0) {
  println("Relocation failed")
  ctx.close()
  return 0
}

get_const = ffi.bind(ctx.getSymbol("get_const"), "i32 get_const()")
println(get_const())  // Output: 42
ctx.close()
```

## Notes

- The module manages its own prelude state - each module instance has independent prelude
- Compiled code remains valid until `handle.close()` or `ctx.close()` is called
- Memory leaks can occur if you don't close handles/contexts
- TCC is integrated at runtime via FFI - no rebuild required to enable/disable
- For production use, consider caching compiled modules

## See Also

- Main TCC example: `example/tcc.urb`
- FFI documentation: `docs/FUNCTION_REFERENCE.md`
- Original TCC documentation: https://bellard.org/tcc/tcc-doc.html

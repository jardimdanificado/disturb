# Disturb

Disturb is a stack-based VM and language with C-like syntax that compiles to compact RPN bytecode.

## Additional Docs

- Quick syntax cheatsheet: `docs/REF_SHEET.md`
- Detailed function-by-function reference: `docs/FUNCTION_REFERENCE.md`

## Build

Requirements:
- `gcc` (or compatible C compiler)
- `make`
- `libffi` headers/libs for desktop/default builds (`DISABLE_IO=0`, default)

Build:

```bash
make
./disturb --help
```

Optional flags:

```bash
make DISABLE_IO=1
```

`DISABLE_IO=1` enables embedded profile behavior by disabling IO natives, dynamic FFI calls (`ffi.open`/`ffi.sym`/`ffi.bind`), and `import` while keeping FFI core layout/view/memory APIs.

MSVC build (Windows):

```powershell
cmake -S . -B build-msvc -A x64 -DDISABLE_IO=1
cmake --build build-msvc --config Release
.\build-msvc\Release\disturb.exe --help
```

Notes:
- The MSVC embedded profile can be validated with `DISABLE_IO=1` (FFI core remains enabled).
- To enable dynamic calls (`ffi.open`/`ffi.sym`/`ffi.bind`) under MSVC, provide a `libffi` build (headers + `.lib`/`.dll`) and configure CMake paths accordingly.

## CLI

```text
disturb [script.urb] [args...]
disturb --compile-bytecode script.urb output.bytecode
disturb --run-bytecode output.bytecode [args...]
disturb --help
```

Notes:
- No-arg execution starts the REPL.
- `--compile-bytecode` emits raw bytecode.
- `--run-bytecode` runs raw bytecode.

## First Script

```disturb
msg = "hello",
println(msg)
```

Run:

```bash
./disturb file.urb
```

## Language Model

Core behavior:
- assignment is global by default: `x = 1,` is equivalent to `global.x = 1,`
- missing globals/keys evaluate to `null`
- `global` is a real table
- `global.common` stores common methods
- method calls bind `this` to the target (`obj.fn()`)

Type names used by `.type`:
- `null`
- `int`
- `float`
- `char`
- `string`
- `table`
- `native`
- `lambda`
- `view` (FFI views)

## Syntax Basics

Statements are separated by commas; the final comma in a sequence is optional (you can drop the trailing comma before a closing brace or end-of-file).

Comments:

```disturb
// line comment
/* block comment */
```

Blocks use `{ ... }`.

Table literal also uses `{ ... }`, while lambda literal uses `(args){ ... }`.

## Values and Literals

Supported literal forms:
- int: `1`
- float: `3.14`
- int suffix: `1i`
- unsigned suffix alias (stored as int): `1u`
- float suffix: `1f`
- char: `'a'` (must be exactly one byte)
- string: `"abc"`
- list: `[1, 2, 3]`
- table: `{a = 1, b = "x"}`

Special global:
- `inf` (positive infinity float)

List behavior:
- numeric lists are homogeneous (`int` list or `float` list)
- mixed numeric literals like `[1, 2.5]` become float lists in non-strict mode
- string values are byte lists with string semantics

## Truthiness

False values:
- `null`
- numeric zero (`0`, `0.0`)

Everything else is true.

## Operators

### Arithmetic and unary
- `+ - * / %`
- unary `-`

### Logical
- `!`
- `&&`
- `||`

### Comparison
- `< <= > >=`
- `== !=`
- `=== !==`

### Bitwise (int only)
- `& | ^ ~ << >>`

### Assignment
- `=`
- `+= -= *= /= %= &= |= ^= <<= >>=`
- `?=` (assign only if target is `null`)
- `++ --` (prefix and postfix)

Operator semantics highlights:
- comparisons/logical ops return numeric booleans (`1` or `0`)
- `+` concatenates when one side is string/char
- `==` compares by value
- `===` compares strict identity/type-level equality semantics
- assignment/compound/inc-dec forms are expressions (usable inside larger expressions)

## Equality Semantics

`==` / `!=`:
- numbers compare by numeric value (`1 == 1.0` is true)
- strings compare by content
- tables compare structurally (deep, cycle-safe)
- functions compare by identity

`===` / `!==`:
- strict identity-sensitive equality
- useful for reference identity checks

## Indexing and Access

Supported forms:
- `obj.key`
- `obj["key"]`
- `obj[k]` where `k` is string-like key
- `list[i]`
- `string[i]`

Rules:
- numeric indexing is 0-based
- out-of-range numeric index errors
- key indexing is for tables
- string index yields a single-byte char value
- string index assignment accepts single-byte char or byte numeric value

## Variables, Scope, and Calls

### Global and local scope
- top-level assignments write to `global`
- lambda bodies use local scope
- `local` is available inside lambdas
- globals are still reachable via `global.name`

### Function/lambda definition

```disturb
add = (a, b){ return a + b; };
```

Parameters:
- positional params
- default params: `(a, b = 10){ ... }`
- varargs: `(head, ...rest){ ... }` (must be last)
- missing non-default params become `null`

Returns:
- `return expr;`
- `return;` returns `null`

Calls:
- regular call: `add(1, 2)`
- method call with `this`: `obj.add(7)`
- table-call convention: if a table has a method with its own name, calling the table invokes it

## Control Flow

Supported:
- `if (...) { ... }`
- `if (...) { ... } else if (...) { ... } else { ... }`
- `while (...) { ... }`
- `for (init; cond; step) { ... }`
- `each(v in expr) { ... }`
- `break;`
- `continue;`
- `switch/case/default`
- labels and `goto`

Switch behavior:
- first matching case executes
- no fall-through
- `default` runs when no case matches

## Reference Semantics and Copies

Assignment shares references:

```disturb
a = {x = 1, y = {z = 2}};
b = a;
b.y.z = 9;
println(a.y.z); // 9
```

Copy helpers:
- `clone()` shallow copy
- `copy()` deep copy

```disturb
c = a.clone();
d = a.copy();
```

## Meta Properties

Each entry exposes metadata fields:
- `.name`
- `.type`
- `.value`
- `.size`
- `.capacity`

Common uses:
- inspect runtime shape: `println(x.type);`
- resize containers: `x.size = 10;`, `x.capacity = 32;`
- replace value while keeping identity slot: `x.value = {...};`

Important constraints:
- `.name` expects string or `null`
- `.size` expects integer
- `.capacity` expects numeric value

## Strict Mode

Strict directives:

```disturb
use strict;
use nostrict;
```

Accepted forms:
- `use strict;`
- `use "strict";`
- `use nostrict;`
- `use "nostrict";`

Effects:
- parser strictness from directive point onward
- runtime strictness toggled in emitted bytecode

Strict mode rules:
- forbids mixed int/float arithmetic
- forbids mixed int/float numeric comparisons
- forbids number/string comparisons
- forbids `null` in numeric operations
- forbids mixed int/float numeric list literals
- string text output should use `.string`

Runtime toggle:

```disturb
global.gc.strict = 1;
global.gc.strict = 0;
```

## Built-in Functions and Methods

Disturb installs common functions in `global.common`, so they are callable as methods and as globals.

### Core
- `print`
- `println`
- `len`
- `pretty`
- `clone`
- `copy`
- `toInt`
- `toFloat`
- `gc`

### IO (when `DISABLE_IO=0`)
- `read(path)`
- `write(path, data)`

### Modules and metaprogramming
- `import`
- `eval`
- `parse`
- `emit`
- `evalBytecode`
- `bytecodeToAst`
- `astToSource`

### Math
- `append`
- `add sub mul div mod pow`
- `min max abs floor ceil round sqrt`
- `sin cos tan asin acos atan log exp`

### String/bytes
- `slice`
- `substr`
- `split`
- `join`
- `upper`
- `lower`
- `trim`
- `startsWith`
- `endsWith`
- `replace`
- `replaceAll`
- `papagaio`

### Table/list mutation and query
- `keys`
- `values`
- `has`
- `delete`
- `push`
- `pop`
- `shift`
- `unshift`
- `insert`
- `remove`

## Print vs Println

- `print(...)` prints values with typed/literal style.
- `println(...)` prints plain value style.
- `print()` / `println()` with no args read the top of stack when available.

## Script Arguments

CLI arguments are exposed as globals:
- `arg_0`, `arg_1`, ...
- `args` table
- `argc` (string value)

Example:

```disturb
println(argc);
println(args.pretty());
println(arg_0);
```

## Modules (`import`)

`import(path)` behavior:
- if `path` ends with `.urb`, loads that file directly
- otherwise loads package entry: `path/<basename(path)>.urb`
- module runs in isolated VM
- module export is the top-level `return` value
- loaded modules are cached by resolved path

Examples:
- `import("tests/modules/math.urb")`
- `import("tests/modules/pkg")` -> loads `tests/modules/pkg/pkg.urb`

## Bytecode and Metaprogramming

Compile and run from source text:

```disturb
bc = parse("println(1 + 2);");
println(emit(bc));
evalBytecode(bc);
```

Assembler/disassembler example is provided in:
- `example/asm_lib.urb`

## Papagaio

Papagaio processing applies to string literals containing `$`.
Use `\$` to keep literal `$`.

Source-level compile-time preprocessing is automatic for papagaio declarations
outside strings/comments (`$pattern{...}{...}`, `$regex ... {...}`, `$eval{...}`).
Papagaio declarations inside string literals stay runtime behavior.

Examples:
- `example/papagaio_preprocess_basic.urb`
- `example/papagaio_preprocess_capture.urb`
- `example/papagaio_preprocess_macro.urb`
- `example/papagaio_preprocess_mixed.urb`

Supported patterns include:
- `$pattern{...}{...}`
- `$regex ... {...}`
- `$eval{...}`

Runtime API:
- `papagaio(text)`

Papagaio runtime context is exposed under `global.papagaio` (for `content` and `match` access inside eval blocks).

## GC and Runtime Controls

Manual GC helpers are under `global.gc`:
- `collect()`
- `free(value)`
- `sweep(value)`
- `new(size)`
- `debug()`
- `stats()`

Runtime flags:
- `global.gc.strict = 0|1`
- `global.gc.keyintern = 0|1`

Compatibility alias:
- `gc()` is available and maps to collection behavior.

## FFI

Dynamic foreign calls (`ffi.open`, `ffi.sym`, `ffi.bind`) require `DISABLE_IO=0` (default in desktop builds; disabled by `DISABLE_IO=1`).

Main API:
- `ffi.open(libPath)`
- `ffi.sym(libHandle, symbolName)`
- `ffi.close(libHandle)`
- `ffi.bind(ptr, "signature")`
- `ffi.callback("signature", lambda)`
- `ffi.compile(schema)`
- `ffi.new(schemaOrLayout)`
- `ffi.free(ptr)`
- `ffi.buffer(len)`
- `ffi.string(ptr)` / `ffi.string(ptr, len)`
- `ffi.sizeof(schemaOrLayout)`
- `ffi.alignof(schemaOrLayout)`
- `ffi.offsetof(schemaOrLayout, "field.path")`
- `ffi.view(ptr, schemaOrLayout)`
- `ffi.viewArray(ptr, elemSpec, len)`

Notes:
- Two-step loading is supported via `ffi.open` + `ffi.sym` + `ffi.bind`.
- `ffi.compile(schema)` is optional for normal use.
- `ffi.view/sizeof/alignof/offsetof/new` accept either a schema table or a compiled layout handle; schema tables are auto-compiled and cached internally.

Signature struct typing:
- by-value struct: `struct(schema)` (example: `i32 sum(struct(outer))`)
- by-value union: `union(schema)` (example: `i32 inspect(union(bits))`)
- typed pointer: `pointer(schema)` (example: `void free_outer(pointer(outer))`)
- raw/generic pointer stays `void*`
- pointer depth in signatures must use nested `pointer(...)` (example: `pointer(pointer(i32))`)
- string-ish types:
  - `string`: marshals to/from Disturb strings
  - `cstring`/`cstr`: raw C pointer semantics (use `ffi.string(ptr)` when needed)
- optional ABI prefix in signatures: `abi(name)` or bare ABI name (`cdecl`, `stdcall`, `fastcall`, `thiscall`, `win64`, `unix64`, `sysv`)

Schema composition:
- schema fields must be type strings
- use `struct(otherSchema)`, `union(otherSchema)`, or `pointer(otherSchema)` inside field declarations
- function pointer fields: `function(signature)` (example: `cb = "function(i32 cb(i32, i32))"`; `fn(...)` also accepted as alias)
- unions: `__meta = { union = 1 }`
- bitfields: use `"type:bits"` (example: `"uint8:3"`, `"uint32:5"`)
- qualifiers accepted in schema/signatures: `const`, `volatile`, `restrict`
- variadic signatures accepted via `...` in `ffi.bind`

Const behavior in views:
- non-strict mode: warns and ignores write
- strict mode: aborts with panic

Ownership:
- `ffi.new` returns an owned pointer handle (GC releases memory if unreachable)
- `ffi.free(ptr)` can free explicitely (works with owned handles and raw pointers)

Supported workflow:
- call C functions
- map pointers to callable functions
- build callbacks with scalar and by-value struct/union signatures
- compile C-like struct schemas
- create live pointer-backed struct views
- handle nested structs and fixed arrays in layouts
- by-value packed/forced-align schemas are still rejected (ABI-sensitive edge case)

Examples:
- `example/guide/11_ffi_system.urb`
- `example/guide/14_ffi_struct_views_bind.urb`
- `example/guide/15_ffi_callbacks_varargs_buffers.urb`
- `example/ffi_view_struct.urb`
- `example/ffi_callbacks_varargs_buffers.urb`
- `example/ffi_fnptr_fields.urb`
- `example/ffi_auto_compile_optional.urb`

Raylib wrapper:
- `lib/raylib.urb` exposes `raylib` core API via FFI (`raylib.load(path?)`)
- Official raylib core ports:
  - `example/raylib/core_basic_window.urb`
  - `example/raylib/core_input_keys.urb`
  - `example/raylib/core_input_mouse.urb`
  - `example/raylib/core_input_mouse_wheel.urb`
  - `example/raylib/core_random_values.urb`
  - `example/raylib/core_basic_screen_manager.urb`
  - `example/raylib/core_input_actions.urb`
  - `example/raylib/core_scissor_test.urb`
  - `example/raylib/core_render_texture.urb`
  - `example/raylib/core_input_multitouch.urb`
  - `example/raylib/core_2d_camera.urb`
  - `example/raylib/core_2d_camera_mouse_zoom.urb`
  - `example/raylib/core_input_gestures.urb`
  - `example/raylib/core_monitor_detector.urb`
  - `example/raylib/core_viewport_scaling.urb`
  - `example/raylib/core_delta_time.urb`
  - `example/raylib/core_window_should_close.urb`
  - `example/raylib/core_window_flags.urb`
  - `example/raylib/core_window_letterbox.urb`
  - `example/raylib/shapes_basic_shapes.urb`
  - `example/raylib/shapes_bouncing_ball.urb`
  - `example/raylib/shapes_collision_area.urb`
  - `example/raylib/shapes_rectangle_scaling.urb`
  - `example/raylib/shapes_lines_bezier.urb`
  - `example/raylib/shapes_lines_drawing.urb`
  - `example/raylib/shapes_dashed_line.urb`
  - `example/raylib/shapes_following_eyes.urb`
  - `example/raylib/shapes_mouse_trail.urb`
  - `example/raylib/shapes_logo_raylib.urb`
  - `example/raylib/shapes_logo_raylib_anim.urb`
  - `example/raylib/shapes_colors_palette.urb`
- If auto-load fails, pass explicit shared library path:
  - Linux: `raylib.load("../raylib/build/raylib/libraylib.so")`
  - macOS: `raylib.load("./raylib/src/libraylib.dylib")`
  - Windows: `raylib.load("./raylib/src/raylib.dll")`

## Tests

Main language tests:

```bash
tests/run.sh
```

Run all examples:

```bash
tests/run_examples.sh
```

[![CI](https://github.com/jardimdanificado/disturb/actions/workflows/ci.yml/badge.svg)](https://github.com/jardimdanificado/disturb/actions/workflows/ci.yml)

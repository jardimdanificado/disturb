# Disturb

Disturb is a stack-based VM and language with C-like syntax that compiles to compact RPN bytecode.

This README now includes the full function reference.

## Build

Requirements:
- `gcc` (or compatible C compiler)
- `make`
- `libffi` headers/libs for default/full builds (`DISABLE_SYSTEM=0`)

Build:

```bash
make
./disturb --help
```

Optional flags:

```bash
make DISABLE_SYSTEM=1
```

Flag behavior summary:
- `DISABLE_SYSTEM=0` (default/full): enables IO natives, `import`, and dynamic FFI calls (`C.ffi.open`/`C.ffi.sym`/`C.ffi.bind`/`C.ffi.callback`)
- `DISABLE_SYSTEM=1` (embedded): disables features that depend on OS/file-system integration (IO natives, `import`, dynamic FFI calls), while keeping FFI core (`C`, `C.memory`, `C.typedef`/`C.struct`) available

MSVC build (Windows):

```powershell
cmake -S . -B build-msvc -A x64 -DDISABLE_SYSTEM=1
cmake --build build-msvc --config Release
.\build-msvc\Release\disturb.exe --help
```

Notes:
- The MSVC embedded profile can be validated with `DISABLE_SYSTEM=1` (FFI core remains enabled).
- To enable dynamic calls (`C.ffi.open`/`C.ffi.sym`/`C.ffi.bind`) under MSVC, provide a `libffi` build (headers + `.lib`/`.dll`) and configure CMake paths accordingly.

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
if msg.size > 0 { println(msg) }
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
- numeric list shorthand: `1 2 3`
- table: `{a = 1, b = "x"}`

Special global:
- `inf` (positive infinity float)

List behavior:
- numeric lists are homogeneous (`int` list or `float` list)
- mixed numeric literals like `1 2.5` become float lists
- int arrays are raw byte buffers; a string literal is an int array accessed via the `.string` view

Numeric list shorthand example:

```disturb
a = 1 2 3,
b = 4 5 6,
println(a + b),
println(-a),
```

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
- `arr.string[i]` — byte `i` of an int array as a 1-byte string (char)
- `arr.u8[i]`, `arr.u16[i]`, `arr.u32[i]`, `arr.u64[i]` — element `i` interpreted as that width

Rules:
- numeric indexing is 0-based
- out-of-range numeric index errors
- key indexing is for tables
- `arr.string[i]` yields a single-byte string (char); assignment accepts a single-byte string or byte integer
- raw `arr[i]` on an int array returns `sizeof(Int)`-wide elements (8 bytes on 64-bit)

## Variables, Scope, and Calls

### Global and local scope
- top-level assignments write to `global`
- lambda bodies use local scope
- `local` is available inside lambdas
- globals are still reachable via `global.name`

### Function/lambda definition

```disturb
add = (a, b){ return a + b, }
```

Parameters:
- positional params
- default params: `(a, b = 10){ ... }`
- varargs: `(head, ...rest){ ... }` (must be last)
- missing non-default params become `null`

Returns:
- `return expr,`
- `return,` returns `null`

Calls:
- regular call: `add(1, 2)`
- method call with `this`: `obj.add(7)`
- table-call convention: if a table has a method with its own name, calling the table invokes it

## Control Flow

Supported:
- `if x { ... }` or `if (x) { ... }` (parentheses optional)
- `if x { ... } else if y { ... } else { ... }`
- `while x { ... }` (parentheses optional)
- `for init, cond, step { ... }` or `for (init, cond, step) { ... }` (parentheses optional)
- `each x in expr { ... }` or `each (x in expr) { ... }` (parentheses optional)
- `switch x { ... }` or `switch (x) { ... }` (parentheses optional; use `case` and `default`)
- `break,`
- `continue,`
- labels and `goto`

Switch behavior:
- first matching case executes
- no fall-through
- `default` runs when no case matches

## Reference Semantics and Copies

Assignment shares references:

```disturb
a = {x = 1, y = {z = 2}},
b = a,
b.y.z = 9,
println(a.y.z), // 9
```

Copy helpers:
- `clone()` shallow copy
- `copy()` deep copy

```disturb
c = a.clone(),
d = a.copy(),
```

## Meta Properties

Each entry exposes metadata fields:
- `.name`
- `.type`
- `.value`
- `.size`
- `.capacity`

Common uses:
- inspect runtime shape: `println(x.type),`
- resize containers: `x.size = 10,`, `x.capacity = 32,`
- replace value while keeping identity slot: `x.value = {...},`

`.size` semantics depend on the type/view:
- `table`: number of entries
- `int` array (raw): `total_bytes / sizeof(Int)`
- `float` array (raw): `total_bytes / sizeof(Float)`
- `arr.string.size`: `strlen` (bytes up to first `\0`)
- `arr.u8.size` / `arr.i8.size`: `total_bytes / 1`
- `arr.u16.size` / `arr.i16.size`: `total_bytes / 2`
- `arr.u32.size` / `arr.i32.size`: `total_bytes / 4`
- `arr.u64.size` / `arr.i64.size`: `total_bytes / 8`
- `arr.f32.size`: `total_bytes / 4`
- `arr.f64.size`: `total_bytes / 8`

Important constraints:
- `.name` expects string or `null`
- `.size` expects integer
- `.capacity` expects numeric value

## Built-in Functions and Methods

Disturb installs common functions in `global.common`, so they are callable as methods and as globals.

### Core
- `describe`
- `print`
- `println`
- `len`
- `pretty`
- `clone`
- `copy`
- `toInt`
- `toFloat`
- `gc`

### IO (when `DISABLE_SYSTEM=0`)
- `read(path)`
- `write(path, data)`

### Modules and metaprogramming
- `import`
- `eval`
- `parse`
- `emit`
- `evalBytecode`

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

## Describe, Print, and Println

- `describe(...)` prints values with typed/literal style (e.g. `[int x] [42]`), followed by a newline.
- `print(...)` prints plain values without a trailing newline.
- `println(...)` prints plain values followed by a newline.
- All three can be called as methods: `x.describe()`, `x.print()`, `x.println()`.
- With no arguments, they read the top of stack when available.

## Script Arguments

CLI arguments are exposed as globals:
- `arg_0`, `arg_1`, ...
- `args` table
- `argc` (string value)

Example:

```disturb
println(argc),
println(args.pretty()),
println(arg_0),
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
bc = parse("println(1 + 2),"),
println(emit(bc)),
evalBytecode(bc),
```

Assembler/disassembler example is provided in:
- `examples/asm_lib.urb`

## Papagaio

Papagaio processing applies to string literals containing `$`.
Use `\$` to keep literal `$`.

Source-level compile-time preprocessing is automatic for papagaio declarations
outside strings/comments (`$pattern{...}{...}`, `$eval{...}`).
Papagaio declarations inside string literals stay runtime behavior.

Examples:
- `examples/papagaio_preprocess_basic.urb`
- `examples/papagaio_preprocess_capture.urb`
- `examples/papagaio_preprocess_macro.urb`
- `examples/papagaio_preprocess_mixed.urb`

Supported patterns include:
- `$pattern{...}{...}`
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
- `global.gc.keyintern = 0|1`

## FFI

Runtime C integration is exposed under global `C`:
- runtime-only type helpers: `C.typedef`, `C.enum`, `C.define`, `C.struct`
- FFI calls/integration: `C.ffi.*`
- memory/layout/view APIs: `C.memory.*`
- runtime/platform info: `C.info()`

Dynamic foreign calls (`C.ffi.open`, `C.ffi.sym`, `C.ffi.bind`) require `DISABLE_SYSTEM=0`.

Main API:
- `C.info()`
- `C.typedef(name, type)`
- `C.enum(name, fields)`
- `C.define(name, value)`
- `C.struct(name, schema)`
- `C.defines` (constants table)
- `C.ffi.open(libPath)`
- `C.ffi.sym(libHandle, symbolName)`
- `C.ffi.close(libHandle)`
- `C.ffi.bind(ptr, "signature")`
- `C.ffi.callback("signature", lambda)`
- `C.ffi.auto(libOrProxy, sig)`
- `C.ffi.lib(path)`
- `C.ffi.global(lib, name, typeOrSchema)`
- `C.ffi.trace()` / `C.ffi.trace(0|1)`
- `C.memory.compile(schema)`
- `C.memory.new(schemaOrLayout)`
- `C.memory.struct(schemaOrLayout[, init])`
- `C.memory.free(ptr)`
- `C.memory.buffer(len)`
- `C.memory.string(ptr)` / `C.memory.string(ptr, len)`
- `C.memory.point(value)`
- `C.memory.valid(ptr)`
- `C.memory.read(ptr, type[, len])`
- `C.memory.write(ptr, type, value)`
- `C.memory.copy(dst, src, len)` / `C.memory.move(dst, src, len)` / `C.memory.zero(ptr, len)`
- `C.memory.offset(ptr, byteOffset)` / `C.memory.offset(ptr, index, elemTypeOrSchema)`
- `C.memory.cast(ptr, schemaOrLayout)`
- `C.memory.deref(ptr[, schemaOrType])`
- `C.memory.sizeof(schemaOrLayout)`
- `C.memory.alignof(schemaOrLayout)`
- `C.memory.offsetof(schemaOrLayout, "field.path")`
- `C.memory.view(ptr, schemaOrLayout[, totalSize])`
- `C.memory.viewArray(ptr, elemSpec, len)`

Notes:
- Two-step loading is supported via `C.ffi.open` + `C.ffi.sym` + `C.ffi.bind`.
- `C.memory.compile(schema)` is optional for normal use.
- `C.memory.view/sizeof/alignof/offsetof/new` accept either a schema table or a compiled layout handle; schema tables are auto-compiled and cached internally.
- `C.memory.point(value)` returns a numeric pointer for list/view data or existing pointer-like FFI values (`null` maps to `0`).
- `C.memory.view` and `C.memory.viewArray` expose `.byteSize`; array views also expose `.len`.
- packed/forced-align structs remain pointer-only for calls (by-value ABI limitation).

Signature struct typing:
- by-value struct: `struct(schema)` (example: `i32 sum(struct(outer))`)
- by-value union: `union(schema)` (example: `i32 inspect(union(bits))`)
- typed pointer: `pointer(schema)` (example: `void free_outer(pointer(outer))`)
- raw/generic pointer stays `void*`
- pointer depth in signatures must use nested `pointer(...)` (example: `pointer(pointer(i32))`)
- string-ish types:
  - `string`: marshals to/from Disturb strings
  - `cstring`: raw C pointer semantics (use `C.memory.string(ptr)` when needed)
- optional ABI prefix in signatures: `abi(name)` or bare ABI name (`cdecl`, `stdcall`, `fastcall`, `thiscall`, `win64`, `unix64`, `sysv`)

Schema composition:
- schema fields must be type strings
- use `struct(otherSchema)`, `union(otherSchema)`, or `pointer(otherSchema)` inside field declarations
- function pointer fields: `function(signature)` (example: `cb = "function(i32 cb(i32, i32))"`)
- unions: `__meta = { union = 1 }`
- bitfields: use `"type:bits"` (example: `"uint8:3"`, `"uint32:5"`)
- qualifiers accepted in schema/signatures: `const`, `volatile`, `restrict`
- variadic signatures accepted via `...` in `C.ffi.bind`

Const behavior in views:
- warns and ignores write

Ownership:
- `C.memory.new` returns an owned pointer handle (GC releases memory if unreachable)
- `C.memory.free(ptr)` can free explicitely (works with owned handles and raw pointers)

Supported workflow:
- call C functions
- map pointers to callable functions
- build callbacks with scalar and by-value struct/union signatures
- compile C-like struct schemas
- create live pointer-backed struct views
- handle nested structs and fixed arrays in layouts
- by-value packed/forced-align schemas are still rejected (ABI-sensitive edge case)

Examples:
- `examples/guide/11_ffi_system.urb`
- `examples/guide/14_ffi_struct_views_bind.urb`
- `examples/guide/15_ffi_callbacks_varargs_buffers.urb`
- `examples/ffi_view_struct.urb`
- `examples/ffi_callbacks_varargs_buffers.urb`
- `examples/ffi_fnptr_fields.urb`
- `examples/ffi_auto_compile_optional.urb`

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

## Function Reference (Detailed)

This file documents runtime functions currently exposed in `global.common` and `global.gc`.

Calling style:
- Most functions support both forms:
  - global: `fn(target, ...)`
  - method: `target.fn(...)`
- In method form, `target` becomes `this`.

Return conventions:
- `1` / `0` are numeric booleans.
- Some mutators are side-effect oriented and should not be relied on for return values.

## Core and Utility

### `describe(...values)` / `target.describe()`
- Prints values in typed/literal style (e.g. `[int x] [42]`), followed by a newline.
- If called with no arguments, prints top of stack (or `(stack empty)`).
- As a method, prints the receiver in typed style.

### `print(...values)` / `target.print()`
- Prints values in plain style without a trailing newline.
- If called with no arguments, prints top of stack.
- As a method, prints the receiver.

### `println(...values)` / `target.println()`
- Prints values in plain style followed by a newline.
- If called with no arguments, prints top of stack plus newline.
- As a method, prints the receiver followed by a newline.

### `len(target)` / `target.len()`
- Returns logical length (same semantics as `.size`).
- Int arrays: `total_bytes / sizeof(Int)` (native-width element count).
- Float arrays: `total_bytes / sizeof(Float)`.
- String literals / `.string` views: `strlen` (bytes up to first `\0`).
- Tables: entry count.
- Numeric list shorthand is valid: `a = 1 2 3,` then `len(a)` returns `3`.

### `pretty(target)` / `target.pretty()`
- Returns a formatted multiline representation.

### `clone(target)` / `target.clone()`
- Returns shallow copy.

### `copy(target)` / `target.copy()`
- Returns deep copy.

### `toInt(floatList)` / `floatList.toInt()`
- Converts float list to int list.
- Errors if target is not float list.

### `toFloat(intListOrString)` / `intList.toFloat()`
- Converts int list to float list.
- Strings are converted byte-by-byte to float values.
- Errors if target is not int-based list.

## IO (requires `DISABLE_SYSTEM=0`)

### `read(path)`
- `path` must be string.
- Returns byte-string content.
- On failure, prints error and returns `null`.

### `write(path, data)`
- `path` must be string.
- `data` can be string or any value (non-string is stringified).
- Returns `1` on success, `0` on failure.

## Modules and Evaluation

### `import(path)`
- `path` must be string.
- Rules:
  - if `.urb`, load directly
  - otherwise load `path/<basename(path)>.urb`
- Executes module in isolated VM.
- Module export is top-level `return` value.
- Uses module cache by resolved path.

### `eval(source)`
- `source` must be string.
- Executes source in current VM.
- Returns `null`.

### `parse(source)`
- `source` must be string.
- Compiles source to bytecode bytes.
- Returns byte-string.

### `emit(x)`
- If `x` is bytecode bytes: returns disassembly text.
- If `x` is bytecode AST table: returns encoded bytes.
- Otherwise errors.

### `evalBytecode(bytes)`
- Executes bytecode bytes.
- Returns `null`.

## GC

### `gc.collect()`
- Runs collection.
- Returns `null`.

### `gc.free(value)`
- Attempts immediate free and sets value to `null` entry.
- Returns `1` on success.
- Fails for protected/shared entries.

### `gc.sweep(value)`
- Marks value for reuse and resets entry to `null`.
- Returns `1` on success.
- Fails for protected entries.

### `gc.new(size = 0)`
- Creates a table with reserved capacity.
- `size` must be non-negative integer.

### `gc.debug()`
- Prints reuse-pool diagnostics.
- Returns `null`.

### `gc.stats()`
- Prints GC memory stats snapshot.
- Returns `null`.

Runtime flags on `gc` object:
- `gc.keyintern = 0|1`

Note:
- `gc.flush()` exists internally but is not currently exposed as a field on `global.gc`.

## Numeric Helpers

All below support global and method form when applicable.

### `append(dst, src)` / `dst.append(src)`
- String-only append.
- Mutates destination string in place.

### `add(a, b, ...)` / `a.add(b, ...)`
- Numeric sum.

### `sub(a, b, ...)` / `a.sub(b, ...)`
- Numeric subtraction chain.

### `mul(a, b, ...)` / `a.mul(b, ...)`
- Numeric multiplication chain.

### `div(a, b, ...)` / `a.div(b, ...)`
- Numeric division chain.

### `mod(a, b)` / `a.mod(b)`
- Numeric modulo (`fmod`).

### `pow(base, exp)` / `base.pow(exp)`
- Exponentiation.

### `min(a, b, ...)` / `a.min(b, ...)`
- Minimum value.

### `max(a, b, ...)` / `a.max(b, ...)`
- Maximum value.

### `abs(x)` / `x.abs()`
- Absolute value.

### `floor(x)` / `x.floor()`
- Floor.

### `ceil(x)` / `x.ceil()`
- Ceil.

### `round(x)` / `x.round()`
- Round.

### `sqrt(x)` / `x.sqrt()`
- Square root.

### `sin(x)` / `x.sin()`
- Sine.

### `cos(x)` / `x.cos()`
- Cosine.

### `tan(x)` / `x.tan()`
- Tangent.

### `asin(x)` / `x.asin()`
- Arc-sine.

### `acos(x)` / `x.acos()`
- Arc-cosine.

### `atan(x)` / `x.atan()`
- Arc-tangent.

### `log(x)` / `x.log()`
- Natural logarithm.

### `exp(x)` / `x.exp()`
- Exponential.

## String and Byte Helpers

### `slice(s, start = 0, end = len)` / `s.slice(...)`
- Returns substring by half-open range `[start, end)`.
- Accepts negative indexes.
- Clamps to valid range.

### `substr(s, start = 0, count = len-start)` / `s.substr(...)`
- Returns substring by start + length.

### `split(s, delim = "")` / `s.split(delim)`
- Returns table of substrings.
- Empty delimiter splits into single-byte chunks.

### `join(arr, delim = "")` / `arr.join(delim)`
- Stringifies each element and joins.

### `upper(s)` / `s.upper()`
- Uppercases ASCII bytes.

### `lower(s)` / `s.lower()`
- Lowercases ASCII bytes.

### `trim(s)` / `s.trim()`
- Trims surrounding whitespace.

### `startsWith(s, prefix)` / `s.startsWith(prefix)`
- Returns `1`/`0`.

### `endsWith(s, suffix)` / `s.endsWith(suffix)`
- Returns `1`/`0`.

### `replace(s, needle, replacement)` / `s.replace(...)`
- Literal substring replacement (first occurrence only).

### `replaceAll(s, needle, replacement)` / `s.replaceAll(...)`
- Literal substring replacement (all occurrences).

### `papagaio(s)` / `s.papagaio()`
- Runs Papagaio processing and returns transformed string.

## Table/List/Array Helpers

### `keys(table)` / `table.keys()`
- Returns table with key names as strings.

### `values(table)` / `table.values()`
- Returns table with value references.

### `has(target, keyOrIndex)` / `target.has(...)`
- For tables:
  - string key lookup
- For list-like targets:
  - numeric index check
- Returns `1`/`0`.

### `delete(target, keyOrIndex)` / `target.delete(...)`
- Deletes by key/index.
- Returns `1` on delete, `0` if not found/out-of-range.

### `push(target, ...values)` / `target.push(...)`
- Appends values to end.
- Table: appends entries.
- String: appends string bytes.
- Int list: appends integral numbers.
- Float list: appends numeric values.
- Side-effect oriented.

### `pop(target)` / `target.pop()`
- Removes and returns last item.
- Table/string/int-list/float-list supported.

### `shift(target)` / `target.shift()`
- Removes and returns first item.
- Table/string/int-list/float-list supported.

### `unshift(target, ...values)` / `target.unshift(...)`
- Inserts values at front.
- Type rules mirror `push`.
- Side-effect oriented.

### `insert(target, index, value)` / `target.insert(index, value)`
- Inserts at index.
- String/list/table supported.
- Side-effect oriented.

### `remove(target, keyOrIndex)` / `target.remove(...)`
- Table:
  - string key removes matching key and returns removed value
  - integer index removes positional entry and returns value
- String/list:
  - removes at numeric index and returns removed element

## FFI

Runtime C integration is exposed under global `C`.

Primary APIs used by examples/tests:
- `C.info()`
- `C.typedef(name, type)`
- `C.enum(name, fields)`
- `C.define(name, value)`
- `C.struct(name, schema)`
- `C.ffi.open(libPath)`
- `C.ffi.sym(libHandle, symbolName)`
- `C.ffi.close(libHandle)`
- `C.ffi.bind(ptr, sig)`
- `C.ffi.callback(sig, lambda)` (builds C callback pointer from lambda)
- `C.ffi.auto(libOrProxy, sig)` / `C.ffi.lib(path)`
- `C.ffi.global(lib, name, typeOrSchema)`
- `C.ffi.trace()` / `C.ffi.trace(0|1)`
- `C.memory.compile(schema)`
- `C.memory.new(schemaOrLayout)` (allocates zeroed struct memory and returns owned pointer handle)
- `C.memory.struct(schemaOrLayout[, init])`
- `C.memory.free(ptr)`
- `C.memory.buffer(len)` (owned raw byte buffer)
- `C.memory.string(ptr)` / `C.memory.string(ptr, len)`
- `C.memory.point(value)` (returns numeric pointer; supports numeric/string lists, numeric views, and pointer-like FFI values)
- `C.memory.valid(ptr)`
- `C.memory.read(ptr, type[, len])` / `C.memory.write(ptr, type, value)`
- `C.memory.copy(dst, src, len)` / `C.memory.move(dst, src, len)` / `C.memory.zero(ptr, len)`
- `C.memory.offset(ptr, byteOffset)` / `C.memory.offset(ptr, index, elemTypeOrSchema)`
- `C.memory.cast(ptr, schemaOrLayout)` / `C.memory.deref(ptr[, schemaOrType])`
- `C.memory.sizeof(schemaOrLayout)`
- `C.memory.alignof(schemaOrLayout)`
- `C.memory.offsetof(schemaOrLayout, "field.path")`
- `C.memory.view(ptr, schemaOrLayout[, totalSize])`
- `C.memory.viewArray(ptr, elemSpec, len)`
- `C.memory.compile(schema)` is optional in common flows; schema tables are auto-compiled/cached when passed to `C.memory.view`, `C.memory.sizeof`, `C.memory.alignof`, `C.memory.offsetof`, and `C.memory.new`.
- signatures support: `struct(schema)` (by-value struct), `union(schema)` (by-value union), `pointer(schema)` (typed pointer), `void*` (raw pointer), pointer depth via `pointer(pointer(...))`
- string-like types in signatures:
  - `string`: marshaled as Disturb string
  - `cstring`: raw C pointer value
- optional ABI prefix in signature: `abi(name)` or bare ABI keyword (`cdecl`, `stdcall`, `fastcall`, `thiscall`, `win64`, `unix64`, `sysv`)
- schema field declarations are strings only; compose with `"struct(name)"`, `"union(name)"`, and `"pointer(name)"`
- function pointer fields: `"function(signature)"` (example: `"function(i32 cb(i32, i32))"`)
- bitfields are declared as `"type:bits"` (e.g., `"uint8:3"`)
- unions are declared via `__meta = { union = 1 }`
- qualifiers accepted in signatures/schema strings: `const`, `volatile`, `restrict`
- view write behavior on `const` fields/elements:
  - warns and ignores write
- variadic signatures are supported with `...` (for `C.ffi.bind`)
- callbacks support scalar and by-value struct/union signatures (callback variadics still unsupported)

See:
- `examples/guide/11_ffi_system.urb`
- `examples/guide/14_ffi_struct_views_bind.urb`
- `examples/guide/15_ffi_callbacks_varargs_buffers.urb`
- `tests/cases/ffi_view_struct.urb`
- `tests/cases/ffi_varargs.urb`
- `tests/cases/ffi_callbacks.urb`
- `tests/cases/ffi_auto_compile.urb`
- `tests/cases/ffi_buffers_strings.urb`
- `tests/cases/ffi_const_views.urb`

# Disturb Reference Sheet

Quick syntax and semantics cheatsheet for day-to-day usage.

## Run

```bash
make
./disturb script.urb [args...]
./disturb --compile-bytecode script.urb out.bytecode
./disturb --run-bytecode out.bytecode [args...]
```

## Core Rules

- `x = 1,` writes to `global.x`.
- Statements are separated by commas; the final comma in a sequence is optional.
- Missing global/key returns `null`.
- `global` is a real table.
- Method call binds `this`: `obj.fn()`.
- `global.common` provides common methods.

## Types and Literals

- int: `1`, `1i`, `1u`
- float: `3.14`, `1f`
- char: `'a'` (single byte only)
- string: `"abc"`
- numeric list shorthand: `1 2 3`
- list (general form): `[1, 2, 3]`
- table: `{a = 1, b = "x"}`
- special: `null`, `inf`

Type names (`value.type`):
- `null`, `int`, `float`, `char`, `string`, `table`, `native`, `lambda`, `view`

## Truthiness

False:
- `null`
- `0` / `0.0`

True:
- everything else

## Operators

- arithmetic: `+ - * / %`
- unary: `- ! ~`
- compare: `< <= > >=`
- equality: `== != === !==`
- logical: `&& ||`
- bitwise: `& | ^ << >>`
- assign: `= += -= *= /= %= &= |= ^= <<= >>=`
- default assign: `?=`
- increments: `++ --` (prefix/postfix)

## Equality

- `==` compares value/content.
- `===` compares strict identity/type-level semantics.

## Control Flow

- `if` / `else if` / `else` (parentheses optional: `if x > 0 { … }` or `if (x > 0) { … }`)
- `while` (parentheses optional)
- `for (init, cond, step)` or `for init, cond, step` (parentheses optional)
- `each(v in expr)` or `each v in expr` (parentheses optional)
- `switch` / `case` / `default` (no fallthrough; parentheses optional: `switch x { … }` or `switch (x) { … }`)
- `break`, `continue`, `return`
- `label:` + `goto label,`

## Operators

- arithmetic: `+ - * / %`
- unary: `- ! ~`
- compare: `< <= > >=`
- equality: `== != === !==`
- logical: `&& ||`
- bitwise: `& | ^ << >>`
- assign: `= += -= *= /= %= &= |= ^= <<= >>=`
- default assign: `?=`
- increments: `++ --` (prefix/postfix)

```disturb
sum = (a, b = 1, ...rest){ return a + b, }
```

- varargs must be last
- missing non-default arg becomes `null`
- `return;` returns `null`
- `local` is available in lambda scope

## Access and Indexing

- table key: `obj.k`, `obj["k"]`
- numeric index: `arr[0]`, `str[0]`
- negative indexes are supported in many native list/string helpers
- out-of-range direct index access errors

## Copy Semantics

- assignment is by reference
- `clone()` shallow copy
- `copy()` deep copy

## Meta Fields

- `.name`
- `.type`
- `.value`
- `.size`
- `.capacity`

Common checks:
- `x.name = null` clears key name
- `.size` expects integer
- `.capacity` expects numeric

## Strict Mode

```disturb
use strict,
use nostrict,
```

Also valid:
- `use "strict",`
- `use "nostrict",`

Strict mode forbids:
- mixed int/float arithmetic and numeric comparisons
- number/string comparisons
- `null` in numeric operations
- mixed int/float numeric list literals

Runtime toggle:

```disturb
global.gc.strict = 1,
global.gc.strict = 0,
```

## IO and Eval

- `read(path)` -> byte-string
- `write(path, data)` -> `1` or `0`
- `eval(source)` -> executes source, returns `null`
- `parse(source)` -> bytecode bytes
- `emit(bytes)` -> disassembly text
- `evalBytecode(bytes)` -> executes bytecode, returns `null`

## Modules

```disturb
m = import("tests/modules/math.urb");
p = import("tests/modules/pkg"); // loads tests/modules/pkg/pkg.urb
```

- module runs in isolated VM
- export is top-level `return`
- cache by resolved path

## Papagaio

- string literals containing `$` are processed
- escape literal `$` with `\$`
- runtime call: `papagaio(text)`

Patterns:
- `$pattern{...}{...}`
- `$regex ... {...}`
- `$eval{...}`

## GC Controls

`global.gc` functions:
- `collect()`
- `free(value)`
- `sweep(value)`
- `new(size)`
- `debug()`
- `stats()`

Flags:
- `global.gc.strict = 0|1`
- `global.gc.keyintern = 0|1`

## FFI (optional build)

Always available (core FFI is always enabled).

Main API:
- `ffi.open(path)`
- `ffi.sym(lib, name)`
- `ffi.close(lib)`
- `ffi.bind(ptr, sig)`
- `ffi.callback(sig, lambda)`
- `ffi.compile(schema)`
- `ffi.new(schemaOrLayout)` (allocates zeroed struct memory; returns owned pointer handle)
- `ffi.free(ptr)`
- `ffi.buffer(len)` (owned raw buffer)
- `ffi.string(ptr[, len])`
- `ffi.sizeof(...)`
- `ffi.alignof(...)`
- `ffi.offsetof(..., "field.path")`
- `ffi.view(ptr, schemaOrLayout)`
- `ffi.viewArray(ptr, elemSpec, len)`
- `ffi.compile(schema)` is optional: schema tables are auto-compiled/cached when accepted.
- signatures: `struct(schema)`, `union(schema)`, `pointer(schema)`, `void*` (raw), nested pointer depth via `pointer(pointer(...))`
- `string` vs `cstring`/`cstr`:
  - `string`: marshals to/from Disturb string values
  - `cstring`/`cstr`: raw C pointer behavior
- optional ABI prefix in signature: `abi(name)` or bare ABI (`cdecl`, `stdcall`, `fastcall`, `thiscall`, `win64`, `unix64`, `sysv`)
- schema fields support composition with strings: `"struct(name)"`, `"union(name)"`, `"pointer(name)"`
- function pointer fields: `"function(signature)"` (example: `"function(i32 cb(i32, i32))"`; `"fn(...)"` alias accepted)
- bitfield declaration: `"uint8:3"`, `"uint32:5"` (inside struct)
- union declaration: `__meta = { union = 1 }`
- qualifiers accepted: `const`, `volatile`, `restrict`
- variadic signatures: `...` (in `ffi.bind`)
- callbacks support scalars and by-value struct/union signatures (callback variadics remain unsupported)
- `const` writes in views:
  - strict off: warning + ignored write
  - strict on: panic/abort

## Script Args

Injected globals:
- `arg_0`, `arg_1`, ...
- `args` (table)
- `argc` (string)

# Disturb Function Reference

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

### `print(...values)`
- Prints values in typed/literal style.
- If called with no arguments, prints top of stack (or `(stack empty)`).

### `println(...values)`
- Prints values in plain style.
- If called with no arguments, prints top of stack plus newline.

### `len(target)` / `target.len()`
- Returns logical length.
- Strings: bytes length.
- Numeric lists: element count.
- Tables: entry count.

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

## IO (requires `ENABLE_IO=1`)

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

### `bytecodeToAst(x)`
- Currently returns `null` (stub).

### `astToSource(x)`
- Currently returns `null` (stub).

## GC

### `gc()`
- Manual collection helper.
- Equivalent behavior to `gc.collect()`.
- Returns `null`.

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
- `gc.strict = 0|1`
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

## Not Exposed in Current Build

The following native implementations exist internally but are not currently attached to `global.common` by default:
- `find`
- `rfind`
- `contains`

If these are intended to be public, they need to be registered in VM initialization.

## FFI

FFI appears under global `ffi` only when built with `ENABLE_FFI=1`.

Primary APIs used by examples/tests:
- `ffi.open(libPath)`
- `ffi.sym(libHandle, symbolName)`
- `ffi.close(libHandle)`
- `ffi.bind(ptr, sig)`
- `ffi.callback(sig, lambda)` (builds C callback pointer from lambda)
- `ffi.compile(schema)`
- `ffi.new(schemaOrLayout)` (allocates zeroed struct memory and returns owned pointer handle)
- `ffi.free(ptr)`
- `ffi.buffer(len)` (owned raw byte buffer)
- `ffi.string(ptr)` / `ffi.string(ptr, len)`
- `ffi.sizeof(schemaOrLayout)`
- `ffi.alignof(schemaOrLayout)`
- `ffi.offsetof(schemaOrLayout, "field.path")`
- `ffi.view(ptr, schemaOrLayout)`
- `ffi.viewArray(ptr, elemSpec, len)`
- `ffi.compile(schema)` is optional in common flows; schema tables are auto-compiled/cached when passed to `ffi.view`, `ffi.sizeof`, `ffi.alignof`, `ffi.offsetof`, and `ffi.new`.
- signatures support: `struct<schema>` (by-value struct), `union<schema>` (by-value union), `pointer<schema>` (typed pointer), `void*` (raw pointer)
- schema field declarations are strings only; compose with `"struct<name>"`, `"union<name>"`, and `"pointer<name>"`
- function pointer fields: `"function<signature>"` (example: `"function<i32 cb(i32, i32)>"`; `"fn<...>"` alias accepted)
- bitfields are declared as `"type:bits"` (e.g., `"uint8:3"`)
- unions are declared via `__meta = { union = 1 }`
- qualifiers accepted in signatures/schema strings: `const`, `volatile`, `restrict`
- view write behavior on `const` fields/elements:
  - non-strict: warns and ignores write
  - strict: aborts runtime (`PANIC`)
- variadic signatures are supported with `...` (for `ffi.bind`)

See:
- `example/guide/11_ffi_system.urb`
- `example/guide/14_ffi_struct_views_bind.urb`
- `example/guide/15_ffi_callbacks_varargs_buffers.urb`
- `tests/cases/ffi_view_struct.urb`
- `tests/cases/ffi_varargs.urb`
- `tests/cases/ffi_callbacks.urb`
- `tests/cases/ffi_auto_compile.urb`
- `tests/cases/ffi_buffers_strings.urb`
- `tests/cases/ffi_const_views.urb`

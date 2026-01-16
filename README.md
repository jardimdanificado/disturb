# Disturb

Disturb is a stack-oriented VM with a C-like source syntax that compiles to a compact RPN bytecode. The language focuses on safety and explicit behavior: everything lives under the global object, and missing lookups return a null object.

## Quick Start

| Command | Purpose |
| --- | --- |
| `make` | Build `disturb` |
| `./disturb file.disturb` | Run source |
| `./disturb --asm input.asm output.bin` | Assemble to bytecode |
| `./disturb --disasm input.bin output.asm` | Disassemble bytecode |

## Core Model

| Concept | Behavior |
| --- | --- |
| Global root | `a = b;` is the same as `global.a = b;` |
| Object type | `object` (formerly `any`) is the generic container |
| Null | Missing globals/keys return `null` |
| Natives | Built-in and stored in `global` as objects |
| Prototype | Shared methods live on `global.prototype` |
| this | Method calls bind `this` to the call target |

## Types and Literals

| Type | Literal | Notes |
| --- | --- | --- |
| number | `1`, `3.14` | Always floating point |
| byte | `(byte){9, 1, 2}` | Byte list, values 0–255 |
| char | `'c'` | Single byte |
| string | `"abc"` | Char object with length > 1 |
| object | `(object){a = 1}` | Keyed container |

## Construction

| Form | Result |
| --- | --- |
| `(number){1, 2}` | Number list |
| `(byte){9, 1}` | Byte list |
| `(object){a = b}` | Object with keys |

## Expressions and Operators

Operators follow standard precedence with parentheses support:
- Unary: `!`, unary `-`
- Multiplicative: `*`, `/`, `%`
- Additive: `+`, `-`
- Comparisons: `<`, `<=`, `>`, `>=`
- Equality: `==`, `!=`
- Logical: `&&`, `||`

Notes:
- Logical and comparison operators return numbers (`1` or `0`).
- `null` is false; everything else is true.
- `+` concatenates when either side is a string/char; non-strings stringify to Disturb literals.

## User Functions

Define functions by assigning a parameter list and body:
- `name = (a, b, rest...){ println(a + b); }`

Rules:
- Parameters are identifiers only.
- `...` marks the last parameter as a vararg list (stored as an object list).
- Calls bind `this` to the call target (`obj.method()` sets `this` to `obj`).
- Calling an object by name (e.g. `obj()`) uses a method with the same name inside that object.

## Indexing

| Syntax | Meaning |
| --- | --- |
| `a[i]` | Numeric indexing |
| `a.key` | Object key lookup |
| `a["key"]` | Object key lookup |
| `a[string_obj]` | Object key lookup |

Rules:
- Only `object` supports string/key indexing.
- Indexing bytes/chars yields a single byte/char object.
- Indexing supports infinite nesting.

## Meta Properties

Every entry exposes meta properties via string keys:

| Property | Type | Description |
| --- | --- | --- |
| `.name` | string | Key name in its parent (`global.a.name == "a"`) |
| `.type` | string | `null`, `number`, `byte`, `char`, `string`, `object`, `native` |
| `.size` | number | Used slots (`list.size - 2`) |
| `.capacity` | number | Allocated slots (`list.capacity - 2`) |

Notes:
- `.name` and `.type` are read-only.
- Setting `.size` changes used slots; if larger than capacity it reallocates.
- Setting `.capacity` reallocates; the object remains in the same entry slot.

## Bytecode

The bytecode is RPN stack-based. There is no const pool; literals are inline.

| Opcode | Stack effect | Purpose |
| --- | --- | --- |
| `PUSH_NUM` | `-- num` | Push number literal |
| `PUSH_CHAR` | `-- char` | Push char literal |
| `PUSH_STRING` | `-- string` | Push string literal |
| `PUSH_BYTE` | `-- byte` | Push byte literal |
| `BUILD_NUMBER n` | `v… -- list` | Build number list |
| `BUILD_BYTE n` | `v… -- list` | Build byte list |
| `BUILD_OBJECT n` | `k v… -- obj` | Build object |
| `INDEX` | `obj idx -- value` | Indexing |
| `STORE_INDEX` | `obj idx val --` | Assign by index/key |
| `LOAD_ROOT` | `-- global` | Push global root |
| `LOAD_GLOBAL` | `-- value` | Lookup in global |
| `LOAD_THIS` | `-- this` | Load current `this` |
| `STORE_GLOBAL` | `val --` | Store in global |
| `SET_THIS` | `val --` | Set current `this` |
| `CALL` | `args --` | Call native |
| `POP` | `val --` | Drop |
| `DUP` | `val -- val val` | Duplicate |
| `GC` | `--` | Collect |
| `DUMP` | `--` | Dump global |
| `ADD` | `a b -- out` | Add/concat |
| `SUB` | `a b -- out` | Subtract |
| `MUL` | `a b -- out` | Multiply |
| `DIV` | `a b -- out` | Divide |
| `MOD` | `a b -- out` | Modulo |
| `NEG` | `a -- out` | Unary minus |
| `NOT` | `a -- out` | Logical not |
| `EQ` | `a b -- out` | Equality |
| `NEQ` | `a b -- out` | Inequality |
| `LT` | `a b -- out` | Less than |
| `LTE` | `a b -- out` | Less or equal |
| `GT` | `a b -- out` | Greater than |
| `GTE` | `a b -- out` | Greater or equal |
| `AND` | `a b -- out` | Logical and |
| `OR` | `a b -- out` | Logical or |

## Safety Notes and Oddities

- Missing globals/keys yield `null` instead of error.
- `global` is a real object; `global.name[0]` is valid.
- Strings are `char` objects; `char` vs `string` is decided by length.
- Resizing always keeps the same object entry slot to preserve references.
- Object stringification uses Disturb literals like `(object){a = 1, b = "x"}`.

## Built-in Methods

All objects share methods from `global.prototype` and can be called as `obj.method(...)`.

Math:
- `add`, `sub`, `mul`, `div`, `mod`, `pow`, `min`, `max`
- `abs`, `floor`, `ceil`, `round`, `sqrt`
- `sin`, `cos`, `tan`, `asin`, `acos`, `atan`, `log`, `exp`

Strings:
- `slice`, `substr`, `split`, `join`, `upper`, `lower`, `trim`
- `startsWith`, `endsWith`, `replace`

Objects/Arrays:
- `keys`, `values`, `has`, `delete`
- `push`, `pop`, `shift`, `unshift`, `insert`, `remove`

`replace` uses Papagaio-style patterns:
- `"hello $name".replace("$name", "world")`

`print`/`println` with no arguments prints the top of the stack if present.

## Tests

| Command | Purpose |
| --- | --- |
| `tests/run.sh` | Runs all language and asm tests |
| `tests/bench.sh` | Runs benchmarks (best-effort) |

Test sources live in `tests/cases`, expected outputs in `tests/expected`.

### Negative and Stress Tests

| Folder | Purpose |
| --- | --- |
| `tests/negative` | Parser and runtime error cases (stderr checks) |
| `tests/cases` | Positive and stress cases |

Stress cases include deep nesting and large list construction to push recursion and indexing.

### Benchmarks

The benchmark script measures:
- Cross-language literal list parsing, deep object access, and string length for Disturb/Lua/Node/Python/C if present

Run:
- `RUNS=5 BIN=./disturb tests/bench.sh`

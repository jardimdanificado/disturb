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
| `STORE_GLOBAL` | `val --` | Store in global |
| `CALL` | `args --` | Call native |
| `POP` | `val --` | Drop |
| `DUP` | `val -- val val` | Duplicate |
| `GC` | `--` | Collect |
| `DUMP` | `--` | Dump global |

## Safety Notes and Oddities

- Missing globals/keys yield `null` instead of error.
- `global` is a real object; `global.name[0]` is valid.
- Strings are `char` objects; `char` vs `string` is decided by length.
- Resizing always keeps the same object entry slot to preserve references.

## Tests

| Command | Purpose |
| --- | --- |
| `tests/run.sh` | Runs all language and asm tests |

Test sources live in `tests/cases`, expected outputs in `tests/expected`.

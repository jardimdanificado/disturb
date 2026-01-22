# Disturb

Disturb is a stack-oriented VM with a C-like source syntax that compiles to a compact RPN bytecode. The language focuses on safety and explicit behavior: everything lives under the global table, and missing lookups return a null table.

## Quick Start

| Command | Purpose |
| --- | --- |
| `make` | Build `disturb` |
| `./disturb file.disturb` | Run source |
| `./disturb` | Interactive REPL |
| `./disturb --repl` | Interactive REPL |
| `./disturb --asm input.asm output.bin` | Assemble to bytecode |
| `./disturb --disasm input.bin output.asm` | Disassemble bytecode |

## Core Model

| Concept | Behavior |
| --- | --- |
| Global root | `a = b;` is the same as `global.a = b;` |
| Table type | `table` (formerly `any`) is the generic container |
| Null | Missing globals/keys return `null` |
| Natives | Built-in and stored in `global` as tables |
| Common | Shared methods live on `global.common` |
| this | Method calls bind `this` to the call target |

## Types and Literals

| Type | Literal | Notes |
| --- | --- | --- |
| number | `1`, `3.14` | Always floating point; arrays use `[]` |
| byte | `[65, 66, 67].toByte()` | String/byte value built from explicit numbers |
| char | `'c'` | Single-byte string |
| string | `"abc"` | String with length > 1 |
| table | `{a = 1}` | Keyed container |

## Construction

| Form | Result |
| --- | --- |
| `[1, 2]` | Number list |
| `[9, 1].toByte()` | Byte/string literal derived from numeric values |
| `{a = b}` | Table with keys |

Notes:
- `[]` builds a number array; call `.toByte()` to coerce to a byte string and `.toNumber()` on byte strings to get numbers.
- Table literals now use `{...}` exclusively; the `table` prefix is no longer supported.
- Plain `{}` is reserved for tables, while `(args){...}` still introduces a lambda.
- Compound assignments (`+=`, `-=`, `*=`, `/=`, `%=`) and increment/decrement statements (`++i`, `i++`, `--i`, `i--`) mutate the left-hand target in place; increments add/subtract `1`.

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
- `null` and numeric `0` are false; everything else is true.
- `+` concatenates when either side is a string/char/byte; non-strings stringify to Disturb literals.
- `a ?= b` assigns `b` only when `a` is `null`.
- Assignment and `++`/`--` forms are expressions and return a value (prefix returns the updated value, postfix returns the previous value).
- Byte indexing assignments accept either byte-length strings/bytes or numeric values `0-255`.

## Control Flow

Supported control flow forms:
- `if (cond) { ... } else { ... }`
- `if (cond) { ... } else if (cond) { ... }`
- `while (cond) { ... }`
- `for (init; cond; step) { ... }`
- `each(value in expr) { ... }`
- `break;` and `continue;`

Notes:
- `each` iterates in index order. For tables, the entry key is available via `value.name`.
- `switch (expr) { case literal: ... }` performs equality checks (strings/numbers) and exits after the first matching case; `default` runs if no case matches (no fall-through, so `break` is unnecessary).
- Performance: the current compiler emits a linear chain of comparisons, so runtime is similar to `if/else`. There is no jump-table optimization yet; dense integer switches would benefit if one is added.
- Use `label:` definitions and `goto label;` statements for direct jumps; `goto` resolves labels at compile time.

## Lambdas

- Define lambdas by assigning a parameter list and body:
- `name = (a, b, rest...){ println(a + b); }`
- `name = (a = 1, b = "x"){ println(a + b); }`

- Rules:
- Parameters are identifiers only.
- `...` marks the last parameter as a vararg list (stored as a table list).
- Missing arguments default to `null` unless a default value is provided.
- `return expr;` exits a lambda and returns a value. `return;` returns `null`.
- Calls bind `this` to the call target (`obj.method()` sets `this` to `obj`).
- Calling a table by name (e.g. `obj()`) uses a method with the same name inside that table.
- Calls can be used inside expressions (`x = add(1, 2);`).

## Indexing

| Syntax | Meaning |
| --- | --- |
| `a[i]` | Numeric indexing |
| `a.key` | Table key lookup |
| `a["key"]` | Table key lookup |
| `a[string_obj]` | Table key lookup |

Rules:
- Only `table` supports string/key indexing.
- Indexing strings/bytes yields a single-byte string.
- Indexing supports infinite nesting.

## Meta Properties

Every entry exposes meta properties via string keys:

| Property | Type | Description |
| --- | --- | --- |
| `.name` | string | Key name in its parent (`global.a.name == "a"`) |
| `.type` | string | `null`, `number`, `byte`, `char`, `string`, `table`, `native` |
| `.size` | number | Used slots (`list.size - 2`) |
| `.capacity` | number | Allocated slots (`list.capacity - 2`) |

Notes:
- `.name` and `.type` are writable. `.name = null` clears the key. `.type` is pure type punning (no conversion).
- Setting `.size` changes used slots; if larger than capacity it reallocates.
- Setting `.capacity` reallocates; the table remains in the same entry slot.

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
| `JMP` | `--` | Unconditional jump |
| `JMP_IF_FALSE` | `cond --` | Jump if false |
| `RETURN` | `val? --` | Return from function |
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
- `global` is a real table; `global.name[0]` is valid.
- Strings are `char` objects; `char` vs `string` is decided by length.
 - Assignments are reference-based; use `clone()` for shallow copies or `copy()` for deep copies.
 Resizing always keeps the same table entry slot to preserve references.
## Built-in Methods
 Cross-language literal list parsing, deep table access, and string length for Disturb/Lua/Node/Python/C if present
 `BUILD_OBJECT n` | `k v… -- obj` | Build table |

Math:
- `add`, `sub`, `mul`, `div`, `mod`, `pow`, `min`, `max`
- `abs`, `floor`, `ceil`, `round`, `sqrt`
- `sin`, `cos`, `tan`, `asin`, `acos`, `atan`, `log`, `exp`

Strings:
- `slice`, `substr`, `split`, `join`, `upper`, `lower`, `trim`
- `startsWith`, `endsWith`, `replace`, `replaceAll`

Tables/Arrays:
- `keys`, `values`, `has`, `delete`
- `push`, `pop`, `shift`, `unshift`, `insert`, `remove`

Values:
- `clone` (shallow copy), `copy` (deep copy)

Formatting:
- `pretty`

IO(might not be available in all environments):
- `read`, `write`

Metaprogramming:
- `parse`, `emit`, `evalBytecode`, `bytecodeToAst`, `astToSource`, `eval`

GC:
- `gc`, `global.gc`

Notes:
- `read(path)` returns a string with file contents.
- `write(path, data)` writes a stringified value and returns `1` on success.
- `eval(code)` executes code in the current VM and returns `null`.
- `parse(source)` compiles source into a bytecode AST (see below).
- `emit(ast)` produces bytecode bytes from a bytecode AST.
- `evalBytecode(bytes)` executes bytecode and returns `null`.
- `bytecodeToAst(bytes)` decodes bytecode bytes into a bytecode AST.
- `astToSource(ast)` returns a disassembly-style text view of the bytecode AST.

## Bytecode AST

Metaprogramming functions use a bytecode-level AST, not a syntax AST.

Top-level shape:
- `{type = "bytecode", ops = {...}}`

Each `ops` item is a table with `op` and optional fields:
- `PUSH_NUM`: `value` (number)
- `PUSH_CHAR`/`PUSH_STRING`: `value` (string)
- `PUSH_BYTE`: `value` (0-255)
- `BUILD_NUMBER`/`BUILD_BYTE`/`BUILD_OBJECT`: `count` (number)
- `BUILD_NUMBER_LIT`: `values` (array of numbers)
- `BUILD_FUNCTION`: `argc`, `vararg`, `code` (byte string), `args` (array of `{name, default}`)
- `LOAD_GLOBAL`/`STORE_GLOBAL`: `name` (string)
- `CALL`: `name` (string), `argc` (number)
- `JMP`/`JMP_IF_FALSE`: `target` (number)

Notes:
- `astToSource` follows the disassembler format; `BUILD_FUNCTION` shows lengths, not raw bytes.
- `emit` consumes AST objects directly, so include `code`/`default` byte strings in `BUILD_FUNCTION`.
- `gc()` runs a collection.
- `global.gc.collect()` runs a collection (manual only, no automatic GC).
- `global.gc.free(value)` frees the value and replaces it with `null` (manual management).
- `global.gc.sweep(value)` marks a value as unused so `gc.collect()` will free it.
- `global.gc.new(size)` allocates a table with reserved capacity.
- Comments are supported via `//` and `/* ... */`.

Papagaio processing is applied to all string literals. Use `\$` to escape a literal `$`.

`replace` and `replaceAll` perform literal substring replacement (first match vs all matches). For Papagaio patterns on runtime strings, use `papagaio(text)` with `$pattern{...}{...}` directives embedded in the text:
- `papagaio("$pattern{hello $name}{Oi $name}hello Joao")`
- `papagaio("\$pattern{a}{b}a")`

Papagaio tokens:
- `$pattern{...}{...}` defines a pattern+replacement pair (nested patterns are supported).
- `$regex name {pattern}` captures regex matches (use `$regex{0}`/`{1}`... in replacements).
- `$eval{...}` evaluates Disturb code; use `return` to produce a value.
- `this` inside `$eval{}` points to `global.papagaio`, which exposes `content` and `match`.

`print`/`println` with no arguments prints the top of the stack if present.

## Tests

| Command | Purpose |
| --- | --- |
| `tests/run.sh` | Runs all language and asm tests |
| `tests/bench.sh` | Runs benchmarks (best-effort) |

Test sources live in `tests/cases`, expected outputs in `tests/expected`.

## Guide Examples

The tutorial-style examples live in `example/guide` and are numbered:
- `example/guide/01_intro.disturb`
- `example/guide/02_types_literals.disturb`
- `example/guide/03_indexing_objects.disturb`
- `example/guide/04_operators_truthiness.disturb`
- `example/guide/05_functions_methods.disturb`
- `example/guide/06_control_flow.disturb`
- `example/guide/07_strings_bytes_io_eval.disturb`
- `example/guide/08_vm_notes.disturb`
- `example/guide/09_metaprogramming.disturb`

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

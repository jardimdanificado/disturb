# Disturb

Disturb is a stack-oriented VM with a C-like source syntax that compiles to a compact RPN bytecode. The language focuses on safety and explicit behavior: everything lives under the global table, and missing lookups return a null table.

Disturb means Distributable Urb, at least that was the original idea;

## Quick Start

| Command | Purpose |
| --- | --- |
| `make` | Build `disturb` |
| `./disturb file.disturb` | Run source |
| `./disturb --compile-bytecode script.disturb output.bytecode` | Compile a script into raw bytecode |
| `./disturb --run-bytecode output.bytecode [args...]` | Run a previously compiled bytecode file |
| `./disturb --repl` | Interactive REPL |
| `./disturb --help` | Show CLI help |

Notes:
- Disturb now uses a single unified runtime backend; legacy `--urb`/`--dist` backend selection flags were removed.

## Core Model

| Concept | Behavior |
| --- | --- |
| Global root | `a = b;` is the same as `global.a = b;` |
| Table type | `table` (formerly `any`) is the generic container |
| Null | Missing globals/keys return `null` |
| Natives | Built-in and stored in `global` as tables |
| Common | Shared methods live on `global.common` |
| this | Method calls bind `this` to the call target |

## Semantics and Oddities

- Everything is an object backed by a list; even scalars are just length-1 lists.
- Indexing a single-element list (`a[0]`) yields the same value as `a`, but not the same object identity.
- `=` is reference assignment: collections store references, not copies.
- Use `.clone()` for a shallow copy or `.copy()` for a deep copy when you want a snapshot.
- Strings are int lists with a `.string` view; in strict mode you must use `.string` to print as text.
- Missing keys/indexes resolve to `null` instead of throwing.

## Types and Literals

| Type | Literal | Notes |
| --- | --- | --- |
| int | `1` | Integer list values |
| float | `3.14` | Float list values |
| char | `'c'` | Single-byte string |
| string | `"abc"` | String with length > 1 |
| table | `{a = 1}` | Keyed container |

## Construction

| Form | Result |
| --- | --- |
| `[1, 2]` | Int list |
| `[1, 2.5]` | Float list |
| `{a = b}` | Table with keys |

Notes:
- `[]` builds an int list; if any element is float, the list is float. Use `.toInt()`/`.toFloat()` for explicit conversion.
- Lists are homogeneous: an int list never mixes floats. If any element is fractional, the entire list becomes float and ints are converted.
- Strings are int lists of bytes; `'c'` is a length-1 string and `"abc"` is length > 1. Use `.string` (type view) to treat an int list as text.
- Table literals now use `{...}` exclusively; the `table` prefix is no longer supported.
- Plain `{}` is reserved for tables, while `(args){...}` still introduces a lambda.
- Compound assignments (`+=`, `-=`, `*=`, `/=`, `%=`) and increment/decrement statements (`++i`, `i++`, `--i`, `i--`) mutate the left-hand target in place; increments add/subtract `1`.
- Compound assignments (`+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `|=`, `^=`, `<<=`, `>>=`) and increment/decrement statements (`++i`, `i++`, `--i`, `i--`) mutate the left-hand target in place; increments add/subtract `1`.
- Numeric suffixes: `1i` (int), `1u` (unsigned int, treated as int), `1f` (float).

## Expressions and Operators

Operators follow standard precedence with parentheses support:
- Unary: `!`, unary `-`
- Multiplicative: `*`, `/`, `%`
- Additive: `+`, `-`
- Shift: `<<`, `>>`
- Comparisons: `<`, `<=`, `>`, `>=`
- Equality: `==`, `!=`
- Bitwise: `&`, `^`, `|`, unary `~`
- Logical: `&&`, `||`

Notes:
- Logical and comparison operators return ints (`1` or `0`).
- `null` and numeric `0` (int/float) are false; everything else is true.
- `+` concatenates when either side is a string/char; non-strings stringify to Disturb literals.
- `a ?= b` assigns `b` only when `a` is `null`.
- Assignment and `++`/`--` forms are expressions and return a value (prefix returns the updated value, postfix returns the previous value).
- String indexing assignments accept either single-byte strings or numeric values `0-255`.
- List indexing on int/float lists returns numeric scalars; string indexing returns a single-byte string.

## Strict Mode

Enable strict numeric rules with directives:
```
use strict;
use nostrict;
```

In strict mode:
- Mixed int/float arithmetic and comparisons are errors.
- Numeric list literals cannot mix ints and floats.
- Numeric suffixes (`1i`, `1u`, `1f`) are honored for literal type selection.
- Number/string comparisons are errors.
- Using `null` in numeric ops is an error.
- `print`/`println` only render text for `.string`; raw string literals print as int lists.

Notes:
- `use strict;` and `use nostrict;` (also `use "strict";` / `use "nostrict";`) can appear anywhere; effects start from that point onward.
- Directives affect both layers:
  - parser strictness (compile-time checks for following code)
  - runtime strictness (emits bytecode that toggles VM strict mode)
- Runtime strict can also be toggled dynamically with `gc.strict = 0/1;` and follows last-write-wins behavior.

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
- `switch (expr) { case literal: ... }` performs equality checks (strings/ints/floats) and exits after the first matching case; `default` runs if no case matches (no fall-through, so `break` is unnecessary).
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
- Indexing strings yields a single-byte string.
- Indexing supports infinite nesting.
- `inf` is a global float constant (positive infinity).

## Meta Properties

Every entry exposes meta properties via string keys:

| Property | Type | Description |
| --- | --- | --- |
| `.name` | string | Key name in its parent (`global.a.name == "a"`) |
| `.type` | string | `null`, `int`, `float`, `char`, `string`, `table`, `native`, `lambda`, `view` |
| `.value` | any | Copy of the entry value (keyless) |
| `.size` | int | Used slots (elements for int/float lists, bytes for strings) |
| `.capacity` | int | Allocated slots (elements for int/float lists, bytes for strings) |

Notes:
- `.name` and `.type` are writable. `.name = null` clears the key. `.type` is pure type punning (no conversion).
- Setting `.size` changes used slots; if larger than capacity it reallocates.
- Setting `.capacity` reallocates; the table remains in the same entry slot.
- Setting `.value` replaces the entry contents without changing its key or identity.

## Bytecode

The bytecode is RPN stack-based. There is no const pool; literals are inline.

| Opcode | Stack effect | Purpose |
| --- | --- | --- |
| `PUSH_INT` | `-- int` | Push int literal |
| `PUSH_FLOAT` | `-- float` | Push float literal |
| `PUSH_CHAR` | `-- char` | Push char literal |
| `PUSH_STRING` | `-- string` | Push string literal |
| `PUSH_CHAR_RAW` | `-- char` | Push char literal (no papagaio) |
| `PUSH_STRING_RAW` | `-- string` | Push string literal (no papagaio) |
| `BUILD_INT n` | `v… -- list` | Build int list |
| `BUILD_FLOAT n` | `v… -- list` | Build float list |
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
| `STRICT` | `--` | Enable runtime strict mode |
| `UNSTRICT` | `--` | Disable runtime strict mode |
| `DUMP` | `--` | Dump global |
| `ADD` | `a b -- out` | Add/concat |
| `SUB` | `a b -- out` | Subtract |
| `MUL` | `a b -- out` | Multiply |
| `DIV` | `a b -- out` | Divide |
| `MOD` | `a b -- out` | Modulo |
| `BITAND` | `a b -- out` | Bitwise and (int) |
| `BITOR` | `a b -- out` | Bitwise or (int) |
| `BITXOR` | `a b -- out` | Bitwise xor (int) |
| `SHL` | `a b -- out` | Shift left (int) |
| `SHR` | `a b -- out` | Shift right (int) |
| `NEG` | `a -- out` | Unary minus |
| `BNOT` | `a -- out` | Bitwise not (int) |
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
 - Lambda bodies now use local scope; assign to `global.name` to update globals explicitly. The local scope is available as `local` inside lambdas.
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

Examples:
```disturb
a = {x = 1, y = {z = 2}};
b = a;
c = a.clone();
d = a.copy();

b.x = 9;
b.y.z = 8;

println(a.x);   // 9
println(c.x);   // 9 (shallow copy shares children)
println(d.x);   // 1 (deep copy)
```

Formatting:
- `pretty`

IO(might not be available in all environments):
- `read`, `write`

Metaprogramming:
- `parse`, `emit`, `evalBytecode`, `eval`

GC:
- `gc`, `global.gc`

Notes:
- `read(path)` returns a string with file contents.
- `write(path, data)` writes a stringified value and returns `1` on success.
- `eval(code)` executes code in the current VM and returns `null`.
- `parse(source)` compiles source into bytecode bytes.
- `emit(bytecode)` returns a disassembly-style text view of bytecode bytes.
- `evalBytecode(bytes)` executes bytecode and returns `null`.

A pure Disturb assembler/disassembler is available in `example/asm_lib.disturb`:

```disturb
eval(read("example/asm_lib.disturb"));
bytes = asm("PUSH_INT 1\nPUSH_INT 2\nADD\n");
println(disasm(bytes));
```

## Bytecode Text

`emit(bytecode)` returns a disassembly-style text format. `example/asm_lib.disturb` can assemble that text back into bytecode bytes.

The internal bytecode AST is no longer a public API.
- `gc()` runs a collection.
- `global.gc.rate = N` sets auto-GC frequency (`0` disables periodic GC checks).
- `global.gc.strict = 0/1` toggles runtime strict checks immediately.
- `global.gc.keyintern = 0/1` toggles key interning for newly created keys (existing interned keys are kept).
- `global.gc.collect()` runs a manual reachability collection and marks unreachable values for reuse.
- `global.gc.free(value)` frees the value and replaces it with `null` (manual management).
- `global.gc.sweep(value)` marks the value for reuse immediately and replaces it with `null`.
- `global.gc.flush()` frees all values currently waiting for reuse.
- `global.gc.new(size)` allocates a table with reserved capacity.
- `global.gc.debug()` prints the reuse pools (sizes and totals).
- `global.gc.stats()` prints memory usage by reuse/inuse/noref blocks.
- Comments are supported via `//` and `/* ... */`.

Papagaio processing is applied to string literals that contain `$` (including escaped `\$`, which the parser stores as a papagaio-escape sigil). Literals without `$` compile to raw string opcodes and skip papagaio. Use `\$` to escape a literal `$`.

`replace` and `replaceAll` perform literal substring replacement (first match vs all matches). For Papagaio patterns on runtime strings, use `papagaio(text)` with `$pattern{...}{...}` directives embedded in the text:
- `papagaio("$pattern{hello $name}{Oi $name}hello Joao")`
- `papagaio("\$pattern{a}{b}a")`

Papagaio tokens:
- `$pattern{...}{...}` defines a pattern+replacement pair (nested patterns are supported).
- `$regex name {pattern}` captures regex matches (use `$regex{0}`/`{1}`... in replacements).
- `$eval{...}` evaluates Disturb code; use `return` to produce a value.
- `this` inside `$eval{}` points to `global.papagaio`, which exposes `content` and `match`.

`print`/`println` with no arguments prints the top of the stack if present.

## FFI

FFI is optional (see build flags below). Load a shared library and bind C-style signatures:

```disturb
lib = ffi.load("libmylib.so",
  "i32 add(i32, i32)",
  "char* getenv(char*)",
  "i32[] make()"
);

println(lib.add(1, 2));
println(lib.getenv("HOME"));
println(lib.make!64()); // override return length for int[]/float[]
```

Signature notes:
- `int[]`/`float[]` inputs pass a pointer to the list data (length is not passed).
- `int[]`/`float[]` return defaults to length `0`; use `name!N()` to override.
- `int[N]` return defaults to `N`, and can be overridden by `name!N()`.
- `char*`/`unsigned char*` map to Disturb strings (copied on return).
- `void*` maps to a Disturb int (uintptr).

## Build Flags

Optional features can be disabled at build time:

```bash
make ENABLE_IO=0        # disable read/write
make ENABLE_SYSTEM=0    # disable system()
make ENABLE_FFI=0       # disable ffi.load
```

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
- `example/guide/10_strict_mode.disturb`
- `example/guide/11_ffi_system.disturb`
- `example/guide/12_references_and_copy.disturb`
- `example/guide/13_manual_gc.disturb`

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

# Changelog

## 1.1.1
- add GitHub Actions CI (`.github/workflows/ci.yml`) with Linux build/test jobs for default build and `ENABLE_FFI=0`.
- expand CI matrix to Linux/macOS/Windows (MSYS2/MinGW), running default (FFI) and `ENABLE_FFI=0` builds.
- add cross-platform dynamic library loading fallback in FFI (`dlopen/dlsym` on Unix, `LoadLibrary/GetProcAddress` on Windows).
- make FFI fixture/examples portable across `.so`, `.dylib`, and `.dll`.
- add by-value FFI struct signatures with `@schema` (args/returns) integrated with compiled struct layouts.
- add `tests/run_examples.sh` to execute all example scripts under `example/`.
- removed "system" native function.
- add `import(path)` module/package loader:
  - `*.urb` paths load directly;
  - non-`.urb` paths load `path/<basename(path)>.urb`;
  - module code runs isolated and exports through top-level `return`;
  - imports are cached per resolved path.
- add FFI struct view system with automatic C-like layout compiler (padding/alignment), nested schemas, and live pointer-backed field access (`ffi.compile`, `ffi.sizeof`, `ffi.alignof`, `ffi.view`, `ffi.offsetof`).
- add string-based schema types for FFI struct views (e.g. `"int32"`, `"float64"`, `"ptr"`), with support for `__meta.packed`, `__meta.align`, and `__order`.
- add string-based schema array syntax: `"int64[8]"` (fixed inline array) and `"int32[]"` (unsized/pointer-style).
- add FFI struct integration test using a dedicated shared C fixture (`tests/ffi/ffi_view_struct.c`) plus runtime test-case wiring in `tests/run.sh`.
- remove the separate URB backend and keep a single unified runtime.
- remove URB runtime/bridge sources and headers from the build (`src/urb_runtime.c`, `src/urb_bridge.c`, `include/urb_runtime.h`, `include/urb_bridge.h`).
- simplify CLI backend behavior by removing `--urb`/`--dist` selection and always running the unified VM backend.
- remove URB-specific test scripts and backend toggles from the Makefile.
- add computed-goto opcode dispatch in `vm_exec_bytecode()` under `#ifdef __GNUC__`, with switch-based fallback preserved.
- optimize VM memory/object paths with pool limits, integer caching (`0..100000`), larger initial stack table capacity, and O(1) registry allocation via free-index stack.
- add stdout full buffering at CLI entry points with flush/restore on exit.
- add phase 5 key-string interning for VM key objects, with safe fallback to non-interned key creation if intern table allocation/growth fails.
- keep interned keys alive across GC by marking intern roots during mark phase using compact root tracking (without full-capacity intern table scans).
- add runtime GC controls `gc.keyintern` (enable/disable key interning for new keys) and `gc.strict` (toggle runtime strict checks).
- add `use nostrict;` / `use "nostrict";` directive support and `BC_UNSTRICT` runtime opcode.
- keep strict mode layered: `use strict;`/`use nostrict;` change parser strictness from that point forward and also emit runtime strict toggles; `gc.strict` changes runtime only.
- add full bitwise operator support: `&`, `|`, `^`, `~`, `<<`, `>>` and compound assignments `&=`, `|=`, `^=`, `<<=`, `>>=`.
- split equality semantics: add strict identity operator `===` (`BC_SEQ`) and make `==` value/content equality with recursive, cycle-safe table comparison; keep `!=` as negation of value equality.
- add strict identity inequality operator `!==` (`BC_SNEQ`) as the negation of `===`.
- add equality coverage tests for primitives, identity vs value, nested/cyclic tables, functions, and FFI-style wrapper objects; document `==` vs `===` behavior in README.

## 0.17.1
- add CLI commands for compiling (`--compile-bytecode`) and running (`--run-bytecode`) bytecode files.

## 0.17.0
- implement full gc in urb mode.
- add runtime-configurable `gc.rate` for both Disturb and URB modes.
- add reuse pools for objects/entries and inline-small-bytes storage to reduce allocations.
- add slab allocators for lists/entries and free-node pools to reduce malloc/free churn.
- some real optimization stuff;

## 0.16.1
- Using urb 0.9.4a direcly instead the disturb's modified version of urb.

## 0.16.0
- Disturb urb runtime mostly implemented.
- Add raw string/char bytecode opcodes to skip papagaio when literals contain no `$`.
- Update metaprogramming: `parse` returns bytecode bytes, `emit` renders bytecode text; remove public bytecode AST helpers.

## 0.15.1
- Added shebang support.

## 0.15.0
- Fix lambdas parameters overwriting in recursive calls.
- Allow assignment and `++`/`--` operators inside expressions (prefix returns updated value, postfix returns previous value).
- Make GC fully manual: remove automatic collection and `gc.rate`, add `gc.free`, `gc.sweep`, `gc.new`, and `gc.flush`.
- Add `gc.stats` to report reuse/inuse/noref memory totals.
- Switch assignments to reference semantics, add `clone` (shallow) and `copy` (deep) helpers, rebind function arguments per call, add local scope for lambda bodies, and make `gc.collect`/`gc.sweep` mark values for immediate reuse.
- Add global `inf` float constant.
- Add optional FFI binding (`ffi.load`) with signature parsing and `name!N()` length overrides.
- Add build flags to disable IO (`ENABLE_IO`), system (`ENABLE_SYSTEM`), or FFI (`ENABLE_FFI`).
- Add `.value` meta to copy/assign entry contents without changing identity.
- Add `use strict;` numeric mode with `1i/1u/1f` suffixes and stricter int/float checks.
- Add pure Disturb assembler/disassembler in `example/asm_lib.urb`.

## 0.14.1
- Apply Papagaio processing to all string literals, with `\$` escape support.
- Add `$pattern{}`/`$regex{}`/`$eval{}` tokens plus nested patterns and block sequences.
- Add `papagaio(text)` helper for runtime strings and expose `global.papagaio` with `content`/`match`.
- Make `replace` a literal substring replacement and add `replaceAll`.

## 0.14.0
- Simplify literal syntax: table literals always use `{...}`; use `.toInt()`/`.toFloat()` for numeric conversions and keep `(args){}` for lambdas.
- Add compound assignment (`+=`, `-=`, `*=`, `/=`, `%=`) plus prefix/postfix `++`/`--` statement forms for in-place updates.
- Add switch/case statements (string/number selectors with `default` handling) plus label/goto support for unconditional jumps.

## 0.13.0
- user-defined functions are now called `lambda`, which is more appropriate.
- `object` type is now called `table`.
- method lookup now uses `global.common` instead of `global.prototype`.
- `string` and `char` are now unified as `byte`.

## 0.12.7
- New string methods: `find`, `rfind`, `contains`;

## 0.12.6
- Args are now supported by the cli.

## 0.12.5
- Add bytecode metaprogramming natives (`parse`, `emit`, `evalBytecode`, `bytecodeToAst`, `astToSource`).

## 0.12.4
- Add `gc()` plus `global.gc.rate` and `global.gc.collect()` for GC control.

## 0.12.3
- Add language comment support (`//` and `/* ... */`).
- Add annotated guide examples under `example/guide`.

## 0.12.2
- Treat byte values like strings for printing and string operations.
- Add `read`, `write`, and `eval` natives (text/binary unified).

## 0.12.1
- Add interactive REPL (`--repl`, default when no args).

## 0.12.0
- Allow function calls inside expressions.
- Add `return`, `break`, and `continue`.
- Add optional parameters and default values for lambdas.
- Add `?=` default assignment operator.

## 0.11.0
- Add control flow statements: `if/else`, `while`, `for`, and `each`.
- Add `pretty` formatting for human-readable object output.
- Allow `{}` table literals without explicit `(table)` cast.
- Treat numeric `0` as false in truthiness checks.

## 0.10.0
- Add arithmetic, comparison, and logical operators with precedence and unary support.
- Add string concatenation via `+` with Disturb-style stringification.
- Add common methods for math, string, and table/array helpers.
- Add `this` binding for method calls and `global.common`.
- Extend bytecode to support `LOAD_THIS`, `SET_THIS`, and operator opcodes.
- Add lambdas with varargs and table-call semantics.

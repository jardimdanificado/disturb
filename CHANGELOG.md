# Changelog

## 1.6.0
- add numeric list shorthand syntax without brackets: `a = 1 2 3,`.
- remove bracket list literals (`[1, 2, 3]`) from the language; use only space-separated numeric lists.
- remove semicolon (`;`) compatibility alias for statement separation; only comma (`,`) is accepted.
- remove strict mode support entirely: `use strict`/`use nostrict`, `gc.strict`, and STRICT/UNSTRICT bytecode op handling are removed.
- remove legacy compatibility aliases in FFI typing: function pointers now accept only `function(...)` (no `fn(...)` alias), and `char*` no longer auto-maps to `cstring`.
- remove `gc()` alias; use `gc.collect()`.
- object literals now accept anonymous members and mixed forms (examples: `{1, 2, 3}`, `{a = 2, 4, d = 9}`, `{b, 4, 12}`).
- numeric operators now work element-wise on numeric lists (arithmetic, bitwise, unary, and comparisons).
- add `memory.point(value)` helper to expose numeric pointers for list/view data and pointer-like FFI values (`null` -> `0`).

## 1.5.0
- language overhaul: statements separated by commas instead of terminating semicolons (`a = 1, b = 2`).  Semicolons are still lexed (mapped to commas) for compatibility but no longer required or emitted.
- final comma in a statement sequence is optional (parser ignores trailing comma before `}` or EOF).
- object literals support optional trailing comma (`{a=1, b=2,}` and `{a=1, b=2}` both valid).
- allow dropping parentheses around control flow keywords: `if cond { … }`, `while cond { … }`, `for init, cond, step { … }`, `each x in expr { … }`, and `switch expr { … }` all work without parentheses, while parenthesized forms remain valid for explicitness.
- parser and bytecode emitter updated accordingly; handled in `parse_simple_statement`, for-loops, control-flow parsing, and expression handling.
- extensive update of examples/tests/documentation to use comma syntax; new negative test `missing_comma.urb` added.
- update `tests/run.sh` messages and CI-friendly ports for new syntax.
- documentation (README, REF_SHEET) revised with comma rules and optional parentheses examples.

## 1.4.1
- unify FFI signature syntax: replace `pointer<schema>`, `union<schema>`, `function<signature>`, and `fn<...>` with parentheses-based syntax `pointer(schema)`, `union(schema)`, `function(signature)`, and `fn(...)`.
- update all signatures in tests, examples, and documentation to use new parentheses-based syntax consistently.

## 1.4.0
- replace FFI by-value struct syntax `struct<schema>` with `struct(schema)` in signatures and schema composition strings.
- add distinct string-pointer semantics in signatures:
  - `string`: marshals as Disturb string values
  - `cstring`: raw C pointer behavior
- unify build profile flags into `DISABLE_IO`:
  - `DISABLE_IO=0` (default): IO natives + dynamic FFI calls enabled
  - `DISABLE_IO=1`: embedded profile (`DISTURB_EMBEDDED`), IO off, dynamic FFI calls off
- make core FFI always enabled in build systems (no `ENABLE_FFI` toggle).

## 1.3.0
- add automatic papagaio source preprocessing at compile-time for declarations outside strings/comments (`$pattern{...}{...}`, `$regex ... {...}`, `$eval{...}`).
- keep papagaio behavior inside string literals as runtime processing, preserving existing `papagaio(text)` and string-literal flows.
- add mixed coverage and examples for compile-time + runtime papagaio usage in the same file (`tests/cases/papagaio_preprocessor.urb`, `example/papagaio_preprocess_mixed.urb`).
- remove `ffi.load` from the public/runtime FFI API and from native alias resolution (`ffiLoad`), keeping dynamic calls on the explicit two-step flow.
- standardize dynamic loading on `ffi.open(path)` + `ffi.sym(lib, name)` + `ffi.bind(ptr, sig)` + `ffi.close(lib)`.
- fix `ffi.sym` symbol-name handling for derived strings (e.g. `split`/`trim` results) by passing a null-terminated copy to the platform loader.
- migrate all FFI-facing scripts from `ffi.load(...)` to the new flow:
  - libraries: `lib/raylib.urb`, `lib/tcc.urb`
  - tests: `tests/cases/ffi_*` loaders
  - examples and guide examples: `example/ffi*.urb`, `example/guide/11_ffi_system.urb`, `example/guide/14_ffi_struct_views_bind.urb`, `example/guide/15_ffi_callbacks_varargs_buffers.urb`, `example/guide/16_ffi_unions.urb`
- update FFI documentation to remove `ffi.load` references and describe the new call flow in `README.md`, `docs/FUNCTION_REFERENCE.md`, and `docs/REF_SHEET.md`.
- update build option descriptions to reflect new dynamic-call API wording (`ffi.open`/`ffi.sym`/`ffi.bind`) in `CMakeLists.txt`.

## 1.2.1
- add function pointer fields in schemas via `function(signature)` (example: `cb = "function(i32 cb(i32, i32))"`; `fn(...)` kept as alias), including read-as-bound-callable in `memory.view` and assignment from C pointers or `ffi.callback(...)`.
- make schema compilation automatic in FFI call sites that accept schema/layout (`memory.view`, `memory.new`, `memory.sizeof`, `memory.alignof`, `memory.offsetof`); `memory.compile` remains available as optional explicit step.
- add dedicated FFI function-pointer-field test coverage: `ffi_fnptr_fields`.
- add dedicated FFI auto-compile coverage: `ffi_auto_compile`.
- skip `ffi_union` case on MinGW/MSYS CI targets due platform-specific by-value union ABI differences in libffi; keep coverage on Unix targets.
- enable `ENABLE_FFI_CALLS=ON` for MSVC CI/release builds using `libffi` from `vcpkg` (`x64-windows`), restoring `ffi.load`/`ffi.bind` availability on Windows MSVC artifacts.
- switch MSVC CI/release `vcpkg` triplet to `x64-windows` and align MSVC runtime selection (`/MD`/`/MDd`) to avoid CRT mismatch warnings (`LNK4098`).
- fix MSVC CI probe step to execute the Disturb binary correctly when checking `ffi.load`/`ffi.bind`.
- include `docs/` and `example/` directories in all release artifacts.
- add function-pointer-field example: `example/ffi_fnptr_fields.urb`.
- add optional compile example: `example/ffi_auto_compile_optional.urb`.
- update docs to make `memory.compile` optional in common flows and document `function(...)` (`fn(...)` alias accepted).

## 1.2.0
- change lambda vararg syntax from `name...` to `...name`; old trailing form now errors with guidance (`invalid vararg syntax: use '...name'`).
- fix lambda callback resolution in calls: when calling `a()` inside a lambda, call target lookup now checks local scope before global scope, so callback args work without `local.a()`.
- add `memory.new(schemaOrLayout)` to allocate zeroed struct memory and return a numeric pointer for use with `memory.view(...)`.
- add `memory.free(ptr)` to release memory allocated with `memory.new`.
- change FFI struct signature syntax to `struct(schema)` (by-value) and `pointer(schema)` (typed pointer); remove legacy `@schema`.
- keep `void*` for raw/generic pointers in signatures.
- require schema field declarations to be type strings; nested inline schema tables in field values are rejected.
- add schema unions (`__meta = { union = 1 }`) and bitfields (`"type:bits"`).
- add `memory.viewArray(ptr, elemSpec, len)` for array views over raw/typed pointers.
- make pointer-submember access in views return nested views when field type is `pointer(schema)`.
- make `memory.new` allocations owned by GC (via pointer handles), with optional manual release via `memory.free`.
- add `ENABLE_EMBEDDED=1` build profile to disable features not suitable for Arduino-like targets (IO natives, dynamic FFI calls `ffi.load`/`ffi.bind`, and `import`) while keeping FFI core APIs.
- add CMake build support and a Windows MSVC CI job (`windows-msvc`) validating build/tests with `ENABLE_FFI_CALLS=OFF`.
- update manual release workflow to publish explicit Windows artifacts for both toolchains: `disturb-vX.Y.Z-windows-x64-mingw.zip` and `disturb-vX.Y.Z-windows-x64-msvc.zip`.
- add/adjust tests for new vararg syntax, lambda callback behavior, new FFI signature forms, and `memory.new`/`memory.free` flow in FFI struct tests.
- add FFI qualifiers support for signatures/schema type strings: `const`, `volatile`, `restrict` (with `const` write-protection on views).
- enforce `const` writes in FFI views/array-views: strict mode now aborts, non-strict prints warning and ignores the write.
- add FFI variadic call support (`...`) in `ffi.bind`/`ffi.load` signatures with runtime vararg type inference.
- add `ffi.callback(signature, lambda)` to expose lambda callbacks as C function pointers via libffi closures.
- add `memory.buffer(len)` and `memory.string(ptr[,len])` helpers for pointer/string/buffer ergonomics.
- add dedicated FFI regression coverage: `ffi_varargs`, `ffi_callbacks`, `ffi_buffers_strings`, `ffi_const_views`, and strict-mode negative test `ffi_const_write_strict`.
- add new examples for advanced FFI flows: `example/ffi_callbacks_varargs_buffers.urb` and `example/guide/15_ffi_callbacks_varargs_buffers.urb`.
- update docs/examples to reflect vararg, FFI signature, and memory APIs.

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
- add FFI struct view system with automatic C-like layout compiler (padding/alignment), nested schemas, and live pointer-backed field access (`memory.compile`, `memory.sizeof`, `memory.alignof`, `memory.view`, `memory.offsetof`).
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
- language overhaul: statements now terminate with commas instead of semicolons (`a = 1, b = 2,`).  Semicolons are still lexed (mapped to commas) for compatibility but no longer required or emitted.  The final comma in a statement sequence is optional (blocks/EOF ignore it).  Added support for optional trailing comma in object literals (`{a = 1, b = 2,}`).
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

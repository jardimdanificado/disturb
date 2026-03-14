# Changelog

## TODO
### later
- optimize the switch case stuff to not be just a ifelse alias, really small gain but not so much work really

### future
- optimize all vector stuff with SIMD, papagaio was written from ground with the exact idea of a fully SIMD-optimized language, is not only useful but really ESSENTIAL for a serious/non-experimental version...

### far-future
- paralelism, almost essential for papagaio later versions, but not really useful right now...
- gpu computing, perfect for papagaio but i know nothing about gpu computing yet...

### uncertain
- write a wrapper for wasm to be easily used from browser... REALLY useful but i dont want to use papagaio on the browser again any soon...
- arduino version with small overhead and small ram footprint... i am pretty sure i will NEVER write this for papagaio, but there was early plans for doing so... prefer the pure urb.h interpreter for arduinos.

## 2.0.1
- COMPLETE REBRAND, disturb is now called papagaio.md... "so it's everything papagaio now? no, its always been.."
- add host I/O abstraction (`host_io.h` + `src/host_io.c`) to support WASM builds and external host file APIs.
- add optional `DISABLE_FFI_CALLS` build flag to disable dynamic FFI calls (`libffi`/`dlopen`) while keeping IO/import enabled.
- add WASM runtime wrapper (`src/papagaio_wasm.c`) exposing `papagaio_wasm_init()`, `papagaio_wasm_eval()`, and `papagaio_wasm_free()`.
- papagaio is now available on browser, check examples/web/... as web is not our focus for now there is no wrapper or such just the `make wasm' which just compile a wasm.

## 1.10.1
- refactor duplicate Markdown extraction logic across the codebase into a centralized native `papagaio_md_extract` routine in the VM.
- add native `mdGenerate()` helper to serialize `global.md` tables back into Markdown text (new regression test: `tests/cases/mdgen_test.urb`).
- modify `import()` and `mdisturb` to automatically parse extended Markdown syntax (`# headings`, `- lists`, `| tables |`), mapping them to AST objects natively dynamically allocated in `global.md.<heading>`.
- add papagaio pattern variable modifiers via `$name$modifier` syntax: type-constrained captures `$int`, `$float`, `$number`, `$hex`, `$binary`, `$percent`; text-constrained captures `$upper`, `$lower`, `$capitalized`, `$word`, `$identifier`, `$path`.
- add parameterized papagaio modifiers: `$name$aliases{a, b, c}` (match one alternative and capture), `$name$optional{text}` (optionally match literal and capture), `$name$starts{prefix}` (match content starting with prefix), `$name$ends{suffix}` (match content ending with suffix).
- replace `$options{a, b, c}` with `$name$aliases{a, b, c}` and `$optional{text}` with `$name$optional{text}`; all parameterized modifiers now bind to a named variable for capture.

## 1.9.3
- whitespace tokens (`TOK_WS`) adjacent to optional tokens no longer fail the match when the optional term is absent.
- fix pattern matching for `$var <literal> $var` forms: the variable scanner now correctly resets the position to the end of the trimmed capture (before trailing whitespace) so the following whitespace token can consume it.
- `TOK_OPTIONS` is now recognised as a valid stopper for the preceding variable scan, mirroring the existing treatment of `TOK_LITERAL`.
- expand `import(path)` to support Markdown modules: direct `.md` imports now extract fenced code blocks before evaluation; package imports keep `.urb` as primary entry and fall back to `.md` when `<pkg>/<pkg>.urb` is missing.

## 1.9.2
- add scalar-vector math helpers in `global.common`: `sadd`, `ssub`, `smul`, `sdiv`, `smod`, `spow`.
- scalar-vector helpers support both call styles: function form (`sadd(vec, n)`) and method form (`vec.sadd(n)`).
- expand math vector regression coverage with scalar-vector operation cases and expected outputs; document new helpers in README math section.
- add `mdisturb.urb`: Disturb-native Markdown tool to extract (`.md` -> `.urb`), print, and run fenced code blocks as Disturb source.

## 1.9.1
- `argc` CLI global is now exposed as an integer scalar instead of a string.
- `C.info()` no longer exposes the deprecated `tcc` field.
- add low-level `C.ffi` loader helpers: `symSelf()`, `errno()`, `dlerror()`, and portable `RTLD_*` constants for `open(path[, flags])`.

## 1.9.0
- int/float arrays are raw byte buffers; `"string"` is a view over those bytes, not a separate type.
- `arr.string` produces a string view over the int array's bytes: `println(arr.string)` prints as NUL-terminated text, `arr.string[i]` returns the char at byte `i` as a 1-byte string.
- `.size` and `.capacity` on typed views (`arr.string`, `arr.u8`, `arr.u16`, `arr.u32`, `arr.u64`, `arr.f32`, `arr.f64`) now return the element count for that view's element width: `arr.u8.size = total_bytes / 1`, `arr.u16.size = total_bytes / 2`, etc.
- `arr.string.size` uses `strlen` semantics (stops at first `\0`); `arr.string.capacity` is raw allocated bytes.
- `arr.size` (plain int array, no view) returns `total_bytes / sizeof(Int)` as before.
- fix `vm_meta_size_entry`: VIEW type now returns `disturb_bytes_len(base) / stride`; string type now uses `strlen` instead of raw byte count.
- fix `vm_meta_capacity_entry`: VIEW type now returns `base_capacity_bytes / stride`.

## 1.8.1
- the `:` after `case <expr>` and `default` in switch statements is no longer part of the syntax; `case 1 { ... }` is the required form.

## 1.8.0
- overhaul boolean/truthiness system: a value is now false when its type is null, it is an empty string, or it is a numeric array (int/float) where zero elements are a majority or tied with non-zero elements; true in all other cases (tables, lambdas, views, non-empty strings, numeric arrays where non-zeros strictly outnumber zeros).
- scalar compatibility preserved: single `0` remains false, any non-zero scalar remains true.
- vectorize `!` (`BC_NOT`): on multi-element numeric arrays produces an element-wise int array (0→1, non-zero→0); scalar fallback uses updated truthiness rule.
- vectorize `&&` and `||` (`BC_AND`/`BC_OR`): on multi-element numeric arrays produce element-wise int results; scalar fallback uses updated truthiness rule.
- all conditional paths (`BC_JMP_IF_FALSE`, `?=`) inherit the new vectorized truthiness semantics automatically.
- update `examples/guide/04_operators_truthiness.urb` to document and demonstrate the new semantics.
- add postfix `expr?` operator (`BC_TRUTH`): returns a float in `[0.0, 1.0]` representing the ratio of non-zero elements — `nonzeros / total`; `null` yields `0.0`, empty string yields `0.0`, non-empty string is measured byte-by-byte, tables/lambdas/views always yield `1.0`.
- scientific notation (`1e3`, `2.5e-4`, `6.022e23`) is supported natively via `strtod`; values that fit an integer are stored as int, others as float.
- `?` alone is now a valid token (`TOK_QMARK`); previously it was silently treated as `TOK_EOF`.
- vectorize all unary math functions (`abs`, `floor`, `ceil`, `round`, `sqrt`, `sin`, `cos`, `tan`, `asin`, `acos`, `atan`, `log`, `exp`): when called on a multi-element int or float array, applies the function element-wise and returns a float array; scalar inputs behave as before.
- vectorize `pow`: supports all four combinations of scalar/array for base and exponent; semantics mirror binary arithmetic operators — `min(len_base, len_exp)` pairs receive `pow()`, extra elements from the longer side are copied unchanged; result is always a float array when any operand is multi-element.
- `slice` now supports tables (returns a new table with elements from `[start, end)`), int arrays, and float arrays (returns a new array of the same type); existing string behaviour is unchanged; both method-call and function-call argument conventions are handled correctly.
- `append` now supports int and float number arrays: concatenates the raw elements; when element types differ (int src or dst vs float src or dst), elements are promoted to float automatically; also supports tables: all elements of the source table are shallow-cloned and appended to the destination table in order.
- `push` (and the int-array path in related mutation functions) now auto-converts float values to int via truncation when the target is an int array, instead of rejecting non-exact float-to-int conversions; float arrays continue to accept int values by widening.
- `pow`, `slice`, and `append` correctly handle the function-call form (`pow(a, b)`, `slice(a, start, end)`, `append(dst, src)`), in addition to the method-call form, by guarding against a stale `this_entry` pointing to the native function itself.
- add `tests/cases/math_vectors.urb` and `examples/math_vectors.urb` covering vectorized math, `pow`, `slice`, and `append` in both method-call and function-call forms.

## 1.7.4
- restructure codebase: remove `libs/` directory (move `urb.h` to `include/`, move `tcc.urb` to `examples/libs/`).
- remove `libregexp` vendored dependency (regex support via `$regex` removed from papagaio).
- consolidate `docs/` directory documentation into main `README.md`.
- simplify build files: remove `libregexp` compilation from Makefile and CMakeLists.txt.
- new target: make test.
- unify build toggles into a single `DISABLE_SYSTEM` flag (default `0` = full build).
- `DISABLE_SYSTEM=1` disables system-dependent features (IO natives, `import`, dynamic FFI calls), while keeping FFI core (`C`, `C.memory`, `C.typedef`, `C.struct`) available.

## 1.7.3
- remove native TCC APIs: `C.ffi.cdef`, `C.ffi.compile`, `C.ffi.header`, `C.ffi.eval`.
- enhanced `examples/libs/tcc.urb`.
- remove `ENABLE_TCC` build flag (Makefile, CMakeLists.txt) and `info.tcc` from `C.info()` runtime.
- remove deprecated test cases `ffi_tcc_unavailable.urb`, `ffi_tcc_compile_eval.urb`.

## 1.7.2
- vectorized binary operations now use `max(left, right)` length instead of `min`: extra elements from the longer side are preserved in the result.
- for arithmetic (`+`, `-`, `*`, `/`, `%`) and bitwise (`&`, `|`, `^`, `<<`, `>>`), extra elements (where the shorter side has no pair) are copied as-is into the output without applying the operation.

## 1.7.1
- rename `print` to `describe`: the old `print(value)` that showed type-annotated output (e.g. `[int x] [42]`) is now called `describe`.
- add new `print`: outputs plain values without a trailing newline (same as the old `println` minus the newline).
- `println` remains unchanged (plain output followed by a newline).
- fix `describe`, `print`, and `println` not working as methods; calling `x.describe()`, `x.print()`, or `x.println()` now correctly operates on the receiver.

## 1.7.0
- unify C runtime/FFI surface under global `C`:
  - runtime-only helpers moved to `C.typedef`, `C.enum`, `C.define`, `C.struct`
  - dynamic integrations under `C.ffi.*`
  - layout/memory APIs under `C.memory.*`
  - platform/runtime capabilities via `C.info()`
- fix constant registry path for `define` to `C.defines` (instead of legacy `ffi.defines`).
- add build toggles for C integration:
  - `ENABLE_FFI` (master switch for `C.ffi`/`C.memory` modules)
  - `ENABLE_TCC` (optional libtcc integration)
  - `DISABLE_IO=1` now forces embedded profile (`ENABLE_FFI=0`, `ENABLE_TCC=0`).
- add optional TCC-backed APIs in `C.ffi` with graceful fallback when unavailable:
  - `C.ffi.cdef`, `C.ffi.compile`, `C.ffi.header`, `C.ffi.eval`.
- expand `C.memory` capabilities:
  - typed read/write (`C.memory.read`, `C.memory.write`)
  - raw operations (`C.memory.copy`, `C.memory.move`, `C.memory.zero`)
  - pointer operations (`C.memory.offset`, `C.memory.cast`, `C.memory.deref`)
  - pointer validation (`C.memory.valid`)
  - `C.memory.view(ptr, schema, totalSize)` for flexible array scenarios
  - view metadata (`.byteSize`; array views also expose `.len`).
- improve FFI type and ABI support:
  - `long_double`, `_Bool` semantic normalization, `__int128`/`__uint128`, `complex_float`, `complex_double`
  - explicit packed/forced-align by-value ABI limitation error guidance
  - `struct(Name)[N]` signature array decay support
  - callback guard for non-main-thread invocation.
- add/expand safety/debug features:
  - broader null-pointer guards in memory/view paths
  - `C.ffi.trace` control and tracing consistency
  - clearer callback variadic limitation messages.
- extend FFI test coverage and harness:
  - new/updated cases for namespace migration, ergonomics, safety, media/low-priority items, and TCC availability/fallback
  - new fixtures: `tests/ffi/ffi_media.c`, `tests/ffi/ffi_baixa.c`
  - `tests/run.sh` updated probes/build steps for `C.*` and new cases.
- refresh docs to reflect the new `C` namespace contract and current build/runtime capabilities.

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
- add mixed coverage and examples for compile-time + runtime papagaio usage in the same file (`tests/cases/papagaio_preprocessor.urb`, `examples/papagaio_preprocess_mixed.urb`).
- remove `ffi.load` from the public/runtime FFI API and from native alias resolution (`ffiLoad`), keeping dynamic calls on the explicit two-step flow.
- standardize dynamic loading on `ffi.open(path)` + `ffi.sym(lib, name)` + `ffi.bind(ptr, sig)` + `ffi.close(lib)`.
- fix `ffi.sym` symbol-name handling for derived strings (e.g. `split`/`trim` results) by passing a null-terminated copy to the platform loader.
- migrate all FFI-facing scripts from `ffi.load(...)` to the new flow:
  - libraries: raylib integration module, `examples/libs/tcc.urb`
  - tests: `tests/cases/ffi_*` loaders
  - examples and guide examples: `examples/ffi*.urb`, `examples/guide/11_ffi_system.urb`, `examples/guide/14_ffi_struct_views_bind.urb`, `examples/guide/15_ffi_callbacks_varargs_buffers.urb`, `examples/guide/16_ffi_unions.urb`
- update FFI documentation to remove `ffi.load` references and describe the new call flow in `README.md`.
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
- include `examples/` directory in all release artifacts.
- add function-pointer-field example: `examples/ffi_fnptr_fields.urb`.
- add optional compile example: `examples/ffi_auto_compile_optional.urb`.
- update documentation to make `memory.compile` optional in common flows and document `function(...)` (`fn(...)` alias accepted).

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
- add new examples for advanced FFI flows: `examples/ffi_callbacks_varargs_buffers.urb` and `examples/guide/15_ffi_callbacks_varargs_buffers.urb`.
- update docs/examples to reflect vararg, FFI signature, and memory APIs.

## 1.1.1
- add GitHub Actions CI (`.github/workflows/ci.yml`) with Linux build/test jobs for default build and `ENABLE_FFI=0`.
- expand CI matrix to Linux/macOS/Windows (MSYS2/MinGW), running default (FFI) and `ENABLE_FFI=0` builds.
- add cross-platform dynamic library loading fallback in FFI (`dlopen/dlsym` on Unix, `LoadLibrary/GetProcAddress` on Windows).
- make FFI fixture/examples portable across `.so`, `.dylib`, and `.dll`.
- add by-value FFI struct signatures with `@schema` (args/returns) integrated with compiled struct layouts.
- add `tests/run_examples.sh` to execute all example scripts under `examples/`.
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
- Add pure Disturb assembler/disassembler in `examples/asm_lib.urb`.

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
- Add annotated guide examples under `examples/guide`.

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

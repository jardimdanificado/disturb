# Changelog

## 0.14.2
- Fix lambdas parameters overwriting in recursive calls.
- Allow assignment and `++`/`--` operators inside expressions (prefix returns updated value, postfix returns previous value).
- Make GC fully manual: remove automatic collection and `gc.rate`, add `gc.free`, `gc.sweep`, and `gc.new`.
- Switch assignments to reference semantics, add `clone` (shallow) and `copy` (deep) helpers, and rebind function arguments per call to preserve recursion while keeping references.

## 0.14.1
- Apply Papagaio processing to all string literals, with `\$` escape support.
- Add `$pattern{}`/`$regex{}`/`$eval{}` tokens plus nested patterns and block sequences.
- Add `papagaio(text)` helper for runtime strings and expose `global.papagaio` with `content`/`match`.
- Make `replace` a literal substring replacement and add `replaceAll`.

## 0.14.0
- Simplify literal syntax: table literals always use `{...}` and byte strings are derived from number arrays via `[]/.toByte()` with `.toNumber()` available for coercion, preserving `(args){}` for lambdas.
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

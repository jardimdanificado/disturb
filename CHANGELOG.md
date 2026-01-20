# Changelog

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
- Add bytecode metaprogramming natives (`parse`, `emit`, `eval_bytecode`, `bytecode_to_ast`, `ast_to_source`).

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

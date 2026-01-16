# Changelog

## 0.12.1
- Add interactive REPL (`--repl`, default when no args).

## 0.12.0
- Allow function calls inside expressions.
- Add `return`, `break`, and `continue`.
- Add optional parameters and default values for user functions.
- Add `?=` default assignment operator.

## 0.11.0
- Add control flow statements: `if/else`, `while`, `for`, and `each`.
- Add `pretty` formatting for human-readable object output.
- Allow `{}` object literals without explicit `(object)` cast.
- Treat numeric `0` as false in truthiness checks.

## 0.10.0
- Add arithmetic, comparison, and logical operators with precedence and unary support.
- Add string concatenation via `+` with Disturb-style stringification.
- Add prototype methods for math, string, and object/array helpers.
- Add `this` binding for method calls and `global.prototype`.
- Extend bytecode to support `LOAD_THIS`, `SET_THIS`, and operator opcodes.
- Add user-defined functions with varargs and object-call semantics.

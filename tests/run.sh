#!/bin/sh
set -eu

BIN=${BIN:-./disturb}

if [ ! -x "$BIN" ]; then
  echo "disturb binary not found: $BIN" >&2
  exit 1
fi

run_case() {
  name=$1
  src="tests/cases/${name}.disturb"
  expected="tests/expected/${name}.out"
  actual="tests/expected/${name}.actual"

  echo "case: $name"
  "$BIN" "$src" > "$actual"
  if ! diff -u "$expected" "$actual"; then
    echo "test failed: $name" >&2
    exit 1
  fi
  rm -f "$actual"
  echo "case: $name ok"
}

run_case basic
run_case indexing
run_case bytes
run_case meta
run_case null
run_case object_keys
run_case operators
run_case natives
run_case functions
run_case control_flow
run_case resize
run_case stress_deep
run_case stress_large_list

run_negative() {
  name=$1
  src="tests/negative/${name}.disturb"
  expect="tests/negative/${name}.err"
  actual_out="tests/negative/${name}.out.actual"
  actual_err="tests/negative/${name}.err.actual"

  echo "negative: $name"
  "$BIN" "$src" > "$actual_out" 2> "$actual_err" || true
  if [ -s "$actual_out" ]; then
    echo "negative test produced stdout: $name" >&2
    cat "$actual_out" >&2
    exit 1
  fi
  if ! grep -F -q "$(cat "$expect")" "$actual_err"; then
    echo "negative test failed (stderr mismatch): $name" >&2
    echo "expected to find: $(cat "$expect")" >&2
    cat "$actual_err" >&2
    exit 1
  fi
  rm -f "$actual_out" "$actual_err"
  echo "negative: $name ok"
}

run_negative assign_invalid
run_negative char_len
run_negative key_on_non_object
run_negative oob_index
run_negative meta_readonly
run_negative meta_size_float
run_negative meta_capacity_string
run_negative byte_range

asm_out="tests/asm/out.bin"
asm_dis="tests/asm/out.asm"
echo "asm: assemble/disassemble"
"$BIN" --asm tests/asm/input.asm "$asm_out"
"$BIN" --disasm "$asm_out" "$asm_dis"
if ! diff -u tests/asm/expected.asm "$asm_dis"; then
  echo "asm test failed" >&2
  exit 1
fi
rm -f "$asm_out" "$asm_dis"
echo "asm: ok"

if command -v valgrind >/dev/null 2>&1; then
  echo "valgrind: leak check (tests/cases/basic.disturb)"
  valgrind --leak-check=full --error-exitcode=1 \
    "$BIN" tests/cases/basic.disturb >/dev/null
else
  echo "valgrind not found; skipping leak check"
fi

echo "all tests passed"

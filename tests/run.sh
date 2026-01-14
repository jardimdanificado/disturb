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

  "$BIN" "$src" > "$actual"
  if ! diff -u "$expected" "$actual"; then
    echo "test failed: $name" >&2
    exit 1
  fi
  rm -f "$actual"
}

run_case basic
run_case indexing
run_case bytes
run_case meta
run_case null
run_case object_keys
run_case resize

asm_out="tests/asm/out.bin"
asm_dis="tests/asm/out.asm"
"$BIN" --asm tests/asm/input.asm "$asm_out"
"$BIN" --disasm "$asm_out" "$asm_dis"
if ! diff -u tests/asm/expected.asm "$asm_dis"; then
  echo "asm test failed" >&2
  exit 1
fi
rm -f "$asm_out" "$asm_dis"

echo "all tests passed"

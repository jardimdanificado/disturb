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
  "$BIN" --urb "$src" > "$actual"
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
run_case switch
run_case natives
run_case functions
run_case papagaio
run_case control_flow
run_case resize
run_case stress_deep
run_case stress_large_list
run_case references
run_case locals
run_case strict
run_case value
# run_case asm

echo "negative tests skipped for URB"

if command -v valgrind >/dev/null 2>&1; then
  echo "valgrind: leak check (tests/cases/basic.disturb)"
  valgrind --leak-check=full --error-exitcode=1 \
    "$BIN" --urb tests/cases/basic.disturb >/dev/null
else
  echo "valgrind not found; skipping leak check"
fi

echo "all URB tests passed"

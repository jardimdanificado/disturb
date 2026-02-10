#!/bin/sh
set -eu

BIN=${BIN:-./disturb}

if [ ! -x "$BIN" ]; then
  echo "disturb binary not found: $BIN" >&2
  exit 1
fi

run_case() {
  name=$1
  src="tests/cases/${name}.urb"
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
run_case equality
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
run_case strict_toggle
run_case value
if [ "${EMBEDDED_MODE:-0}" = "1" ]; then
  echo "EMBEDDED_MODE=1; skipping modules case"
else
  run_case modules
fi
run_case varargs_prefix
run_case call_local_lambda
# run_case asm

run_ffi_case() {
  name=$1
  src="tests/cases/${name}.urb"
  expected="tests/expected/${name}.out"
  actual="tests/expected/${name}.actual"

  echo "ffi case: $name"
  "$BIN" "$src" > "$actual"
  if ! diff -u "$expected" "$actual"; then
    echo "ffi test failed: $name" >&2
    exit 1
  fi
  rm -f "$actual"
  echo "ffi case: $name ok"
}

run_negative() {
  name=$1
  src="tests/negative/${name}.urb"
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
run_negative strict_mixed_list
run_negative bitwise_float
run_negative vararg_old_syntax

if [ "${SKIP_FFI:-0}" = "1" ]; then
  echo "SKIP_FFI=1; skipping ffi struct view test"
  if [ "${EMBEDDED_MODE:-0}" = "1" ]; then
    probe_file="$(mktemp)"
    cat > "$probe_file" <<'EOF'
s = { a = "int32" };
println(ffi.sizeof(s));
EOF
    if ! "$BIN" "$probe_file" >/dev/null 2>/dev/null; then
      echo "embedded ffi core probe failed" >&2
      rm -f "$probe_file"
      exit 1
    fi
    rm -f "$probe_file"
    echo "embedded ffi core probe ok"
  fi
else
  probe_file="$(mktemp)"
  echo 'println(ffi.bind.type);' > "$probe_file"
  if "$BIN" "$probe_file" >/dev/null 2>/dev/null; then
    if command -v gcc >/dev/null 2>&1; then
      uname_s="$(uname -s 2>/dev/null || echo Unknown)"
      lib_ext="so"
      cflags_shared="-shared -fPIC"
      case "$uname_s" in
        Darwin)
          lib_ext="dylib"
          cflags_shared="-dynamiclib"
          ;;
        MINGW*|MSYS*|CYGWIN*)
          lib_ext="dll"
          cflags_shared="-shared -Wl,--export-all-symbols"
          ;;
      esac
      echo "building ffi struct test library"
      rm -f tests/ffi/libffi_view_struct.so tests/ffi/libffi_view_struct.dylib tests/ffi/libffi_view_struct.dll
      gcc $cflags_shared tests/ffi/ffi_view_struct.c -o "tests/ffi/libffi_view_struct.$lib_ext"
      run_ffi_case ffi_view_struct
    else
      echo "gcc not found; skipping ffi struct view test"
    fi
  else
    echo "ffi module unavailable; skipping ffi struct view test"
  fi
  rm -f "$probe_file"
fi

if command -v valgrind >/dev/null 2>&1; then
  echo "valgrind: leak check (tests/cases/basic.urb)"
  valgrind --leak-check=full --error-exitcode=1 \
    "$BIN" tests/cases/basic.urb >/dev/null
else
  echo "valgrind not found; skipping leak check"
fi

echo "all tests passed"

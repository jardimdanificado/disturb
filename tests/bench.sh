#!/bin/sh
set -eu

BIN=${BIN:-./disturb}
RUNS=${RUNS:-5}

if [ ! -x "$BIN" ]; then
  echo "disturb binary not found: $BIN" >&2
  exit 1
fi

now_ns() {
  ns=$(date +%s%N 2>/dev/null || true)
  case "$ns" in
    *N*)
      s=$(date +%s)
      echo $((s * 1000000000))
      ;;
    *)
      echo "$ns"
      ;;
  esac
}

ns_to_ms() {
  awk -v ns="$1" 'BEGIN { printf "%.3f", ns / 1000000 }'
}

bench_cmd() {
  name=$1
  shift
  sum=0
  i=1
  while [ $i -le "$RUNS" ]; do
    start=$(now_ns)
    "$@" >/dev/null 2>/dev/null || true
    end=$(now_ns)
    dur=$((end - start))
    sum=$((sum + dur))
    i=$((i + 1))
  done
  avg=$((sum / RUNS))
  printf "%-28s %s ms\n" "$name" "$(ns_to_ms "$avg")"
}

printf "Disturb benchmarks (runs=%s)\n" "$RUNS"
bench_cmd "startup" "$BIN" tests/bench/empty.disturb
bench_cmd "compile bytecode" "$BIN" --asm tests/bench/big.asm tests/bench/big.bin
bench_cmd "disassemble" "$BIN" --disasm tests/bench/big.bin tests/bench/out.asm
bench_cmd "interpret big file" "$BIN" tests/bench/big.disturb
rm -f tests/bench/big.bin tests/bench/out.asm

echo ""

echo "Cross-language (if available)"
bench_cmd "disturb literal list" "$BIN" tests/bench/literal.disturb
if command -v lua >/dev/null 2>&1; then
  bench_cmd "lua sum loop" lua tests/bench/loop.lua
  bench_cmd "lua literal list" lua tests/bench/literal.lua
else
  echo "lua not found"
fi

if command -v node >/dev/null 2>&1; then
  bench_cmd "node sum loop" node tests/bench/loop.js
  bench_cmd "node literal list" node tests/bench/literal.js
else
  echo "node not found"
fi

if command -v cc >/dev/null 2>&1; then
  c_bin=tests/bench/loop_c
  c_lit_bin=tests/bench/literal_c
  if [ ! -x "$c_bin" ] || [ tests/bench/loop.c -nt "$c_bin" ]; then
    cc -O2 tests/bench/loop.c -o "$c_bin" >/dev/null 2>&1 || true
  fi
  if [ -x "$c_bin" ]; then
    bench_cmd "c sum loop" "$c_bin"
  else
    echo "c compiler found but build failed"
  fi
  if [ ! -x "$c_lit_bin" ] || [ tests/bench/literal.c -nt "$c_lit_bin" ]; then
    cc -O2 tests/bench/literal.c -o "$c_lit_bin" >/dev/null 2>&1 || true
  fi
  if [ -x "$c_lit_bin" ]; then
    bench_cmd "c literal list" "$c_lit_bin"
  else
    echo "c literal list build failed"
  fi
else
  echo "c compiler not found"
fi

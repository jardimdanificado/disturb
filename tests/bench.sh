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

printf "Comparative benchmarks (runs=%s)\n" "$RUNS"

echo ""
echo "Literal list"
bench_cmd "disturb" "$BIN" tests/bench/literal.disturb
if command -v lua >/dev/null 2>&1; then
  bench_cmd "lua" lua tests/bench/literal.lua
else
  echo "lua not found"
fi
if command -v node >/dev/null 2>&1; then
  bench_cmd "node" node tests/bench/literal.js
else
  echo "node not found"
fi
if command -v python3 >/dev/null 2>&1; then
  bench_cmd "python" python3 tests/bench/literal.py
elif command -v python >/dev/null 2>&1; then
  bench_cmd "python" python tests/bench/literal.py
else
  echo "python not found"
fi
if command -v cc >/dev/null 2>&1; then
  c_lit_bin=tests/bench/literal_c
  if [ ! -x "$c_lit_bin" ] || [ tests/bench/literal.c -nt "$c_lit_bin" ]; then
    cc -O2 tests/bench/literal.c -o "$c_lit_bin" >/dev/null 2>&1 || true
  fi
  if [ -x "$c_lit_bin" ]; then
    bench_cmd "c" "$c_lit_bin"
  else
    echo "c literal list build failed"
  fi
else
  echo "c compiler not found"
fi

echo ""
echo "Deep access"
bench_cmd "disturb" "$BIN" tests/bench/deep.disturb
if command -v lua >/dev/null 2>&1; then
  bench_cmd "lua" lua tests/bench/deep.lua
else
  echo "lua not found"
fi
if command -v node >/dev/null 2>&1; then
  bench_cmd "node" node tests/bench/deep.js
else
  echo "node not found"
fi
if command -v python3 >/dev/null 2>&1; then
  bench_cmd "python" python3 tests/bench/deep.py
elif command -v python >/dev/null 2>&1; then
  bench_cmd "python" python tests/bench/deep.py
else
  echo "python not found"
fi
if command -v cc >/dev/null 2>&1; then
  c_deep_bin=tests/bench/deep_c
  if [ ! -x "$c_deep_bin" ] || [ tests/bench/deep.c -nt "$c_deep_bin" ]; then
    cc -O2 tests/bench/deep.c -o "$c_deep_bin" >/dev/null 2>&1 || true
  fi
  if [ -x "$c_deep_bin" ]; then
    bench_cmd "c" "$c_deep_bin"
  else
    echo "c deep access build failed"
  fi
else
  echo "c compiler not found"
fi

echo ""
echo "String length"
bench_cmd "disturb" "$BIN" tests/bench/string.disturb
if command -v lua >/dev/null 2>&1; then
  bench_cmd "lua" lua tests/bench/string.lua
else
  echo "lua not found"
fi
if command -v node >/dev/null 2>&1; then
  bench_cmd "node" node tests/bench/string.js
else
  echo "node not found"
fi
if command -v python3 >/dev/null 2>&1; then
  bench_cmd "python" python3 tests/bench/string.py
elif command -v python >/dev/null 2>&1; then
  bench_cmd "python" python tests/bench/string.py
else
  echo "python not found"
fi
if command -v cc >/dev/null 2>&1; then
  c_str_bin=tests/bench/string_c
  if [ ! -x "$c_str_bin" ] || [ tests/bench/string.c -nt "$c_str_bin" ]; then
    cc -O2 tests/bench/string.c -o "$c_str_bin" >/dev/null 2>&1 || true
  fi
  if [ -x "$c_str_bin" ]; then
    bench_cmd "c" "$c_str_bin"
  else
    echo "c string length build failed"
  fi
else
  echo "c compiler not found"
fi

echo ""
echo "Empty program"
bench_cmd "disturb" "$BIN" tests/bench/empty.disturb

echo ""
echo "Big program"
bench_cmd "disturb" "$BIN" tests/bench/big.disturb
bench_cmd "disturb --asm" "$BIN" --asm tests/bench/big.asm

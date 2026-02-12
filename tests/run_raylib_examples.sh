#!/bin/sh
set -eu

BIN=${BIN:-./disturb}
EXAMPLE_DIR=${EXAMPLE_DIR:-example/raylib}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-3}
# Space-separated basenames to skip.
SKIP_EXAMPLES=${SKIP_EXAMPLES:-core_input_virtual_controls.urb}

if [ ! -x "$BIN" ]; then
  echo "disturb binary not found: $BIN" >&2
  exit 1
fi

if [ ! -d "$EXAMPLE_DIR" ]; then
  echo "raylib example directory not found: $EXAMPLE_DIR" >&2
  exit 1
fi

TMP_OUT=/tmp/disturb_raylib_example.out
TMP_ERR=/tmp/disturb_raylib_example.err

ok=0
timeout_ok=0
skipped=0
fail=0

has_timeout=0
if command -v timeout >/dev/null 2>&1; then
  has_timeout=1
fi

is_skipped() {
  base=$1
  for item in $SKIP_EXAMPLES; do
    if [ "$base" = "$item" ]; then
      return 0
    fi
  done
  return 1
}

for src in $(find "$EXAMPLE_DIR" -type f -name '*.urb' | sort); do
  base=$(basename "$src")
  if is_skipped "$base"; then
    skipped=$((skipped + 1))
    echo "skip: $src"
    continue
  fi

  echo "run:  $src"
  rc=0
  if [ "$has_timeout" -eq 1 ]; then
    if timeout --signal=TERM "${TIMEOUT_SECONDS}" "$BIN" "$src" >"$TMP_OUT" 2>"$TMP_ERR"; then
      rc=0
    else
      rc=$?
    fi
  else
    if "$BIN" "$src" >"$TMP_OUT" 2>"$TMP_ERR"; then
      rc=0
    else
      rc=$?
    fi
  fi

  if [ "$rc" -eq 0 ]; then
    ok=$((ok + 1))
    echo "ok:   $src"
    continue
  fi

  if [ "$has_timeout" -eq 1 ] && [ "$rc" -eq 124 ]; then
    timeout_ok=$((timeout_ok + 1))
    echo "ok*:  $src (timed out after ${TIMEOUT_SECONDS}s, no crash detected)"
    continue
  fi

  fail=$((fail + 1))
  echo "fail: $src (rc=$rc)" >&2
  echo "stdout:" >&2
  sed -n '1,60p' "$TMP_OUT" >&2
  echo "stderr:" >&2
  sed -n '1,60p' "$TMP_ERR" >&2
done

rm -f "$TMP_OUT" "$TMP_ERR"

echo "raylib examples summary: ok=$ok timeout_ok=$timeout_ok skipped=$skipped fail=$fail"
if [ "$fail" -ne 0 ]; then
  exit 1
fi


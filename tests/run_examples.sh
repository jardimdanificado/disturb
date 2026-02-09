#!/bin/sh
set -eu

BIN=${BIN:-./disturb}

if [ ! -x "$BIN" ]; then
  echo "disturb binary not found: $BIN" >&2
  exit 1
fi

ok=0
fail=0

for src in $(find example -type f -name '*.urb' | sort); do
  echo "example: $src"
  if "$BIN" "$src" >/tmp/disturb_example.out 2>/tmp/disturb_example.err; then
    ok=$((ok + 1))
    echo "example: $src ok"
  else
    fail=$((fail + 1))
    echo "example failed: $src" >&2
    echo "stdout:" >&2
    sed -n '1,40p' /tmp/disturb_example.out >&2
    echo "stderr:" >&2
    sed -n '1,40p' /tmp/disturb_example.err >&2
  fi
done

rm -f /tmp/disturb_example.out /tmp/disturb_example.err

echo "examples: ok=$ok fail=$fail"
if [ "$fail" -ne 0 ]; then
  exit 1
fi

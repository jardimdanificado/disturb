#!/usr/bin/env bash
set -u

BIN="${BIN:-./disturb}"

if [[ ! -x "$BIN" ]]; then
  echo "error: binary not found: $BIN" >&2
  exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "error: rg is required to list examples" >&2
  exit 1
fi

fail=0
while IFS= read -r example; do
  name="$(basename "$example")"
  echo "example: $name"
  if ! "$BIN" --urb "$example" >/dev/null; then
    echo "example failed: $example" >&2
    fail=1
  fi
done < <(rg --files -g '*.disturb' example)

exit "$fail"

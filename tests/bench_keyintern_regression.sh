#!/bin/sh
set -eu

BIN=${BIN:-./disturb}
RUNS=${RUNS:-2}
IO_ITERS=${IO_ITERS:-100000}
COMPUTE_ITERS=${COMPUTE_ITERS:-20000}
KEY_ITERS=${KEY_ITERS:-5000}

if [ ! -x "$BIN" ]; then
  echo "disturb binary not found: $BIN" >&2
  exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

time_case() {
  src=$1
  start=$(date +%s%N)
  "$BIN" "$src" > /dev/null
  end=$(date +%s%N)
  awk -v s="$start" -v e="$end" 'BEGIN { printf "%.3f", (e - s) / 1000000.0 }'
}

run_case() {
  label=$1
  src=$2
  i=1
  while [ "$i" -le "$RUNS" ]; do
    ms=$(time_case "$src")
    echo "$label run$i: ${ms} ms"
    i=$((i + 1))
  done
}

make_io_case() {
  keyintern=$1
  out=$2
  cat > "$out" <<EOF
gc.keyintern = $keyintern;
gc.rate = 100;
for(i = 0; i < $IO_ITERS; i = i + 1){ println(i); }
gc.stats();
EOF
}

make_compute_case() {
  keyintern=$1
  gcrate=$2
  out=$3
  cat > "$out" <<EOF
gc.keyintern = $keyintern;
gc.rate = $gcrate;
x = 0;
for(i = 0; i < $COMPUTE_ITERS; i = i + 1){ x = x + 1; }
println(x);
EOF
}

make_key_case() {
  keyintern=$1
  gcrate=$2
  out=$3
  cat > "$out" <<EOF
gc.keyintern = $keyintern;
gc.rate = $gcrate;
obj = {};
for(i = 0; i < $KEY_ITERS; i = i + 1){
  k = "k" + i;
  obj[k] = i;
}
println(obj["k$((KEY_ITERS - 1))"]);
EOF
}

echo "== Disturb keyintern regression benchmark =="
echo "BIN=$BIN RUNS=$RUNS IO_ITERS=$IO_ITERS COMPUTE_ITERS=$COMPUTE_ITERS KEY_ITERS=$KEY_ITERS"

for ki in 0 1; do
  io_src="$TMPDIR/io_ki${ki}.disturb"
  make_io_case "$ki" "$io_src"
  run_case "A io-heavy (gc.rate=100, keyintern=$ki)" "$io_src"
done

for ki in 0 1; do
  for rate in 0 100; do
    compute_src="$TMPDIR/compute_ki${ki}_r${rate}.disturb"
    make_compute_case "$ki" "$rate" "$compute_src"
    run_case "B compute (gc.rate=$rate, keyintern=$ki)" "$compute_src"
  done
done

for ki in 0 1; do
  for rate in 0 100; do
    key_src="$TMPDIR/key_ki${ki}_r${rate}.disturb"
    make_key_case "$ki" "$rate" "$key_src"
    run_case "C key-heavy (gc.rate=$rate, keyintern=$ki)" "$key_src"
  done
done

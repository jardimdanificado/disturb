#!/usr/bin/env bash
# benchmark.sh — Run all Disturb benchmarks on both optimized and minimal binaries
# and compare execution times.
#
# Usage: ./benchmarks/benchmark.sh [rounds]
#   rounds = number of times to run each benchmark (default 3, takes median)

set -uo pipefail
cd "$(dirname "$0")/.."

FULL_BIN="./disturb"
MIN_BIN="./disturb-minimal"
BENCH_DIR="benchmarks"
ROUNDS="${1:-3}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Check binaries exist
if [[ ! -x "$FULL_BIN" ]]; then
    echo -e "${RED}ERROR: $FULL_BIN not found. Run 'make' first.${NC}"
    exit 1
fi
if [[ ! -x "$MIN_BIN" ]]; then
    echo -e "${RED}ERROR: $MIN_BIN not found. Run 'make' first.${NC}"
    exit 1
fi

# Collect benchmark files
BENCHMARKS=("$BENCH_DIR"/bench_*.urb)
if [[ ${#BENCHMARKS[@]} -eq 0 ]]; then
    echo -e "${RED}ERROR: No benchmark files found in $BENCH_DIR/${NC}"
    exit 1
fi

echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║           DISTURB BENCHMARK SUITE                          ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC} Full binary:    ${CYAN}$FULL_BIN${NC} (SIMD + Parallel + GPU)"
echo -e "${BOLD}║${NC} Minimal binary: ${CYAN}$MIN_BIN${NC} (scalar only)"
echo -e "${BOLD}║${NC} Rounds per test: ${YELLOW}$ROUNDS${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Helper: run a benchmark N times, return median time in ms
run_bench() {
    local bin="$1"
    local file="$2"
    local times=()
    for ((i = 1; i <= ROUNDS; i++)); do
        local start end ms
        start=$(date +%s%N)
        "$bin" "$file" > /dev/null 2>&1 || true
        end=$(date +%s%N)
        ms=$(( (end - start) / 1000000 ))
        times+=("$ms")
    done
    # Sort and pick median
    local sorted
    sorted=$(printf '%s\n' "${times[@]}" | sort -n)
    local mid=$(( (ROUNDS + 1) / 2 ))
    echo "$sorted" | sed -n "${mid}p"
}

# Header
printf "${BOLD}%-30s %12s %12s %12s %10s${NC}\n" \
    "BENCHMARK" "FULL (ms)" "MINIMAL (ms)" "DELTA (ms)" "SPEEDUP"
printf "%-30s %12s %12s %12s %10s\n" \
    "------------------------------" "------------" "------------" "------------" "----------"

total_full=0
total_min=0

for bench in "${BENCHMARKS[@]}"; do
    name=$(basename "$bench" .urb)
    # warm-up run (discard)
    "$FULL_BIN" "$bench" > /dev/null 2>&1 || true
    "$MIN_BIN" "$bench" > /dev/null 2>&1 || true

    t_full=$(run_bench "$FULL_BIN" "$bench")
    t_min=$(run_bench "$MIN_BIN" "$bench")

    delta=$(awk "BEGIN {printf \"%.0f\", $t_min - $t_full}")
    speedup=$(awk "BEGIN {if ($t_full > 0) printf \"%.2fx\", $t_min/$t_full; else print \"N/A\"}")

    # Color the speedup
    color="$NC"
    if awk "BEGIN {exit !($t_full < $t_min)}" 2>/dev/null; then
        color="$GREEN"
    elif awk "BEGIN {exit !($t_full > $t_min)}" 2>/dev/null; then
        color="$RED"
    fi

    printf "%-30s %12s %12s %12s ${color}%10s${NC}\n" \
        "$name" "${t_full}" "${t_min}" "${delta}" "${speedup}"

    total_full=$((total_full + t_full))
    total_min=$((total_min + t_min))
done

echo ""
printf "%-30s %12s %12s %12s %10s\n" \
    "------------------------------" "------------" "------------" "------------" "----------"

total_delta=$((total_min - total_full))
total_speedup=$(awk "BEGIN {if ($total_full > 0) printf \"%.2fx\", $total_min/$total_full; else print \"N/A\"}")
printf "${BOLD}%-30s %12d %12d %12d %10s${NC}\n" \
    "TOTAL" "$total_full" "$total_min" "$total_delta" "$total_speedup"

echo ""
echo -e "${BOLD}Legend:${NC}"
echo -e "  ${GREEN}Green${NC} = optimized binary is faster"
echo -e "  ${RED}Red${NC}   = minimal binary is faster (unexpected)"
echo -e "  Speedup = minimal_time / full_time (higher is better)"
echo ""

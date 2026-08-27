#!/bin/sh
# Batch runner: exports the isolated runtime store so background runs inherit it.
# Usage: run-batch.sh <sequences> <logfile>
set -eu
export FERROCRATE_HOME=/path/to/ferrocrate-lab/runtimes/fuzz
export FERROCRATE_BIN=/data/dev/ferrocrate/target/release/ferro-cli
cd /data/dev/ferrocrate-fuzz
exec python3 bench/fuzz/fuzz.py --sequences "$1" \
    --out bench/results/2026-08-27/fuzz-500.jsonl > "$2" 2>&1

#!/bin/sh
# Soak runner: the isolated store must be exported so the setsid-detached
# process inherits it, and the run must survive the agent exiting, hence setsid.
# Usage: run-soak.sh <duration e.g. 4h> <logfile>
set -eu
export FERROCRATE_HOME=/path/to/ferrocrate-lab/runtimes/fuzz
export FERROCRATE_BIN=/data/dev/ferrocrate/target/release/ferro-cli
export FUZZ_IMAGE=public.ecr.aws/docker/library/alpine:3.20
cd /data/dev/ferrocrate-fuzz
exec python3 bench/fuzz/fuzz.py --soak "$1" --audit \
    --out bench/results/2026-08-27/fuzz-soak.jsonl > "$2" 2>&1

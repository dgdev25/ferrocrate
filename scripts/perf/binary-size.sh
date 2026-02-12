#!/usr/bin/env bash
set -euo pipefail

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

size_bytes=$(stat -c %s ./target/release/ferro-cli)
size_mb=$((size_bytes / 1024 / 1024))

echo "perf.binary_size_bytes=${size_bytes}"
echo "perf.binary_size_mb=${size_mb}"

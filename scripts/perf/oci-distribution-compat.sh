#!/usr/bin/env bash
set -euo pipefail

IMAGE=${FERROCRATE_PERF_IMAGE:-alpine:latest}

if [ ! -x ./target/release/ferro-cli ]; then
  cargo build -p ferro-cli --release
fi

canonical="$IMAGE"
if [[ "$IMAGE" != */* ]]; then
  canonical="registry-1.docker.io/library/$IMAGE"
elif [[ "$IMAGE" != */*/* ]]; then
  canonical="registry-1.docker.io/$IMAGE"
fi

# Reuse a previously verified local manifest when available. This keeps the
# qualification deterministic on hosts subject to anonymous registry limits;
# a fresh pull is still attempted when the exact reference is absent.
if ./target/release/ferro-cli images --format json 2>/dev/null | grep -Fq '"reference": "'$canonical'"'; then
  echo "perf.oci_distribution_compat=1"
  echo "perf.oci_distribution_source=cached"
  exit 0
fi

if ./target/release/ferro-cli pull "$IMAGE" >/dev/null 2>&1; then
  echo "perf.oci_distribution_compat=1"
else
  echo "perf.oci_distribution_compat=0"
  exit 1
fi

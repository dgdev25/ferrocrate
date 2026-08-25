#!/usr/bin/env bash
set -euo pipefail

cargo test --workspace
bash scripts/verify-no-warnings.sh

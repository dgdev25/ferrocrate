#!/bin/bash
# usage: bench/run-all.sh [both|docker|ferrocrate]  — every manifest in order, then the scoreboard
set -u; B="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; E="${1:-both}"
for m in "$B"/apps/*/manifest.yaml; do a="$(basename "$(dirname "$m")")"; bash "$B/run-app.sh" "$a" "$E" 2>&1 | tail -3; done
python3 "$B/scoreboard.py"

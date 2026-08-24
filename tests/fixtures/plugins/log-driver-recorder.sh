#!/bin/sh
set -eu
test -n "${FERROCRATE_LOG_DRIVER_CAPTURE:-}"
payload=$(cat)
printf '%s\n' "$payload" >> "$FERROCRATE_LOG_DRIVER_CAPTURE"

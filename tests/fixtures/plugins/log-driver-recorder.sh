#!/bin/sh
set -eu
capture=${FERROCRATE_LOG_DRIVER_CAPTURE:-"$0.capture"}
payload=$(cat)
printf '%s\n' "$payload" >> "$capture"

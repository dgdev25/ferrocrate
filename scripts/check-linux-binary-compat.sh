#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: check-linux-binary-compat.sh BINARY [MAX_GLIBC_VERSION]" >&2
}

[[ $# -ge 1 && $# -le 2 ]] || { usage; exit 2; }
binary="$1"
max_version="${2:-${FERROCRATE_LINUX_GLIBC_BASELINE:-2.34}}"
readelf_bin="${READELF:-readelf}"

[[ -f "$binary" ]] || { echo "binary does not exist: $binary" >&2; exit 1; }
[[ -x "$binary" ]] || { echo "binary is not executable: $binary" >&2; exit 1; }
command -v "$readelf_bin" >/dev/null 2>&1 || {
  echo "readelf is required to check Linux ABI compatibility" >&2
  exit 1
}

file_header="$($readelf_bin -h "$binary" 2>/dev/null)" || {
  echo "unable to inspect ELF header: $binary" >&2
  exit 1
}
grep -q 'ELF' <<<"$file_header" || {
  echo "binary is not an ELF executable: $binary" >&2
  exit 1
}

[[ "$max_version" =~ ^[0-9]+\.[0-9]+$ ]] || {
  echo "invalid maximum glibc version: $max_version" >&2
  exit 2
}

versions="$($readelf_bin --version-info "$binary" 2>/dev/null \
  | grep -oE 'GLIBC_[0-9]+\.[0-9]+' \
  | sed 's/^GLIBC_//' | sort -Vu || true)"
if [[ -z "$versions" ]]; then
  echo "linux ABI check passed: $binary has no dynamic GLIBC symbol requirements (baseline=$max_version)"
  exit 0
fi

highest="$(tail -n 1 <<<"$versions")"
newest="$(printf '%s\n' "$max_version" "$highest" | sort -V | tail -n 1)"
if [[ "$newest" != "$max_version" ]]; then
  echo "linux ABI check failed: $binary requires GLIBC_$highest, baseline is GLIBC_$max_version" >&2
  exit 1
fi

echo "linux ABI check passed: $binary highest=GLIBC_$highest baseline=GLIBC_$max_version"

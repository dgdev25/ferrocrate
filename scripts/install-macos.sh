#!/usr/bin/env bash
set -euo pipefail

# Secure macOS installer for FerroCrate.
# Supports:
# 1) binary install from GitHub release artifacts (default)
# 2) source build from git

REPO="${REPO:-dgtise25/ferrocrate}"
VERSION="${VERSION:-latest}"
PREFIX="${PREFIX:-/usr/local/bin}"
METHOD="${METHOD:-binary}"
FORCE="0"

usage() {
  cat <<USAGE
Usage: install-macos.sh [options]

Options:
  --method <binary|source>   Install method (default: binary)
  --version <tag|latest>     Release tag (default: latest)
  --repo <owner/name>        GitHub repo (default: dgtise25/ferrocrate)
  --prefix <path>            Install destination (default: /usr/local/bin)
  --force                    Overwrite existing files without prompt
  -h, --help                 Show this help

Examples:
  ./install-macos.sh
  ./install-macos.sh --version v0.1.0
  ./install-macos.sh --method source --prefix ~/.local/bin
USAGE
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --method)
        METHOD="${2:-}"
        shift 2
        ;;
      --version)
        VERSION="${2:-}"
        shift 2
        ;;
      --repo)
        REPO="${2:-}"
        shift 2
        ;;
      --prefix)
        PREFIX="${2:-}"
        shift 2
        ;;
      --force)
        FORCE="1"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "unknown option: $1" >&2
        usage
        exit 1
        ;;
    esac
  done
}

ensure_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "this installer is for macOS only" >&2
    exit 1
  fi
}

arch_name() {
  local machine
  machine="$(uname -m)"
  case "$machine" in
    arm64|aarch64) echo "aarch64" ;;
    x86_64) echo "x86_64" ;;
    *)
      echo "unsupported macOS architecture: $machine" >&2
      exit 1
      ;;
  esac
}

install_binary_release() {
  require_cmd curl
  require_cmd tar
  require_cmd shasum

  local arch tag base_url asset_name checksum_name tmpdir tarball checksums expected actual
  arch="$(arch_name)"

  if [[ "$VERSION" == "latest" ]]; then
    require_cmd awk
    tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | awk -F '"' '/"tag_name":/ {print $4; exit}')"
    if [[ -z "$tag" ]]; then
      echo "failed to resolve latest release tag from GitHub API" >&2
      exit 1
    fi
  else
    tag="$VERSION"
  fi

  base_url="https://github.com/${REPO}/releases/download/${tag}"
  asset_name="ferrocrate-${tag}-macos-${arch}.tar.gz"
  checksum_name="ferrocrate-${tag}-checksums.txt"

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  tarball="$tmpdir/$asset_name"
  checksums="$tmpdir/$checksum_name"

  echo "downloading: $asset_name"
  curl -fL "$base_url/$asset_name" -o "$tarball"

  echo "downloading: $checksum_name"
  curl -fL "$base_url/$checksum_name" -o "$checksums"

  expected="$(awk -v file="$asset_name" '$2==file {print $1}' "$checksums")"
  if [[ -z "$expected" ]]; then
    echo "checksum entry not found for $asset_name in $checksum_name" >&2
    exit 1
  fi

  actual="$(shasum -a 256 "$tarball" | awk '{print $1}')"
  if [[ "$expected" != "$actual" ]]; then
    echo "checksum mismatch for $asset_name" >&2
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
  fi

  mkdir -p "$tmpdir/unpack"
  tar -xzf "$tarball" -C "$tmpdir/unpack"

  install_binaries_from_dir "$tmpdir/unpack"
  echo "installed FerroCrate from release tag $tag"
}

install_from_source() {
  require_cmd git
  require_cmd cargo

  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  echo "cloning repository: https://github.com/${REPO}.git"
  git clone "https://github.com/${REPO}.git" "$tmpdir/src" --depth 1
  if [[ "$VERSION" != "latest" ]]; then
    (cd "$tmpdir/src" && git fetch --tags --depth 1 && git checkout "$VERSION")
  fi

  (cd "$tmpdir/src" && cargo build --release -p ferro-cli -p ferro-desktop)

  mkdir -p "$tmpdir/unpack"
  cp "$tmpdir/src/target/release/ferro-cli" "$tmpdir/unpack/ferrocrate"
  if [[ -f "$tmpdir/src/target/release/ferro-desktop" ]]; then
    cp "$tmpdir/src/target/release/ferro-desktop" "$tmpdir/unpack/ferro-desktop"
  fi

  install_binaries_from_dir "$tmpdir/unpack"
  echo "installed FerroCrate from source"
}

install_file() {
  local src="$1"
  local dst="$2"

  if [[ -e "$dst" && "$FORCE" != "1" ]]; then
    echo "file exists: $dst (use --force to overwrite)" >&2
    exit 1
  fi

  install -m 0755 "$src" "$dst"
}

install_binaries_from_dir() {
  local dir="$1"
  local ferrocrate_src=""
  local desktop_src=""

  if [[ -f "$dir/ferrocrate" ]]; then
    ferrocrate_src="$dir/ferrocrate"
  elif [[ -f "$dir/ferro-cli" ]]; then
    ferrocrate_src="$dir/ferro-cli"
  elif [[ -f "$dir/ferrocrate/ferrocrate" ]]; then
    ferrocrate_src="$dir/ferrocrate/ferrocrate"
  fi

  if [[ -z "$ferrocrate_src" ]]; then
    echo "could not find ferrocrate binary in: $dir" >&2
    exit 1
  fi

  if [[ -f "$dir/ferro-desktop" ]]; then
    desktop_src="$dir/ferro-desktop"
  elif [[ -f "$dir/ferrocrate/ferro-desktop" ]]; then
    desktop_src="$dir/ferrocrate/ferro-desktop"
  fi

  mkdir -p "$PREFIX"
  install_file "$ferrocrate_src" "$PREFIX/ferrocrate"
  if [[ -n "$desktop_src" ]]; then
    install_file "$desktop_src" "$PREFIX/ferro-desktop"
  fi
}

main() {
  parse_args "$@"
  ensure_macos

  case "$METHOD" in
    binary)
      install_binary_release
      ;;
    source)
      install_from_source
      ;;
    *)
      echo "invalid --method: $METHOD (expected binary or source)" >&2
      exit 1
      ;;
  esac

  echo "done. try: ferrocrate --help"
}

main "$@"

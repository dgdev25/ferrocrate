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
DESKTOP_BOOTSTRAP="${DESKTOP_BOOTSTRAP:-1}"
VM_STATE_FILE="${VM_STATE_FILE:-$HOME/.ferrocrate/desktop-vm.json}"
VM_DIR="${VM_DIR:-$HOME/.ferrocrate/vm}"
VM_DISK_PATH="${VM_DISK_PATH:-$VM_DIR/ferrocrate-desktop.qcow2}"
VM_CLOUD_INIT_PATH="${VM_CLOUD_INIT_PATH:-$VM_DIR/cloud-init-seed.iso}"
VM_SIZE_GB="${VM_SIZE_GB:-20}"
VM_SSH_PORT="${VM_SSH_PORT:-2222}"
VM_API_PORT="${VM_API_PORT:-4288}"
VM_HOST_SHARE="${VM_HOST_SHARE:-$HOME}"
VM_GUEST_USER="${VM_GUEST_USER:-ferro}"
VM_SSH_KEY_PATH="${VM_SSH_KEY_PATH:-$VM_DIR/desktop_vm_ed25519}"
FORCE="0"
RESOLVED_RELEASE_TAG=""

usage() {
  cat <<USAGE
Usage: install-macos.sh [options]

Options:
  --method <binary|source>   Install method (default: binary)
  --version <tag|latest>     Release tag (default: latest)
  --repo <owner/name>        GitHub repo (default: dgtise25/ferrocrate)
  --prefix <path>            Install destination (default: /usr/local/bin)
  --no-desktop-bootstrap     Skip desktop VM/bootstrap setup
  --force                    Overwrite existing files without prompt
  -h, --help                 Show this help

Examples:
  ./install-macos.sh
  ./install-macos.sh --version v0.1.0
  ./install-macos.sh --no-desktop-bootstrap
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
      --no-desktop-bootstrap)
        DESKTOP_BOOTSTRAP="0"
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

resolve_release_tag() {
  if [[ -n "$RESOLVED_RELEASE_TAG" ]]; then
    echo "$RESOLVED_RELEASE_TAG"
    return
  fi
  if [[ "$VERSION" == "latest" ]]; then
    require_cmd awk
    RESOLVED_RELEASE_TAG="$(
      curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | awk -F '"' '/"tag_name":/ {print $4; exit}'
    )"
    if [[ -z "$RESOLVED_RELEASE_TAG" ]]; then
      echo "failed to resolve latest release tag from GitHub API" >&2
      exit 1
    fi
  else
    RESOLVED_RELEASE_TAG="$VERSION"
  fi
  echo "$RESOLVED_RELEASE_TAG"
}

install_binary_release() {
  require_cmd curl
  require_cmd tar
  require_cmd shasum

  local arch tag base_url asset_name checksum_name tmpdir tarball checksums expected actual
  arch="$(arch_name)"

  tag="$(resolve_release_tag)"

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
    RESOLVED_RELEASE_TAG="$VERSION"
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

ensure_homebrew() {
  if command -v brew >/dev/null 2>&1; then
    return
  fi
  echo "homebrew not found, installing..."
  NONINTERACTIVE=1 /bin/bash -c \
    "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [[ -x /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
  command -v brew >/dev/null 2>&1 || {
    echo "failed to install homebrew" >&2
    exit 1
  }
}

brew_install_if_missing() {
  local bin_name="$1"
  local formula="$2"
  if command -v "$bin_name" >/dev/null 2>&1; then
    return
  fi
  echo "installing dependency: $formula"
  brew install "$formula"
  command -v "$bin_name" >/dev/null 2>&1 || {
    echo "dependency install failed: $formula (missing binary $bin_name)" >&2
    exit 1
  }
}

ensure_host_dependencies() {
  require_cmd curl
  require_cmd shasum
  require_cmd nc
  require_cmd hdiutil
  require_cmd ssh-keygen
  ensure_homebrew
  brew_install_if_missing qemu-img qemu
  case "$(arch_name)" in
    aarch64)
      brew_install_if_missing qemu-system-aarch64 qemu
      ;;
    x86_64)
      brew_install_if_missing qemu-system-x86_64 qemu
      ;;
  esac
  # ssh client is usually preinstalled on macOS; install via brew if missing.
  if ! command -v ssh >/dev/null 2>&1; then
    brew install openssh
  fi
  command -v ssh >/dev/null 2>&1 || {
    echo "missing required command: ssh" >&2
    exit 1
  }
}

vm_backend_for_host() {
  if [[ "$(uname -m)" == "x86_64" ]]; then
    echo "qemu-x86_64"
  else
    echo "qemu-hvf"
  fi
}

base_cloud_image_url() {
  case "$(arch_name)" in
    aarch64)
      echo "https://cloud-images.ubuntu.com/minimal/releases/24.04/release/ubuntu-24.04-minimal-cloudimg-arm64.img"
      ;;
    x86_64)
      echo "https://cloud-images.ubuntu.com/minimal/releases/24.04/release/ubuntu-24.04-minimal-cloudimg-amd64.img"
      ;;
    *)
      echo "unsupported architecture for vm image" >&2
      exit 1
      ;;
  esac
}

prepare_vm_image() {
  local base_url base_img cache_dir
  cache_dir="$VM_DIR/cache"
  base_url="$(base_cloud_image_url)"
  base_img="$cache_dir/base-cloudimg.qcow2"

  mkdir -p "$VM_DIR" "$cache_dir"
  if [[ ! -f "$base_img" ]]; then
    echo "downloading desktop VM base image..."
    curl -fL "$base_url" -o "$base_img"
  fi

  if [[ ! -f "$VM_DISK_PATH" ]]; then
    echo "creating desktop VM disk at $VM_DISK_PATH..."
    qemu-img create -f qcow2 -F qcow2 -b "$base_img" "$VM_DISK_PATH" "${VM_SIZE_GB}G" >/dev/null
  else
    echo "reusing existing VM disk: $VM_DISK_PATH"
  fi
}

wait_for_ssh_port() {
  local host="$1"
  local port="$2"
  local timeout_secs="$3"
  local start now
  start="$(date +%s)"
  while true; do
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      return 0
    fi
    now="$(date +%s)"
    if (( now - start >= timeout_secs )); then
      return 1
    fi
    sleep 2
  done
}

generate_vm_ssh_key() {
  mkdir -p "$VM_DIR"
  if [[ -f "$VM_SSH_KEY_PATH" && -f "${VM_SSH_KEY_PATH}.pub" ]]; then
    return
  fi
  echo "generating VM SSH key..."
  ssh-keygen -t ed25519 -N "" -f "$VM_SSH_KEY_PATH" >/dev/null
}

generate_cloud_init_seed() {
  local tmpdir user_data meta_data pubkey release_tag
  tmpdir="$(mktemp -d)"
  pubkey="$(cat "${VM_SSH_KEY_PATH}.pub")"
  release_tag="$(resolve_release_tag)"
  user_data="$tmpdir/user-data"
  meta_data="$tmpdir/meta-data"

  cat >"$user_data" <<EOF
#cloud-config
users:
  - name: ${VM_GUEST_USER}
    groups: sudo
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ${pubkey}
ssh_pwauth: false
disable_root: true
package_update: true
packages:
  - curl
  - ca-certificates
  - tar
runcmd:
  - [ bash, -lc, "set -euo pipefail; arch=\$(uname -m); case \$arch in aarch64|arm64) fc_arch=aarch64 ;; x86_64|amd64) fc_arch=x86_64 ;; *) exit 0 ;; esac; tag='${release_tag}'; asset=\"ferrocrate-\${tag}-linux-\${fc_arch}.tar.gz\"; url=\"https://github.com/${REPO}/releases/download/\${tag}/\${asset}\"; tmp=/tmp/ferrocrate-install; rm -rf \"\$tmp\"; mkdir -p \"\$tmp\"; curl -fL \"\$url\" -o \"\$tmp/pkg.tgz\"; tar -xzf \"\$tmp/pkg.tgz\" -C \"\$tmp\"; if [ -f \"\$tmp/ferrocrate\" ]; then install -m 0755 \"\$tmp/ferrocrate\" /usr/local/bin/ferrocrate; elif [ -f \"\$tmp/ferro-cli\" ]; then install -m 0755 \"\$tmp/ferro-cli\" /usr/local/bin/ferrocrate; fi; if [ -f \"\$tmp/ferro-desktop\" ]; then install -m 0755 \"\$tmp/ferro-desktop\" /usr/local/bin/ferro-desktop; fi" ]
final_message: "FerroCrate guest bootstrap complete"
EOF

  cat >"$meta_data" <<EOF
instance-id: ferrocrate-desktop
local-hostname: ferrocrate-vm
EOF

  mkdir -p "$VM_DIR"
  rm -f "$VM_CLOUD_INIT_PATH"
  hdiutil makehybrid \
    -quiet \
    -o "$VM_CLOUD_INIT_PATH" \
    "$tmpdir" \
    -iso \
    -joliet \
    -ov \
    -default-volume-name cidata >/dev/null
  rm -rf "$tmpdir"
}

guest_ssh() {
  local command_string="$1"
  ssh \
    -i "$VM_SSH_KEY_PATH" \
    -p "$VM_SSH_PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    "${VM_GUEST_USER}@127.0.0.1" \
    -- bash -lc "$command_string"
}

wait_for_guest_ssh() {
  local timeout_secs="$1"
  local start now
  start="$(date +%s)"
  while true; do
    if guest_ssh "echo ready" >/dev/null 2>&1; then
      return 0
    fi
    now="$(date +%s)"
    if (( now - start >= timeout_secs )); then
      return 1
    fi
    sleep 3
  done
}

ensure_guest_ferrocrate_installed() {
  local tag install_cmd fallback_cmd
  if guest_ssh "command -v ferrocrate >/dev/null"; then
    echo "guest ferrocrate runtime is installed"
    return
  fi

  tag="$(resolve_release_tag)"
  echo "guest runtime missing, installing ferrocrate in VM..."
  install_cmd="set -euo pipefail; arch=\$(uname -m); case \$arch in aarch64|arm64) fc_arch=aarch64 ;; x86_64|amd64) fc_arch=x86_64 ;; *) echo unsupported_arch:\$arch >&2; exit 1 ;; esac; asset='ferrocrate-${tag}-linux-'\${fc_arch}'.tar.gz'; url='https://github.com/${REPO}/releases/download/${tag}/'\${asset}; tmp=/tmp/ferrocrate-install-host; rm -rf \"\$tmp\"; mkdir -p \"\$tmp\"; curl -fL \"\$url\" -o \"\$tmp/pkg.tgz\"; tar -xzf \"\$tmp/pkg.tgz\" -C \"\$tmp\"; if [ -f \"\$tmp/ferrocrate\" ]; then sudo install -m 0755 \"\$tmp/ferrocrate\" /usr/local/bin/ferrocrate; elif [ -f \"\$tmp/ferro-cli\" ]; then sudo install -m 0755 \"\$tmp/ferro-cli\" /usr/local/bin/ferrocrate; else echo no_ferrocrate_binary >&2; exit 1; fi; if [ -f \"\$tmp/ferro-desktop\" ]; then sudo install -m 0755 \"\$tmp/ferro-desktop\" /usr/local/bin/ferro-desktop; fi"
  if ! guest_ssh "$install_cmd"; then
    echo "guest prebuilt artifacts unavailable for ${tag}; building from source in guest..."
    fallback_cmd="set -euo pipefail; tmp=/tmp/ferrocrate-source-build; rm -rf \"\$tmp\"; mkdir -p \"\$tmp\"; sudo apt-get update; sudo apt-get install -y build-essential pkg-config libssl-dev curl ca-certificates git; if ! command -v cargo >/dev/null 2>&1; then curl https://sh.rustup.rs -sSf | sh -s -- -y; fi; . \"\$HOME/.cargo/env\"; src=\"\$tmp/src\"; if [ '${tag}' = 'latest' ]; then git clone --depth 1 https://github.com/${REPO}.git \"\$src\"; else git clone --depth 1 --branch '${tag}' https://github.com/${REPO}.git \"\$src\"; fi; cd \"\$src\"; cargo build --release -p ferro-cli -p ferro-desktop; if [ -f target/release/ferro-cli ]; then sudo install -m 0755 target/release/ferro-cli /usr/local/bin/ferrocrate; elif [ -f target/release/ferrocrate ]; then sudo install -m 0755 target/release/ferrocrate /usr/local/bin/ferrocrate; else echo missing_guest_cli_binary >&2; exit 1; fi; if [ -f target/release/ferro-desktop ]; then sudo install -m 0755 target/release/ferro-desktop /usr/local/bin/ferro-desktop; fi"
    guest_ssh "$fallback_cmd"
  fi
  guest_ssh "command -v ferrocrate >/dev/null"
}

bootstrap_desktop_vm() {
  local ferro_desktop vm_backend
  ferro_desktop="$PREFIX/ferro-desktop"
  [[ -x "$ferro_desktop" ]] || ferro_desktop="$(command -v ferro-desktop || true)"
  if [[ -z "$ferro_desktop" || ! -x "$ferro_desktop" ]]; then
    echo "ferro-desktop binary not found after install" >&2
    exit 1
  fi

  prepare_vm_image
  generate_vm_ssh_key
  generate_cloud_init_seed
  vm_backend="$(vm_backend_for_host)"
  echo "initializing desktop VM state..."
  "$ferro_desktop" vm \
    --state-file "$VM_STATE_FILE" \
    init \
    --backend "$vm_backend" \
    --disk-path "$VM_DISK_PATH" \
    --host-share-path "$VM_HOST_SHARE" \
    --fs-backend 9p \
    --ssh-port "$VM_SSH_PORT" \
    --api-port "$VM_API_PORT" \
    --guest-user "$VM_GUEST_USER" \
    --ssh-private-key-path "$VM_SSH_KEY_PATH" \
    --cloud-init-image-path "$VM_CLOUD_INIT_PATH" >/dev/null

  echo "starting desktop VM..."
  if ! "$ferro_desktop" vm --state-file "$VM_STATE_FILE" start; then
    echo "desktop VM failed to start; inspect with:" >&2
    echo "  $ferro_desktop vm --state-file $VM_STATE_FILE status --json" >&2
    exit 1
  fi

  echo "waiting for guest SSH on 127.0.0.1:$VM_SSH_PORT..."
  if wait_for_ssh_port 127.0.0.1 "$VM_SSH_PORT" 120; then
    echo "guest SSH TCP port is reachable"
  else
    echo "guest SSH TCP port did not become reachable within timeout" >&2
    exit 1
  fi

  echo "waiting for guest SSH authentication..."
  if wait_for_guest_ssh 180; then
    echo "guest SSH authentication succeeded"
  else
    echo "guest SSH did not become ready for auth within timeout" >&2
    exit 1
  fi

  ensure_guest_ferrocrate_installed
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

  if [[ "$DESKTOP_BOOTSTRAP" == "1" ]]; then
    ensure_host_dependencies
    bootstrap_desktop_vm
  fi

  echo "done. try: ferrocrate --help"
}

main "$@"

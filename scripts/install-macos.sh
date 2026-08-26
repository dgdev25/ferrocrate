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
RELEASE_CHANNEL="${RELEASE_CHANNEL:-public}"
INSTALL_DESKTOP_BIN="${INSTALL_DESKTOP_BIN:-0}"
DESKTOP_BOOTSTRAP="${DESKTOP_BOOTSTRAP:-0}"
FULL_STACK="${FULL_STACK:-0}"
PAID_RELEASE_BASE_URL="${PAID_RELEASE_BASE_URL:-}"
PAID_RELEASE_TOKEN="${PAID_RELEASE_TOKEN:-}"
PAID_SESSION_TOKEN="${PAID_SESSION_TOKEN:-}"
PAID_RELEASE_TOKEN_ENDPOINT="${PAID_RELEASE_TOKEN_ENDPOINT:-}"
PAID_ENTITLEMENT_FILE="${PAID_ENTITLEMENT_FILE:-$HOME/.ferrocrate/entitlement.lic}"
FERROCRATE_CONFIG_DIR="${FERROCRATE_CONFIG_DIR:-$HOME/.ferrocrate}"
VM_STATE_FILE="${VM_STATE_FILE:-${FERROCRATE_DESKTOP_VM_STATE:-$FERROCRATE_CONFIG_DIR/desktop-vm.json}}"
VM_STATE_DIR="$(dirname "$VM_STATE_FILE")"
VM_KNOWN_HOSTS_PATH="${VM_KNOWN_HOSTS_PATH:-$VM_STATE_DIR/known_hosts}"
VM_DIR="${VM_DIR:-${FERROCRATE_VM_DIR:-$FERROCRATE_CONFIG_DIR/vm}}"
VM_DISK_PATH_OVERRIDE="${VM_DISK_PATH:-}"
VM_DISK_PATH="${VM_DISK_PATH:-$VM_DIR/ferrocrate-desktop.qcow2}"
VM_CLOUD_INIT_PATH="${VM_CLOUD_INIT_PATH:-$VM_DIR/cloud-init-seed.iso}"
VM_SIZE_GB="${VM_SIZE_GB:-20}"
VM_SSH_PORT="${VM_SSH_PORT:-${FERROCRATE_VM_SSH_PORT:-2222}}"
VM_API_PORT="${VM_API_PORT:-${FERROCRATE_VM_API_PORT:-4288}}"
VM_HOST_SHARE="${VM_HOST_SHARE:-$HOME}"
VM_GUEST_USER="${VM_GUEST_USER:-${FERROCRATE_VM_GUEST_USER:-ferro}}"
VM_SSH_KEY_PATH="${VM_SSH_KEY_PATH:-${FERROCRATE_VM_SSH_KEY:-$VM_DIR/desktop_vm_ed25519}}"
VM_GUEST_SOCKET="${VM_GUEST_SOCKET:-/home/${VM_GUEST_USER}/.local/state/ferrocrate/ferrocrate.sock}"
VFKIT_MAC="${VFKIT_MAC:-5a:94:ef:e4:0c:ee}"
FORCE="0"
RESOLVED_RELEASE_TAG=""
DESKTOP_BIN_SET="0"
DESKTOP_BOOTSTRAP_SET="0"

usage() {
  cat <<USAGE
Usage: install-macos.sh [options]

Options:
  --method <binary|source>   Install method (default: binary)
  --channel <public|paid>    Artifact channel (default: public)
  --version <tag|latest>     Release tag (default: latest)
  --repo <owner/name>        GitHub repo (default: dgtise25/ferrocrate)
  --prefix <path>            Install destination (default: /usr/local/bin)
  --with-desktop-bin         Install ferro-desktop binary (paid channels)
  --with-desktop-bootstrap   Initialize/start desktop VM (requires desktop binary)
  --full-stack               Enable desktop binary + desktop VM bootstrap
  --cli-only                 Disable desktop binary + bootstrap
  --no-desktop-bootstrap     Skip desktop VM/bootstrap setup
  --force                    Overwrite existing files without prompt
  -h, --help                 Show this help

Examples:
  ./install-macos.sh
  ./install-macos.sh --version v0.1.0
  ./install-macos.sh --channel paid
  ./install-macos.sh --with-desktop-bin --with-desktop-bootstrap
  ./install-macos.sh --channel paid --full-stack
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
      --channel)
        RELEASE_CHANNEL="${2:-}"
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
      --with-desktop-bin)
        INSTALL_DESKTOP_BIN="1"
        DESKTOP_BIN_SET="1"
        shift
        ;;
      --with-desktop-bootstrap)
        INSTALL_DESKTOP_BIN="1"
        DESKTOP_BOOTSTRAP="1"
        DESKTOP_BIN_SET="1"
        DESKTOP_BOOTSTRAP_SET="1"
        shift
        ;;
      --full-stack)
        FULL_STACK="1"
        shift
        ;;
      --cli-only)
        INSTALL_DESKTOP_BIN="0"
        DESKTOP_BOOTSTRAP="0"
        DESKTOP_BIN_SET="1"
        DESKTOP_BOOTSTRAP_SET="1"
        shift
        ;;
      --no-desktop-bootstrap)
        DESKTOP_BOOTSTRAP="0"
        DESKTOP_BOOTSTRAP_SET="1"
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

release_base_url_for_tag() {
  local tag="$1"
  if [[ "$RELEASE_CHANNEL" == "public" ]]; then
    echo "https://github.com/${REPO}/releases/download/${tag}"
    return
  fi
  if [[ "$RELEASE_CHANNEL" != "paid" ]]; then
    echo "invalid --channel: $RELEASE_CHANNEL (expected public or paid)" >&2
    exit 1
  fi
  if [[ -z "$PAID_RELEASE_BASE_URL" ]]; then
    echo "paid channel requires PAID_RELEASE_BASE_URL (can include {tag} placeholder)" >&2
    exit 1
  fi
  if [[ "$PAID_RELEASE_BASE_URL" == *"{tag}"* ]]; then
    echo "${PAID_RELEASE_BASE_URL//\{tag\}/$tag}"
  else
    echo "${PAID_RELEASE_BASE_URL%/}/${tag}"
  fi
}

ensure_paid_release_token() {
  local tag="${1:-latest}"
  if [[ "$RELEASE_CHANNEL" != "paid" ]]; then
    return
  fi
  if [[ -n "$PAID_SESSION_TOKEN" ]]; then
    if [[ -z "$PAID_RELEASE_TOKEN_ENDPOINT" ]]; then
      echo "paid channel with PAID_SESSION_TOKEN requires PAID_RELEASE_TOKEN_ENDPOINT" >&2
      exit 1
    fi
    local session_response session_token
    echo "requesting paid release token via session..."
    session_response="$(
      curl -fsSL \
        -X POST \
        -H "Authorization: Bearer ${PAID_SESSION_TOKEN}" \
        -H "X-Ferrocrate-Tag: ${tag}" \
        "$PAID_RELEASE_TOKEN_ENDPOINT"
    )"
    session_token="$(printf '%s' "$session_response" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    if [[ -z "$session_token" ]]; then
      echo "failed to parse token from session token endpoint response" >&2
      exit 1
    fi
    PAID_RELEASE_TOKEN="$session_token"
    return
  fi
  if [[ -n "$PAID_RELEASE_TOKEN" ]]; then
    return
  fi
  if [[ -z "$PAID_RELEASE_TOKEN_ENDPOINT" ]]; then
    echo "paid channel requires PAID_RELEASE_TOKEN or PAID_RELEASE_TOKEN_ENDPOINT" >&2
    exit 1
  fi
  if [[ ! -f "$PAID_ENTITLEMENT_FILE" ]]; then
    echo "paid channel token exchange requires entitlement file: $PAID_ENTITLEMENT_FILE" >&2
    exit 1
  fi

  local response token
  echo "requesting paid release token..."
  response="$(
    curl -fsSL \
      -H "Content-Type: application/json" \
      -H "X-Ferrocrate-Tag: ${tag}" \
      --data-binary @"$PAID_ENTITLEMENT_FILE" \
      "$PAID_RELEASE_TOKEN_ENDPOINT"
  )"
  token="$(printf '%s' "$response" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  if [[ -z "$token" ]]; then
    echo "failed to parse token from paid release token endpoint response" >&2
    exit 1
  fi
  PAID_RELEASE_TOKEN="$token"
}

install_binary_release() {
  require_cmd curl
  require_cmd tar
  require_cmd shasum

  local arch tag base_url asset_name checksum_name tmpdir tarball checksums expected actual
  arch="$(arch_name)"

  tag="$(resolve_release_tag)"
  ensure_paid_release_token "$tag"

  base_url="$(release_base_url_for_tag "$tag")"
  asset_name="ferrocrate-${tag}-macos-${arch}.tar.gz"
  checksum_name="ferrocrate-${tag}-checksums.txt"
  if [[ "$RELEASE_CHANNEL" == "paid" ]]; then
    checksum_name="ferrocrate-${tag}-paid-checksums.txt"
  fi

  tmpdir="$(mktemp -d)"
  trap "rm -rf '$tmpdir'" EXIT

  tarball="$tmpdir/$asset_name"
  checksums="$tmpdir/$checksum_name"

  echo "downloading: $asset_name"
  if [[ "$RELEASE_CHANNEL" == "paid" ]]; then
    curl -fL \
      -H "Authorization: Bearer $PAID_RELEASE_TOKEN" \
      -H "X-Ferrocrate-Channel: paid" \
      "$base_url/$asset_name" \
      -o "$tarball"
  else
    curl -fL "$base_url/$asset_name" -o "$tarball"
  fi

  echo "downloading: $checksum_name"
  if [[ "$RELEASE_CHANNEL" == "paid" ]]; then
    curl -fL \
      -H "Authorization: Bearer $PAID_RELEASE_TOKEN" \
      -H "X-Ferrocrate-Channel: paid" \
      "$base_url/$checksum_name" \
      -o "$checksums"
  else
    curl -fL "$base_url/$checksum_name" -o "$checksums"
  fi

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
  trap "rm -rf '$tmpdir'" EXIT

  echo "cloning repository: https://github.com/${REPO}.git"
  git clone "https://github.com/${REPO}.git" "$tmpdir/src" --depth 1
  if [[ "$VERSION" != "latest" ]]; then
    (cd "$tmpdir/src" && git fetch --tags --depth 1 && git checkout "$VERSION")
    RESOLVED_RELEASE_TAG="$VERSION"
  fi

  local build_packages=(-p ferro-cli)
  if [[ "$INSTALL_DESKTOP_BIN" == "1" ]]; then
    build_packages+=(-p ferro-desktop)
  fi
  (cd "$tmpdir/src" && cargo build --release "${build_packages[@]}")

  mkdir -p "$tmpdir/unpack"
  cp "$tmpdir/src/target/release/ferro-cli" "$tmpdir/unpack/ferrocrate"
  if [[ "$INSTALL_DESKTOP_BIN" == "1" && -f "$tmpdir/src/target/release/ferro-desktop" ]]; then
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
  if [[ "$INSTALL_DESKTOP_BIN" == "1" && -n "$desktop_src" ]]; then
    install_file "$desktop_src" "$PREFIX/ferro-desktop"
  elif [[ "$INSTALL_DESKTOP_BIN" == "1" ]]; then
    echo "desktop binary requested but artifact did not contain ferro-desktop; use --channel paid with valid PAID_RELEASE_BASE_URL or install from source" >&2
    exit 1
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
  # vfkit is the preferred Apple Virtualization.framework launcher. QEMU is
  # installed as the portable fallback for Intel hosts and hosts where nested
  # virtualization is unavailable.
  if ! command -v vfkit >/dev/null 2>&1; then
    brew install vfkit || true
  fi
  brew_install_if_missing qemu-img qemu
  brew_install_if_missing socat socat
  case "$(arch_name)" in
    aarch64)
      brew_install_if_missing qemu-system-aarch64 qemu
      ;;
    x86_64)
      brew_install_if_missing qemu-system-x86_64 qemu
      ;;
  esac
  if ! command -v virtiofsd >/dev/null 2>&1; then
    local qemu_prefix qemu_virtiofsd
    qemu_prefix="$(brew --prefix qemu)"
    qemu_virtiofsd="$qemu_prefix/libexec/virtiofsd"
    if [[ -x "$qemu_virtiofsd" ]]; then
      mkdir -p "$PREFIX"
      ln -sf "$qemu_virtiofsd" "$PREFIX/virtiofsd"
    fi
  fi
  command -v virtiofsd >/dev/null 2>&1 || {
    echo "missing required command: virtiofsd (install qemu failed to provide it)" >&2
    exit 1
  }
  # ssh client is usually preinstalled on macOS; install via brew if missing.
  if ! command -v ssh >/dev/null 2>&1; then
    brew install openssh
  fi
  command -v ssh >/dev/null 2>&1 || {
    echo "missing required command: ssh" >&2
    exit 1
  }
}

diagnose_virtualization() {
  if [[ "$(sysctl -n kern.hv_support 2>/dev/null || echo 0)" != "1" ]]; then
    echo "nested virtualization unavailable: kern.hv_support is not enabled; using QEMU software acceleration" >&2
    return 1
  fi
  return 0
}

vm_backend_for_host() {
  if command -v vfkit >/dev/null 2>&1 && diagnose_virtualization; then
    # The shared macos-vm backend launches vfkit first. The legacy vm command
    # remains the QEMU fallback used by this bootstrap when no vfkit kernel
    # bundle has been supplied.
    if [[ -n "${FERROCRATE_VFKIT_KERNEL:-}" && -n "${FERROCRATE_VFKIT_INITRD:-}" ]]; then
      echo "vfkit"
      return
    fi
    echo "vfkit is available but no kernel bundle was supplied; using QEMU fallback" >&2
  fi
  if [[ "$(uname -m)" == "x86_64" ]]; then
    if diagnose_virtualization; then
      echo "qemu-x86_64"
    else
      echo "qemu-tcg-x86_64"
    fi
  else
    if diagnose_virtualization; then
      echo "qemu-hvf"
    else
      echo "qemu-tcg-aarch64"
    fi
  fi
}

start_vfkit_vm() {
  local disk="$1" cloud_init="$2"
  vfkit \
    --cpus 4 \
    --memory 4096 \
    --bootloader "linux,kernel=${FERROCRATE_VFKIT_KERNEL},initrd=${FERROCRATE_VFKIT_INITRD},cmdline=console=hvc0 root=/dev/vda1" \
    --device "virtio-blk,path=${disk}" \
    --device "virtio-blk,path=${cloud_init}" \
    --device "virtio-fs,sharedDir=${VM_HOST_SHARE},mountTag=ferrocrate" \
    --device "virtio-net,nat,mac=${VFKIT_MAC}" \
    >"${VM_DIR}/vfkit.log" 2>&1 &
  echo $! >"${VM_DIR}/vfkit.pid"
}

vfkit_guest_address() {
  awk -v mac="$VFKIT_MAC" '
    BEGIN { RS = "}" }
    index(tolower($0), tolower(mac)) {
      if (match($0, /ip_address=[0-9.]+/)) {
        value = substr($0, RSTART, RLENGTH)
        sub(/^ip_address=/, "", value)
        print value
        exit
      }
    }
  ' /var/db/dhcpd_leases 2>/dev/null
}

start_vfkit_ssh_forward() {
  local guest_ip="" pidfile="$VM_DIR/vfkit-ssh-forward.pid" started now
  started="$(date +%s)"
  while [[ -z "$guest_ip" ]]; do
    guest_ip="$(vfkit_guest_address)"
    now="$(date +%s)"
    if (( now - started >= 120 )); then
      echo "vfkit guest address was not recorded in /var/db/dhcpd_leases" >&2
      return 1
    fi
    [[ -n "$guest_ip" ]] || sleep 2
  done
  socat "TCP-LISTEN:${VM_SSH_PORT},bind=127.0.0.1,reuseaddr,fork" "TCP:${guest_ip}:22" &
  echo $! >"$pidfile"
}

start_guest_socket_forward() {
  local pidfile="$VM_DIR/socket-forward.pid"
  if [[ -s "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    return
  fi
  ssh -N \
    -i "$VM_SSH_KEY_PATH" \
    -p "$VM_SSH_PORT" \
    -o ExitOnForwardFailure=yes \
    -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$VM_KNOWN_HOSTS_PATH" \
    -L "127.0.0.1:${VM_API_PORT}:${VM_GUEST_SOCKET}" \
    "${VM_GUEST_USER}@127.0.0.1" &
  echo $! >"$pidfile"
}

base_cloud_image_url() {
  case "$(arch_name)" in
    aarch64)
      echo "https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-arm64.img"
      ;;
    x86_64)
      echo "https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-amd64.img"
      ;;
    *)
      echo "unsupported architecture for vm image" >&2
      exit 1
      ;;
  esac
}

prepare_vm_image() {
  local backend="$1" base_url base_img cache_dir
  cache_dir="$VM_DIR/cache"
  base_url="$(base_cloud_image_url)"
  base_img="$cache_dir/base-cloudimg.qcow2"

  mkdir -p "$VM_DIR" "$cache_dir"
  if [[ ! -f "$base_img" ]]; then
    echo "downloading desktop VM base image..."
    curl -fL "$base_url" -o "$base_img"
  fi

  if [[ "$backend" == "vfkit" ]]; then
    VM_DISK_PATH="${VM_DISK_PATH_OVERRIDE:-$VM_DIR/ferrocrate-desktop.raw}"
    if [[ ! -f "$VM_DISK_PATH" ]]; then
      echo "creating raw vfkit desktop VM disk at $VM_DISK_PATH..."
      qemu-img convert -O raw "$base_img" "$VM_DISK_PATH"
      qemu-img resize "$VM_DISK_PATH" "${VM_SIZE_GB}G" >/dev/null
    else
      echo "reusing existing vfkit VM disk: $VM_DISK_PATH"
    fi
  elif [[ ! -f "$VM_DISK_PATH" ]]; then
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
  local tmpdir user_data meta_data pubkey release_tag guest_release_base_url guest_curl_auth
  tmpdir="$(mktemp -d)"
  pubkey="$(cat "${VM_SSH_KEY_PATH}.pub")"
  release_tag="$(resolve_release_tag)"
  guest_release_base_url="$(release_base_url_for_tag "$release_tag")"
  guest_curl_auth=""
  if [[ "$RELEASE_CHANNEL" == "paid" ]]; then
    ensure_paid_release_token "$release_tag"
    guest_curl_auth="-H 'Authorization: Bearer ${PAID_RELEASE_TOKEN}' -H 'X-Ferrocrate-Channel: paid'"
  fi
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
  - [ bash, -lc, "set -euo pipefail; arch=\$(uname -m); case \$arch in aarch64|arm64) fc_arch=aarch64 ;; x86_64|amd64) fc_arch=x86_64 ;; *) exit 0 ;; esac; tag='${release_tag}'; asset=\"ferrocrate-\${tag}-linux-\${fc_arch}.tar.gz\"; url=\"${guest_release_base_url}/\${asset}\"; tmp=/tmp/ferrocrate-install; rm -rf \"\$tmp\"; mkdir -p \"\$tmp\"; curl -fL ${guest_curl_auth} \"\$url\" -o \"\$tmp/pkg.tgz\"; tar -xzf \"\$tmp/pkg.tgz\" -C \"\$tmp\"; if [ -f \"\$tmp/ferrocrate\" ]; then install -m 0755 \"\$tmp/ferrocrate\" /usr/local/bin/ferrocrate; elif [ -f \"\$tmp/ferro-cli\" ]; then install -m 0755 \"\$tmp/ferro-cli\" /usr/local/bin/ferrocrate; fi; if [ -f \"\$tmp/ferro-desktop\" ]; then install -m 0755 \"\$tmp/ferro-desktop\" /usr/local/bin/ferro-desktop; fi" ]
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
    -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$VM_KNOWN_HOSTS_PATH" \
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
  local tag install_cmd fallback_cmd guest_release_base_url guest_curl_auth
  if guest_ssh "command -v ferrocrate >/dev/null"; then
    echo "guest ferrocrate runtime is installed"
    return
  fi

  tag="$(resolve_release_tag)"
  guest_release_base_url="$(release_base_url_for_tag "$tag")"
  guest_curl_auth=""
  if [[ "$RELEASE_CHANNEL" == "paid" ]]; then
    ensure_paid_release_token "$tag"
    guest_curl_auth="-H 'Authorization: Bearer ${PAID_RELEASE_TOKEN}' -H 'X-Ferrocrate-Channel: paid'"
  fi
  echo "guest runtime missing, installing ferrocrate in VM..."
  install_cmd="set -euo pipefail; arch=\$(uname -m); case \$arch in aarch64|arm64) fc_arch=aarch64 ;; x86_64|amd64) fc_arch=x86_64 ;; *) echo unsupported_arch:\$arch >&2; exit 1 ;; esac; asset='ferrocrate-${tag}-linux-'\${fc_arch}'.tar.gz'; url='${guest_release_base_url}/'\${asset}; tmp=/tmp/ferrocrate-install-host; rm -rf \"\$tmp\"; mkdir -p \"\$tmp\"; curl -fL ${guest_curl_auth} \"\$url\" -o \"\$tmp/pkg.tgz\"; tar -xzf \"\$tmp/pkg.tgz\" -C \"\$tmp\"; if [ -f \"\$tmp/ferrocrate\" ]; then sudo install -m 0755 \"\$tmp/ferrocrate\" /usr/local/bin/ferrocrate; elif [ -f \"\$tmp/ferro-cli\" ]; then sudo install -m 0755 \"\$tmp/ferro-cli\" /usr/local/bin/ferrocrate; else echo no_ferrocrate_binary >&2; exit 1; fi; if [ -f \"\$tmp/ferro-desktop\" ]; then sudo install -m 0755 \"\$tmp/ferro-desktop\" /usr/local/bin/ferro-desktop; fi"
  if ! guest_ssh "$install_cmd"; then
    echo "guest prebuilt artifacts unavailable for ${tag}; building from source in guest..."
    fallback_cmd="set -euo pipefail; tmp=/tmp/ferrocrate-source-build; rm -rf \"\$tmp\"; mkdir -p \"\$tmp\"; sudo apt-get update; sudo apt-get install -y build-essential pkg-config libssl-dev curl ca-certificates git; if ! command -v cargo >/dev/null 2>&1; then curl https://sh.rustup.rs -sSf | sh -s -- -y; fi; . \"\$HOME/.cargo/env\"; src=\"\$tmp/src\"; if [ '${tag}' = 'latest' ]; then git clone --depth 1 https://github.com/${REPO}.git \"\$src\"; else git clone --depth 1 --branch '${tag}' https://github.com/${REPO}.git \"\$src\"; fi; cd \"\$src\"; cargo build --release -p ferro-cli -p ferro-desktop; if [ -f target/release/ferro-cli ]; then sudo install -m 0755 target/release/ferro-cli /usr/local/bin/ferrocrate; elif [ -f target/release/ferrocrate ]; then sudo install -m 0755 target/release/ferrocrate /usr/local/bin/ferrocrate; else echo missing_guest_cli_binary >&2; exit 1; fi; if [ -f target/release/ferro-desktop ]; then sudo install -m 0755 target/release/ferro-desktop /usr/local/bin/ferro-desktop; fi"
    guest_ssh "$fallback_cmd"
  fi
  guest_ssh "command -v ferrocrate >/dev/null"
}

ensure_guest_daemon_running() {
  local service_cmd
  service_cmd="set -euo pipefail; sudo install -d -o '${VM_GUEST_USER}' -g '${VM_GUEST_USER}' '/home/${VM_GUEST_USER}/.local/state/ferrocrate'; printf '%s\\n' '[Unit]' 'Description=FerroCrate guest daemon' 'After=network-online.target' '' '[Service]' 'Type=simple' 'User=${VM_GUEST_USER}' 'Environment=HOME=/home/${VM_GUEST_USER}' 'ExecStart=/usr/local/bin/ferrocrate daemon --socket ${VM_GUEST_SOCKET} --docker-compat' 'Restart=on-failure' 'RestartSec=2' '' '[Install]' 'WantedBy=multi-user.target' | sudo tee /etc/systemd/system/ferrocrate.service >/dev/null; sudo systemctl daemon-reload; sudo systemctl enable --now ferrocrate.service; sudo systemctl is-active --quiet ferrocrate.service"
  guest_ssh "$service_cmd"
}

bootstrap_desktop_vm() {
  local ferro_desktop vm_backend
  local -a vm_init_args
  ferro_desktop="$PREFIX/ferro-desktop"
  [[ -x "$ferro_desktop" ]] || ferro_desktop="$(command -v ferro-desktop || true)"
  if [[ -z "$ferro_desktop" || ! -x "$ferro_desktop" ]]; then
    echo "ferro-desktop binary not found after install" >&2
    exit 1
  fi

  vm_backend="$(vm_backend_for_host)"
  mkdir -p "$VM_STATE_DIR"
  rm -f "$VM_KNOWN_HOSTS_PATH"
  prepare_vm_image "$vm_backend"
  generate_vm_ssh_key
  generate_cloud_init_seed
  echo "initializing desktop VM state..."
  vm_init_args=(
    vm --state-file "$VM_STATE_FILE" init
    --backend "$vm_backend"
    --disk-path "$VM_DISK_PATH"
    --host-share-path "$VM_HOST_SHARE"
    --fs-backend virtiofs
    --ssh-port "$VM_SSH_PORT"
    --api-port "$VM_API_PORT"
    --guest-user "$VM_GUEST_USER"
    --ssh-private-key-path "$VM_SSH_KEY_PATH"
    --cloud-init-image-path "$VM_CLOUD_INIT_PATH"
  )
  if [[ "$vm_backend" == "vfkit" ]]; then
    vm_init_args+=(
      --vfkit-kernel-path "$FERROCRATE_VFKIT_KERNEL"
      --vfkit-initrd-path "$FERROCRATE_VFKIT_INITRD"
      --vfkit-mac "$VFKIT_MAC"
    )
  fi
  "$ferro_desktop" "${vm_init_args[@]}" >/dev/null

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
  ensure_guest_daemon_running
  start_guest_socket_forward
}

main() {
  parse_args "$@"
  ensure_macos

  if [[ "$FULL_STACK" == "1" ]]; then
    if [[ "$RELEASE_CHANNEL" == "public" ]]; then
      echo "--full-stack requires --channel paid (desktop artifacts are paid-channel only)" >&2
      exit 1
    fi
    INSTALL_DESKTOP_BIN="1"
    DESKTOP_BOOTSTRAP="1"
  elif [[ "$RELEASE_CHANNEL" == "paid" && "$DESKTOP_BIN_SET" == "0" && "$DESKTOP_BOOTSTRAP_SET" == "0" ]]; then
    # Paid channel defaults to one-command full setup unless explicitly overridden.
    INSTALL_DESKTOP_BIN="1"
    DESKTOP_BOOTSTRAP="1"
  fi

  if [[ "$DESKTOP_BOOTSTRAP" == "1" && "$INSTALL_DESKTOP_BIN" != "1" ]]; then
    echo "--with-desktop-bootstrap requires --with-desktop-bin" >&2
    exit 1
  fi
  if [[ "$RELEASE_CHANNEL" != "public" && "$RELEASE_CHANNEL" != "paid" ]]; then
    echo "invalid --channel: $RELEASE_CHANNEL (expected public or paid)" >&2
    exit 1
  fi

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

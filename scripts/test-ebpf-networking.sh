#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'eBPF networking qualification failed: %s\n' "$*" >&2; exit 1; }
[[ "$(uname -s)" == Linux ]] || fail "Linux is required"
[[ "${EUID}" -eq 0 ]] || fail "run with sudo"
command -v timeout >/dev/null 2>&1 || fail "timeout is required for bounded qualification"
command -v setsid >/dev/null 2>&1 || fail "setsid is required for process-group cleanup"

step_timeout="${FERROCRATE_EBPF_STEP_TIMEOUT:-45}"
[[ "$step_timeout" =~ ^[1-9][0-9]*$ ]] || fail "FERROCRATE_EBPF_STEP_TIMEOUT must be a positive integer"
(( step_timeout <= 600 )) || fail "FERROCRATE_EBPF_STEP_TIMEOUT must be <= 600 seconds"
run_bounded() {
  # Cargo can leave the ignored integration child alive after a plain timeout,
  # retaining pinned classifiers while the parent has already returned. Run
  # each step in its own process group and terminate the whole group on expiry.
  local command_pid status timed_out=0 deadline=$((SECONDS + step_timeout))
  setsid "$@" &
  command_pid=$!
  while kill -0 "$command_pid" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      timed_out=1
      kill -TERM -- "-${command_pid}" 2>/dev/null || true
      for _ in $(seq 1 20); do
        kill -0 "$command_pid" 2>/dev/null || break
        sleep 0.1
      done
      kill -KILL -- "-${command_pid}" 2>/dev/null || true
      break
    fi
    sleep 0.1
  done
  if wait "$command_pid"; then
    status=0
  else
    status=$?
  fi
  if (( timed_out )); then
    printf 'eBPF qualification step timed out after %ss: %s\n' "$step_timeout" "$*" >&2
    return 124
  fi
  return "$status"
}

# sudo's secure_path commonly hides the operator's Rustup shim. Resolve the
# invoking user's Cargo explicitly so the privileged fixture does not fail
# before it reaches any kernel qualification, while still allowing callers to
# choose a pinned binary through FERROCRATE_CARGO_BIN.
if [[ -z "${FERROCRATE_CARGO_BIN:-}" ]]; then
  if command -v cargo >/dev/null 2>&1; then
    FERROCRATE_CARGO_BIN="$(command -v cargo)"
  elif [[ -n "${SUDO_USER:-}" ]] && command -v getent >/dev/null 2>&1; then
    operator_home="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
    if [[ -n "${operator_home}" && -x "${operator_home}/.cargo/bin/cargo" ]]; then
      FERROCRATE_CARGO_BIN="${operator_home}/.cargo/bin/cargo"
      export CARGO_HOME="${CARGO_HOME:-${operator_home}/.cargo}"
      export RUSTUP_HOME="${RUSTUP_HOME:-${operator_home}/.rustup}"
    fi
  fi
fi
[[ -n "${FERROCRATE_CARGO_BIN:-}" && -x "${FERROCRATE_CARGO_BIN}" ]] \
  || fail "cargo is required (set FERROCRATE_CARGO_BIN or expose the operator's Rustup shim)"
command -v tc >/dev/null || fail "tc is required"
mountpoint -q /sys/fs/bpf || fail "bpffs must be mounted at /sys/fs/bpf"

IFS=. read -r kernel_major kernel_minor _ <<<"$(uname -r)"
(( kernel_major > 5 || (kernel_major == 5 && kernel_minor >= 10) )) \
  || fail "kernel 5.10+ is required"

: "${FERRO_EBPF_TEST_INTERFACE:?set the host interface used for qualification}"
: "${FERRO_EBPF_TEST_IFINDEX:?set the matching host interface ifindex}"
: "${FERRO_EBPF_TEST_EXTERNAL_IPV4:?set the matching external IPv4 address}"
: "${FERRO_EBPF_TEST_NEXT_HOP_MAC:?set the route next-hop MAC address}"
: "${FERRO_EBPF_TEST_SNAT_START:?set a reserved SNAT range start}"
: "${FERRO_EBPF_TEST_SNAT_END:?set a reserved SNAT range end}"

export FERRO_EBPF_TEST_NETWORK_ID="ferro-qualify-$$"
# Give each live probe a unique bridge/network identity. A timed-out cargo
# child may leave a classifier briefly visible; reusing the fixed `ferro0`
# identity would make the next probe fail closed against that prior run.
export FERROCRATE_BRIDGE_NAME="fep-$((BASHPID % 100000))"
export FERROCRATE_BRIDGE_CIDR="10.77.$((BASHPID % 200 + 20)).1/24"
export FERROCRATE_E2E_NETWORK_BACKEND=ebpf
# This gate intentionally exercises the experimental published-port path;
# production remains fail-closed until the live checksum/redirect qualification
# succeeds.  Without the opt-in, the e2e fixture exits before attaching the
# datapath and the privileged probe gives a false negative.
export FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS=1
export FERROCRATE_EBPF_SNAT_PORT_RANGE="${FERRO_EBPF_TEST_SNAT_START}-${FERRO_EBPF_TEST_SNAT_END}"
# Set FERROCRATE_EBPF_DISABLE_PROBE_VETH_OFFLOADS=1 for an A/B diagnostic.
# Only veths created after probe entry are changed; production defaults remain
# untouched and cleanup removes those owned interfaces.
pin_root_before="$(find /sys/fs/bpf/ferrocrate -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null || true)"
netns_before="$(ip netns list 2>/dev/null | awk '$1 ~ /^ferro-/ { print $1 }' | sort || true)"
veth_before="$(ip -o link show master "$FERROCRATE_BRIDGE_NAME" 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | sort || true)"
lo_ingress_before="$(tc filter show dev lo ingress 2>/dev/null || true)"
lo_egress_before="$(tc filter show dev lo egress 2>/dev/null || true)"
external_ingress_before="$(tc filter show dev "$FERRO_EBPF_TEST_INTERFACE" ingress 2>/dev/null || true)"
external_egress_before="$(tc filter show dev "$FERRO_EBPF_TEST_INTERFACE" egress 2>/dev/null || true)"
before_iptables="$(mktemp)"
before_nft="$(mktemp)"
after_iptables="$(mktemp)"
after_nft="$(mktemp)"
redirect_diagnostics="$(mktemp)"
offload_diagnostics="$(mktemp)"
redirect_sampler_pid=""
packet_capture="$(mktemp)"
loopback_ingress_capture="$(mktemp)"
loopback_egress_capture="$(mktemp)"
packet_capture_pid=""
loopback_ingress_capture_pid=""
loopback_egress_capture_pid=""
checksum_errors_before="$(nstat -as 2>/dev/null | awk '$1 == "TcpInCsumErrors" { print $2; found=1 } END { if (!found) print 0 }')"
diagnostics_output_dir="${FERROCRATE_EBPF_DIAGNOSTICS_DIR:-}"
reserved_ports_path="/proc/sys/net/ipv4/ip_local_reserved_ports"
reserved_ports_before="$(cat "$reserved_ports_path" 2>/dev/null || true)"
reserved_ports_changed=0
# The eBPF published-port reverse path injects 127/8-sourced replies onto host
# loopback; the kernel's input route lookup drops them as martian unless
# loopback route_localnet is enabled. Qualification enables it for the run and
# restores the exact prior value in the EXIT trap.
route_localnet_path="/proc/sys/net/ipv4/conf/lo/route_localnet"
route_localnet_before="$(cat "$route_localnet_path" 2>/dev/null || true)"
route_localnet_changed=0
if [[ "$route_localnet_before" != "1" ]]; then
  printf '1\n' >"$route_localnet_path"     || fail "could not enable net.ipv4.conf.lo.route_localnet for eBPF published-port qualification"
  route_localnet_changed=1
fi
cleanup() {
  if [[ -n "$redirect_sampler_pid" ]]; then
    kill "$redirect_sampler_pid" 2>/dev/null || true
    wait "$redirect_sampler_pid" 2>/dev/null || true
  fi
  if [[ -n "$packet_capture_pid" ]]; then
    kill "$packet_capture_pid" 2>/dev/null || true
    wait "$packet_capture_pid" 2>/dev/null || true
  fi
  for capture_pid in "$loopback_ingress_capture_pid" "$loopback_egress_capture_pid"; do
    if [[ -n "$capture_pid" ]]; then
      kill "$capture_pid" 2>/dev/null || true
      wait "$capture_pid" 2>/dev/null || true
    fi
  done
  if [[ "$route_localnet_changed" -eq 1 ]]; then
    printf '%s\n' "$route_localnet_before" >"$route_localnet_path" 2>/dev/null || true
  fi
  if [[ "$reserved_ports_changed" -eq 1 ]]; then
    printf '%s\n' "$reserved_ports_before" >"$reserved_ports_path" || true
  fi
  rm -f "$before_iptables" "$before_nft" "$after_iptables" "$after_nft" \
    "$redirect_diagnostics" "$offload_diagnostics" "$packet_capture" \
    "$loopback_ingress_capture" "$loopback_egress_capture"
  while IFS= read -r pin_name; do
    [[ -n "$pin_name" ]] || continue
    if ! grep -Fqx "$pin_name" <<<"$pin_root_before"; then
      pin_path="/sys/fs/bpf/ferrocrate/$pin_name"
      find "$pin_path" -type f -delete 2>/dev/null || true
      find "$pin_path" -depth -type d -empty -delete 2>/dev/null || true
    fi
  done < <(find /sys/fs/bpf/ferrocrate -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort)
  # A failed attach can leave the two loopback classifiers live even after
  # their pin directory is gone. Remove only the exact qualification filters
  # when no ferro classifier existed on that hook at entry.
  if ! grep -q 'ferro_ingress' <<<"$lo_ingress_before" &&
     grep -q 'ferro_ingress' <<<"$(tc filter show dev lo ingress 2>/dev/null || true)"; then
    tc filter del dev lo ingress pref 49152 handle 1 bpf 2>/dev/null || true
  fi
  if ! grep -q 'ferro_egress' <<<"$lo_egress_before" &&
     grep -q 'ferro_egress' <<<"$(tc filter show dev lo egress 2>/dev/null || true)"; then
    tc filter del dev lo egress pref 49152 handle 1 bpf 2>/dev/null || true
  fi
  if ! grep -q 'ferro_ingress' <<<"$external_ingress_before" &&
     grep -q 'ferro_ingress' <<<"$(tc filter show dev "$FERRO_EBPF_TEST_INTERFACE" ingress 2>/dev/null || true)"; then
    tc filter del dev "$FERRO_EBPF_TEST_INTERFACE" ingress pref 49152 handle 1 bpf 2>/dev/null || true
  fi
  if ! grep -q 'ferro_egress' <<<"$external_egress_before" &&
     grep -q 'ferro_egress' <<<"$(tc filter show dev "$FERRO_EBPF_TEST_INTERFACE" egress 2>/dev/null || true)"; then
    tc filter del dev "$FERRO_EBPF_TEST_INTERFACE" egress pref 49152 handle 1 bpf 2>/dev/null || true
  fi
  # A failed e2e process can leave a PID-free namespace after its normal
  # runtime cleanup has already lost ownership metadata.  The qualification
  # harness owns only namespaces that did not exist at entry; remove those
  # exact ferro-* names so a later bounded probe cannot inherit partial tc
  # state.  Never touch pre-existing namespaces.
  while IFS= read -r netns_name; do
    [[ -n "$netns_name" ]] || continue
    if ! grep -Fqx "$netns_name" <<<"$netns_before"; then
      if [[ -z "$(ip netns pids "$netns_name" 2>/dev/null || true)" ]]; then
        ip netns del "$netns_name" 2>/dev/null || true
      fi
    fi
  done < <(ip netns list 2>/dev/null | awk '$1 ~ /^ferro-/ { print $1 }' | sort)
  # Deleting an orphaned netns can leave its host-side veth with an invalid
  # peer reference. Remove only veths that were absent at probe entry and no
  # longer name a live ferro-* peer; pre-existing interfaces are untouched.
  while IFS= read -r veth_name; do
    [[ -n "$veth_name" ]] || continue
    if ! grep -Fqx "$veth_name" <<<"$veth_before"; then
      link_state="$(ip -o link show dev "$veth_name" 2>/dev/null || true)"
      if grep -q 'link-netnsid' <<<"$link_state" && ! grep -q 'link-netns ferro-' <<<"$link_state"; then
        ip link delete "$veth_name" 2>/dev/null || true
      fi
    fi
  done < <(ip -o link show master "$FERROCRATE_BRIDGE_NAME" 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | sort)
  if [[ -n "${FERROCRATE_BRIDGE_NAME:-}" ]]; then
    ip link delete "$FERROCRATE_BRIDGE_NAME" 2>/dev/null || true
  fi
}
trap cleanup EXIT

sample_redirect_diagnostics() {
  while :; do
    if [[ "${FERROCRATE_EBPF_DISABLE_PROBE_VETH_OFFLOADS:-0}" == 1 ]] &&
       command -v ethtool >/dev/null 2>&1; then
      while IFS= read -r interface; do
        [[ -n "$interface" ]] || continue
        if ! grep -Fqx "$interface" <<<"$veth_before"; then
          ethtool -K "$interface" rx off tx off tso off gso off gro off >/dev/null 2>&1 || true
        fi
      done < <(ip -o link show type veth 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1)
    fi
    printf '\n--- %s ---\n' "$(date --iso-8601=seconds)"
    for interface in $(ip -o link show type veth 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
      printf 'tc ingress %s:\n' "$interface"
      tc -s filter show dev "$interface" ingress 2>/dev/null || true
      printf 'tc egress %s:\n' "$interface"
      tc -s filter show dev "$interface" egress 2>/dev/null || true
    done
    printf 'tc ingress lo:\n'
    tc -s filter show dev lo ingress 2>/dev/null || true
    printf 'tc egress lo:\n'
    tc -s filter show dev lo egress 2>/dev/null || true
    # The e2e fixture performs ownership cleanup before returning a failure,
    # so a post-failure dump can miss the maps entirely. Poll the pinned
    # counter map while classifiers are live to preserve disposition evidence.
    if command -v bpftool >/dev/null 2>&1; then
      while IFS= read -r counters_path; do
        [[ -n "$counters_path" ]] || continue
        printf 'counter map %s:\n' "$counters_path"
        bpftool map dump pinned "$counters_path" 2>/dev/null || true
      done < <(find /sys/fs/bpf/ferrocrate -mindepth 3 -maxdepth 3 -path '*/maps/FERRO_COUNTERS' 2>/dev/null)
    fi
    sleep 0.2
  done
}

dump_redirect_diagnostics() {
  printf '%s\n' '--- eBPF redirect diagnostics sampled during qualification ---' >&2
  tail -n 300 "$redirect_diagnostics" >&2 || true
  printf '%s\n' '--- eBPF decision counters ---' >&2
  if command -v bpftool >/dev/null 2>&1; then
    while IFS= read -r counters_path; do
      pin_name="$(basename "$(dirname "$(dirname "$counters_path")")")"
      if grep -Fqx "$pin_name" <<<"$pin_root_before"; then
        continue
      fi
      printf 'counter map %s:\n' "$counters_path" >&2
      bpftool map dump pinned "$counters_path" 2>&1 || true
    # Pinned bpffs maps are not guaranteed to report as regular files across
    # kernels/filesystem implementations; match the exact pin path instead.
    done < <(find /sys/fs/bpf/ferrocrate -mindepth 3 -maxdepth 3 -path '*/maps/FERRO_COUNTERS' 2>/dev/null)
  fi
  printf '%s\n' '--- packet/checksum diagnostics ---' >&2
  printf '%s\n' '--- interface offload diagnostics ---' >&2
  cat "$offload_diagnostics" >&2 || true
  printf 'TcpInCsumErrors before=%s after=%s\n' "$checksum_errors_before" \
    "$(nstat -as 2>/dev/null | awk '$1 == "TcpInCsumErrors" { print $2; found=1 } END { if (!found) print 0 }')" >&2
  if [[ -s "$packet_capture" ]]; then
    tail -n 120 "$packet_capture" >&2 || true
  fi
  if [[ -s "$loopback_ingress_capture" ]]; then
    printf '%s\n' '--- loopback ingress capture ---' >&2
    tail -n 120 "$loopback_ingress_capture" >&2 || true
  fi
  if [[ -s "$loopback_egress_capture" ]]; then
    printf '%s\n' '--- loopback egress capture ---' >&2
    tail -n 120 "$loopback_egress_capture" >&2 || true
  fi
  if [[ -n "$diagnostics_output_dir" ]]; then
    mkdir -p "$diagnostics_output_dir"
    cp "$redirect_diagnostics" "$diagnostics_output_dir/redirect-samples.log"
    cp "$offload_diagnostics" "$diagnostics_output_dir/offload-features.log"
    cp "$packet_capture" "$diagnostics_output_dir/any-capture.log"
    cp "$loopback_ingress_capture" "$diagnostics_output_dir/loopback-ingress.log"
    cp "$loopback_egress_capture" "$diagnostics_output_dir/loopback-egress.log"
    printf 'before=%s\nafter=%s\n' "$checksum_errors_before" \
      "$(nstat -as 2>/dev/null | awk '$1 == "TcpInCsumErrors" { print $2; found=1 } END { if (!found) print 0 }')" \
      >"$diagnostics_output_dir/checksum-errors.txt"
    printf 'saved eBPF diagnostics to %s\n' "$diagnostics_output_dir" >&2
  fi
}

snapshot_offloads() {
  local label="$1" device
  shift
  printf '## %s\n' "$label" >>"$offload_diagnostics"
  for device in "$@"; do
    [[ -n "$device" ]] || continue
    printf '[%s]\n' "$device" >>"$offload_diagnostics"
    if command -v ethtool >/dev/null 2>&1 && ip link show dev "$device" >/dev/null 2>&1; then
      ethtool -k "$device" >>"$offload_diagnostics" 2>&1 || true
    else
      printf 'ethtool-unavailable-or-device-missing\n' >>"$offload_diagnostics"
    fi
  done
}

# The eBPF loader refuses to allocate a SNAT port unless the complete range is
# reserved by the host. Qualification owns only the explicit test range and
# restores the exact prior sysctl value in the EXIT trap.
reserved_ports_value="$reserved_ports_before"
case ",$reserved_ports_before," in
  *",${FERRO_EBPF_TEST_SNAT_START}-${FERRO_EBPF_TEST_SNAT_END},"*) ;;
  *)
    if [[ -n "$reserved_ports_value" ]]; then
      reserved_ports_value+=","
    fi
    reserved_ports_value+="${FERRO_EBPF_TEST_SNAT_START}-${FERRO_EBPF_TEST_SNAT_END}"
    printf '%s\n' "$reserved_ports_value" >"$reserved_ports_path" \
      || fail "could not reserve SNAT range ${FERRO_EBPF_TEST_SNAT_START}-${FERRO_EBPF_TEST_SNAT_END}"
    reserved_ports_changed=1
    ;;
esac

iptables-save >"$before_iptables" 2>/dev/null || true
nft list ruleset >"$before_nft" 2>/dev/null || true
snapshot_offloads "before" "$FERRO_EBPF_TEST_INTERFACE" lo

run_bounded "${FERROCRATE_CARGO_BIN}" test -p ferro-net --test kernel_compat -- --ignored
run_bounded "${FERROCRATE_CARGO_BIN}" test -p ferro-net --test ebpf_integration privileged_aya_load_detach_smoke_deferred_to_task_7 -- --ignored
sample_redirect_diagnostics >"$redirect_diagnostics" 2>&1 &
redirect_sampler_pid=$!
if [[ "${FERRO_EBPF_CAPTURE:-0}" == "1" ]] && command -v tcpdump >/dev/null 2>&1; then
  capture_filter='tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack) != 0) and (host 127.0.0.1 or net 10.0.0.0/24)'
  tcpdump -i any -nn -vvv -l -s 0 "$capture_filter" >"$packet_capture" 2>&1 &
  packet_capture_pid=$!
  # Split loopback direction so a translated SYN-ACK observed on `any` can be
  # classified as ingress stack delivery versus egress redirect re-entry.
  tcpdump -Q in -i lo -nn -vvv -l -s 0 'tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack) != 0) and host 127.0.0.1' >"$loopback_ingress_capture" 2>&1 &
  loopback_ingress_capture_pid=$!
  tcpdump -Q out -i lo -nn -vvv -l -s 0 'tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack) != 0) and host 127.0.0.1' >"$loopback_egress_capture" 2>&1 &
  loopback_egress_capture_pid=$!
fi
if ! run_bounded "${FERROCRATE_CARGO_BIN}" test --test e2e_container_lifecycle -- --ignored ebpf_network_published_port_egress_without_netfilter_changes; then
  probe_devices=(lo "$FERROCRATE_BRIDGE_NAME")
  while IFS= read -r device; do
    [[ -n "$device" ]] && probe_devices+=("$device")
  done < <(ip -o link show type veth 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1)
  snapshot_offloads "after-failed-e2e" "${probe_devices[@]}"
  dump_redirect_diagnostics
  exit 1
fi

probe_devices=(lo "$FERROCRATE_BRIDGE_NAME")
while IFS= read -r device; do
  [[ -n "$device" ]] && probe_devices+=("$device")
done < <(ip -o link show type veth 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1)
snapshot_offloads "after-e2e" "${probe_devices[@]}"

iptables-save >"$after_iptables" 2>/dev/null || true
nft list ruleset >"$after_nft" 2>/dev/null || true
cmp -s "$before_iptables" "$after_iptables" || fail "iptables state changed in eBPF mode"
cmp -s "$before_nft" "$after_nft" || fail "nftables state changed in eBPF mode"
while IFS= read -r pin_name; do
  [[ -n "$pin_name" ]] || continue
  if ! grep -Fqx "$pin_name" <<<"$pin_root_before"; then
    fail "owned eBPF pins leaked: $pin_name"
  fi
done < <(find /sys/fs/bpf/ferrocrate -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort)

printf 'eBPF networking qualification passed\n'

#!/usr/bin/env bash
# Live diagnostics for the experimental eBPF published-port fixture.
# Run with sudo from the worktree root. All captures and traces go to /tmp
# (raw privileged diagnostics are never committed).
set -euo pipefail

cd /data/dev/ferrocrate/.worktrees/fcnet103-grok

# sudo resets the invoking user's Cargo/Rustup PATH. Keep the diagnostic
# runnable from a privileged shell without requiring operators to mutate PATH.
cargo_bin="${FERROCRATE_CARGO:-/home/USER/.cargo/bin/cargo}"
[[ -x "$cargo_bin" ]] || { echo "missing Cargo executable: $cargo_bin" >&2; exit 2; }
export CARGO_HOME="${CARGO_HOME:-/home/USER/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/home/USER/.rustup}"

if [[ "$(id -u)" != 0 ]]; then
    echo "live eBPF diagnostics require root; rerun with sudo (exit 77)" >&2
    exit 77
fi

fixture_timeout_seconds="${FERROCRATE_EBPF_FIXTURE_TIMEOUT_SECONDS:-90}"
[[ "$fixture_timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
    echo "FERROCRATE_EBPF_FIXTURE_TIMEOUT_SECONDS must be a positive integer" >&2
    exit 2
}

target_dir="${FERROCRATE_EBPF_TARGET_DIR:-}"
target_dir_owned=0
if [[ -z "$target_dir" ]]; then
    target_dir="$(mktemp -d /tmp/ferrocrate-ebpf-target.XXXXXX)"
    target_dir_owned=1
fi

for tool in tcpdump bpftrace nstat ip; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 2; }
done

STAMP=$(date +%Y%m%d-%H%M%S)
OUT=/tmp/ebpf-diag-$STAMP
mkdir -p "$OUT"

# The live fixture requires its SNAT allocator range to be reserved from the
# host ephemeral-port allocator. Restore the exact prior value on every exit.
snat_range="${FERROCRATE_EBPF_SNAT_PORT_RANGE:-50000-50031}"
reserved_ports_before="$(cat /proc/sys/net/ipv4/ip_local_reserved_ports)"
restore_reserved_ports() {
    sysctl -q -w "net.ipv4.ip_local_reserved_ports=$reserved_ports_before" >/dev/null 2>&1 || true
}
stop_capture_processes() {
    for pid in "${TCPD_PID:-}" "${LO_IN_PID:-}" "${LO_OUT_PID:-}" "${BT1:-}" "${BT2:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
}
cleanup() {
    restore_reserved_ports
    stop_capture_processes
    if [[ "$target_dir_owned" == 1 ]]; then
        # A timed cargo process can still be unwinding incremental writes when
        # EXIT runs. Cleanup is best-effort and must not mask the fixture's
        # actual exit status or leave the release gate hanging.
        rm -rf -- "$target_dir" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM
sysctl -q -w "net.ipv4.ip_local_reserved_ports=$snat_range"

echo "== sysctl snapshot ==" > "$OUT/sysctl.log"
sysctl -a 2>/dev/null | grep -E 'rp_filter|route_localnet|accept_local|log_martians' >> "$OUT/sysctl.log"
echo "== routes (all tables) ==" >> "$OUT/sysctl.log"
ip route show table all >> "$OUT/sysctl.log" 2>&1
echo "== policy rules ==" >> "$OUT/sysctl.log"
ip rule show >> "$OUT/sysctl.log" 2>&1
echo "== links before ==" >> "$OUT/sysctl.log"
ip -br link show >> "$OUT/sysctl.log" 2>&1
echo "== conntrack available ==" >> "$OUT/sysctl.log"
ls /proc/net/nf_conntrack >/dev/null 2>&1 && echo yes || echo no >> "$OUT/sysctl.log"

# Baseline kernel counters.
nstat -az > "$OUT/nstat-before.txt" 2>&1 || true
cat /proc/net/snmp > "$OUT/snmp-before.txt"
cat /proc/net/netstat > "$OUT/netstat-before.txt"

# Packet captures: "any" covers the veth ingress hop, while separate loopback
# direction captures distinguish the classifier's ingress handoff from a
# packet that actually leaves the loopback device.  This is important for the
# published-port failure: a translated SYN-ACK can be visible on lo without
# ever reaching the host TCP receive path.
tcpdump -i any -n -s 0 -w "$OUT/any.pcap" >/dev/null 2>&1 &
TCPD_PID=$!
tcpdump -i lo -Q in -n -s 0 -w "$OUT/lo-ingress.pcap" >/dev/null 2>&1 &
LO_IN_PID=$!
tcpdump -i lo -Q out -n -s 0 -w "$OUT/lo-egress.pcap" >/dev/null 2>&1 &
LO_OUT_PID=$!

# Snapshot TC counters around the fixture.  Keep this best-effort because
# minimal guests may not ship tc; the packet captures and tracepoints remain
# the authoritative artifacts in that case.
tc_snapshot() {
    local path="$1"
    {
        echo "== lo ingress =="
        tc -s filter show dev lo ingress 2>&1 || true
        echo "== lo egress =="
        tc -s filter show dev lo egress 2>&1 || true
        echo "== qdiscs =="
        tc -s qdisc show 2>&1 || true
    } > "$path"
}
tc_snapshot "$OUT/tc-before.log"

# Drop-site trace: skb:kfree_skb carries the kernel drop_reason enum. Include
# the skb delivery fields so a stack drop can be distinguished from a TC
# redirect that never reaches the host receive path.
bpftrace -e 'tracepoint:skb:kfree_skb { $s = (struct sk_buff *)args->skbaddr; printf("KFREE comm=%s dev=%s reason=%d sum=%d pkt=%d iif=%d proto=0x%x\n", comm, str($s->dev->name), args->reason, $s->ip_summed, $s->pkt_type, $s->skb_iif, $s->protocol); }' \
    > "$OUT/kfree.log" 2>&1 &
BT1=$!

# Receive-boundary trace: dev, length, checksum state, pkt_type, ingress ifindex.
bpftrace -e 'tracepoint:net:netif_receive_skb { $s = (struct sk_buff *)args->skbaddr; printf("RX dev=%s len=%u sum=%d pkt=%d iif=%d\n", str(args->name), args->len, $s->ip_summed, $s->pkt_type, $s->skb_iif); }' \
    > "$OUT/netif_rx.log" 2>&1 &
BT2=$!

# Let the tracepoints attach before traffic starts.
sleep 2

set +e
FERROCRATE_E2E_NETWORK_BACKEND=ebpf FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS=1 \
    FERROCRATE_EBPF_SNAT_PORT_RANGE="$snat_range" \
    CARGO_TARGET_DIR="$target_dir" \
    timeout --foreground --kill-after=10s "${fixture_timeout_seconds}s" \
    "$cargo_bin" test --test e2e_container_lifecycle \
    -- --ignored ebpf_network_published_port_egress_without_netfilter_changes --nocapture \
    2>&1 | tee "$OUT/fixture.log"
RC=${PIPESTATUS[0]}
set -e
echo "fixture exit: $RC" >> "$OUT/fixture.log"

# Capture classifier counters while the per-fixture links and filters still
# exist.  The post-cleanup snapshot below is retained as a baseline for
# teardown verification, but cannot explain a redirect that was dropped
# before cleanup detached its classifier.
tc_snapshot "$OUT/tc-during.log"

stop_capture_processes
wait "$TCPD_PID" "$LO_IN_PID" "$LO_OUT_PID" "$BT1" "$BT2" 2>/dev/null || true

tc_snapshot "$OUT/tc-after.log"

# After counters.
cat /proc/net/snmp > "$OUT/snmp-after.txt"
cat /proc/net/netstat > "$OUT/netstat-after.txt"
nstat -az > "$OUT/nstat-after.txt" 2>&1 || true

echo "artifacts in $OUT"
ls -la "$OUT"
exit "$RC"

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
trap restore_reserved_ports EXIT
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

# Packet captures: "any" covers the veth ingress hop, "lo" covers the
# redirected loopback ingress hop.
tcpdump -i any -n -s 0 -w "$OUT/any.pcap" >/dev/null 2>&1 &
TCPD_PID=$!
tcpdump -i lo -n -s 0 -w "$OUT/lo.pcap" >/dev/null 2>&1 &
LO_PID=$!

# Drop-site trace: skb:kfree_skb carries the kernel drop_reason enum.
bpftrace -e 'tracepoint:skb:kfree_skb { printf("KFREE dev=%s reason=%d\n", comm, args->reason); }' \
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
    "$cargo_bin" test --test e2e_container_lifecycle \
    -- --ignored ebpf_network_published_port_egress_without_netfilter_changes --nocapture \
    2>&1 | tee "$OUT/fixture.log"
RC=$?
set -e
echo "fixture exit: $RC" >> "$OUT/fixture.log"

kill "$TCPD_PID" "$LO_PID" "$BT1" "$BT2" 2>/dev/null || true
wait "$TCPD_PID" "$LO_PID" "$BT1" "$BT2" 2>/dev/null || true

# After counters.
cat /proc/net/snmp > "$OUT/snmp-after.txt"
cat /proc/net/netstat > "$OUT/netstat-after.txt"
nstat -az > "$OUT/nstat-after.txt" 2>&1 || true

echo "artifacts in $OUT"
ls -la "$OUT"

#!/usr/bin/env bash
# Live diagnostics for the experimental eBPF published-port fixture.
# Run with sudo from the worktree root. All captures and traces go to /tmp
# (raw privileged diagnostics are never committed).
set -euo pipefail

cd /data/dev/ferrocrate/.worktrees/fcnet103-grok

command -v setsid >/dev/null 2>&1 || {
    echo "live eBPF diagnostics require setsid for process-group cleanup" >&2
    exit 77
}

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

for tool in tcpdump bpftrace nstat ip df; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 2; }
done

# A fresh Cargo target for this diagnostic can consume several gigabytes. Do
# not start a compile when the target filesystem is already near exhaustion;
# repeated privileged probes must never be allowed to fill the host tmpfs.
min_free_kb="${FERROCRATE_EBPF_MIN_FREE_KB:-4194304}"
[[ "$min_free_kb" =~ ^[1-9][0-9]*$ ]] || {
    echo "FERROCRATE_EBPF_MIN_FREE_KB must be a positive integer" >&2
    exit 2
}
target_parent="$(dirname -- "$target_dir")"
available_kb="$(df -Pk "$target_parent" | awk 'NR == 2 { print $4 }')"
if [[ ! "$available_kb" =~ ^[0-9]+$ ]]; then
    if [[ "$target_dir_owned" == 1 ]]; then find "$target_dir" -depth -delete 2>/dev/null || true; fi
    echo "unable to determine free space for eBPF diagnostic target: $target_parent" >&2
    exit 77
fi
if (( available_kb < min_free_kb )); then
    if [[ "$target_dir_owned" == 1 ]]; then find "$target_dir" -depth -delete 2>/dev/null || true; fi
    echo "eBPF diagnostic skipped: ${available_kb} KiB free on $target_parent; ${min_free_kb} KiB required" >&2
    exit 77
fi

STAMP=$(date +%Y%m%d-%H%M%S)
OUT=/tmp/ebpf-diag-$STAMP
mkdir -p "$OUT"

# Remember the pin directories that predate this diagnostic. If the bounded
# fixture is terminated while its runtime is between attach and cleanup, the
# kernel can retain a classifier link and the next run would fail with a
# misleading "live classifiers" error. Cleanup below removes only bridge pin
# directories created by this invocation; pre-existing Ferrocrate workloads
# are never touched.
pin_root="${FERROCRATE_EBPF_PIN_ROOT:-/sys/fs/bpf/ferrocrate}"
baseline_pin_dirs="$(find "$pin_root" -mindepth 1 -maxdepth 1 -type d -name 'bridge-*' -printf '%f\n' 2>/dev/null || true)"

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
run_bounded() {
    local seconds="$1" log_path="$2"
    shift 2
    setsid "$@" >"$log_path" 2>&1 &
    local command_pid=$!
    local deadline=$((SECONDS + seconds))
    while kill -0 "$command_pid" 2>/dev/null; do
        if (( SECONDS >= deadline )); then
            echo "fixture timed out after ${seconds}s; terminating process group" >&2
            kill -TERM -- "-$command_pid" 2>/dev/null || true
            sleep 1
            kill -KILL -- "-$command_pid" 2>/dev/null || true
            wait "$command_pid" 2>/dev/null || true
            cat "$log_path" >&2 || true
            return 124
        fi
        sleep 0.1
    done
    local status=0
    wait "$command_pid" || status=$?
    cat "$log_path"
    return "$status"
}
cleanup() {
    cleanup_created_classifiers
    restore_reserved_ports
    stop_capture_processes
    if [[ "$target_dir_owned" == 1 ]]; then
        # A timed cargo process can still be unwinding incremental writes when
        # EXIT runs. Cleanup is best-effort and must not mask the fixture's
        # actual exit status or leave the release gate hanging.
        find "$target_dir" -depth -delete 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

cleanup_created_classifiers() {
    [[ -d "$pin_root" ]] || return 0
    command -v tc >/dev/null 2>&1 || return 0
    command -v bpftool >/dev/null 2>&1 || return 0
    local bridge_dir bridge_name program_path program_id dev direction pref handle
    for bridge_dir in "$pin_root"/bridge-*; do
        [[ -d "$bridge_dir" ]] || continue
        bridge_name="${bridge_dir##*/}"
        if grep -Fqx "$bridge_name" <<<"$baseline_pin_dirs"; then
            continue
        fi
        for direction in ingress egress; do
            program_path="$bridge_dir/programs/ferro_$direction"
            [[ -e "$program_path" ]] || continue
            program_id="$(bpftool prog show pinned "$program_path" 2>/dev/null | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')"
            [[ "$program_id" =~ ^[0-9]+$ ]] || continue
            while read -r dev pref handle; do
                [[ -n "$dev" && -n "$pref" && -n "$handle" ]] || continue
                tc filter del dev "$dev" "$direction" protocol all pref "$pref" handle "$handle" bpf >/dev/null 2>&1 || true
            done < <(
                for dev in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
                    tc filter show dev "$dev" "$direction" 2>/dev/null |
                        awk -v id="$program_id" -v dev="$dev" '
                            $0 ~ (" id " id " ") {
                                pref=""; handle=""
                                for (i = 1; i <= NF; i++) {
                                    if ($i == "pref") pref=$(i + 1)
                                    if ($i == "handle") handle=$(i + 1)
                                }
                                if (pref != "" && handle != "") print dev, pref, handle
                            }'
                done
            )
        done
        find "$bridge_dir" -depth -delete 2>/dev/null || true
    done
}
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

if run_bounded "$fixture_timeout_seconds" "$OUT/fixture.log" \
    env FERROCRATE_E2E_NETWORK_BACKEND=ebpf \
    FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS=1 \
    FERROCRATE_EBPF_SNAT_PORT_RANGE="$snat_range" \
    CARGO_TARGET_DIR="$target_dir" \
    "$cargo_bin" test --test e2e_container_lifecycle \
    -- --ignored ebpf_network_published_port_egress_without_netfilter_changes --nocapture; then
    RC=0
else
    RC=$?
fi
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

# Emit a compact summary alongside the raw captures.  The raw pcap/trace files
# are intentionally ephemeral, but this summary is safe to attach to a bug
# report and makes repeated kernel runs directly comparable.  In particular,
# distinguish a checksum counter change from a loopback drop and record the
# devices observed at the receive boundary.
{
    printf 'fixture_exit=%s\n' "$RC"
    printf 'kernel=%s\n' "$(uname -r)"
    printf 'snat_range=%s\n' "$snat_range"
    printf 'tcp_in_csum_errors_before='
    awk '$1 == "TcpInCsumErrors" { print $2; found=1 } END { if (!found) print 0 }' \
        "$OUT/nstat-before.txt"
    printf 'tcp_in_csum_errors_after='
    awk '$1 == "TcpInCsumErrors" { print $2; found=1 } END { if (!found) print 0 }' \
        "$OUT/nstat-after.txt"
    printf 'rx_devices='
    awk -F'dev=' '/^RX dev=/{ split($2, fields, " "); counts[fields[1]]++ }
        END { first=1; for (device in counts) { if (!first) printf ","; printf "%s:%d", device, counts[device]; first=0 } }' \
        "$OUT/netif_rx.log" | sort
    printf 'kfree_reasons='
    awk -F'reason=' '/^KFREE /{ split($2, fields, " "); counts[fields[1]]++ }
        END { first=1; for (reason in counts) { if (!first) printf ","; printf "%s:%d", reason, counts[reason]; first=0 } }' \
        "$OUT/kfree.log" | sort
    printf 'syn_packets='
    tcpdump -nn -r "$OUT/any.pcap" 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0' 2>/dev/null | wc -l
} > "$OUT/summary.txt"

echo "artifacts in $OUT"
ls -la "$OUT"
exit "$RC"

#!/usr/bin/env bash
set -euo pipefail

if [ ! -x ./target/release/ai-latency ]; then
  cargo build -p ferro-mind --release
  cat <<'RS' > /tmp/ai-latency.rs
use std::time::Instant;
use ferro_mind::ai::restart::{decide_restart, RestartSignal};

fn main() {
    let iterations: u64 = std::env::var("FERROCRATE_AI_ITER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10000);
    let signal = RestartSignal { exit_code: 1, recent_failures: 0 };
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = decide_restart(signal);
    }
    let elapsed = start.elapsed().as_nanos();
    let per = elapsed / iterations as u128;
    println!("perf.ai_decision_ns={}", per);
}
RS
  rustc /tmp/ai-latency.rs -o ./target/release/ai-latency -L target/release -L target/release/deps -C opt-level=3
fi

./target/release/ai-latency

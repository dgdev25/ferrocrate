use ferro_mind::ai::resource::{ResourcePredictor, ResourceSample};
use std::time::{Duration, Instant};

fn main() {
    let mut predictor = ResourcePredictor::new(120).with_memory_limit(700_000_000);

    let mut samples = Vec::new();
    let start = Instant::now();
    let mut memory: u64 = 256 * 1024 * 1024; // 256 MiB
    let mut cpu = 12.0_f32;

    for idx in 0..90_u64 {
        // Upward trend with a deterministic oscillation to test adaptation quality.
        let oscillation = (idx % 5) as i64 - 2;
        let delta = 6_500_000_i64 + (oscillation * 250_000);
        memory = memory.saturating_add(delta.max(0) as u64);
        cpu = (cpu + 0.35).min(95.0);
        samples.push(ResourceSample {
            cpu_percent: cpu,
            memory_bytes: memory,
            pids_count: 20 + (idx % 7),
            timestamp: start + Duration::from_secs(idx * 30),
        });
    }

    let expected_growth_bps = 6_500_000_f64 / 30.0;
    let mut growth_mae_bps = 0.0_f64;
    let mut points = 0_u64;
    let mut oom_hits = 0_u64;
    let mut oom_checks = 0_u64;

    for (idx, sample) in samples.iter().copied().enumerate().take(samples.len() - 1) {
        predictor.push(sample);
        if let Some(pred) = predictor.predict() {
            let err = (pred.memory_growth_rate - expected_growth_bps).abs();
            growth_mae_bps += err;
            points += 1;
        }
        if idx > 20 {
            oom_checks += 1;
            if predictor.predict_oom(Duration::from_secs(1800)).is_some() {
                oom_hits += 1;
            }
        }
    }

    let growth_mae = if points == 0 {
        0.0
    } else {
        growth_mae_bps / points as f64
    };
    let oom_detection_rate = if oom_checks == 0 {
        0.0
    } else {
        oom_hits as f64 / oom_checks as f64
    };

    println!("perf.ai_growth_rate_mae_bps={:.2}", growth_mae);
    println!("perf.ai_oom_detection_rate={:.4}", oom_detection_rate);
}

use ferro_mind::ai::resource::{ResourcePredictor, ResourceSample};
use std::time::{Duration, Instant};

fn main() {
    let iterations: usize = std::env::var("FERROCRATE_AI_OVERHEAD_ITER")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000);
    let mut predictor = ResourcePredictor::new(60).with_memory_limit(256 * 1024 * 1024);
    let warmup = 100usize;
    for index in 0..warmup {
        predictor.push(sample(index));
        let _ = predictor.predict();
    }

    let start = Instant::now();
    for index in 0..iterations {
        predictor.push(sample(index + warmup));
        let _ = predictor.predict();
        let _ = predictor.predict_oom(Duration::from_secs(1_200));
    }
    let elapsed = start.elapsed().as_nanos();
    let per_sample = elapsed / iterations.max(1) as u128;
    println!("perf.ai_monitor_sample_ns={per_sample}");
    println!("perf.ai_monitor_iterations={iterations}");
}

fn sample(index: usize) -> ResourceSample {
    ResourceSample {
        cpu_percent: 10.0 + (index % 20) as f32,
        memory_bytes: 16 * 1024 * 1024 + (index as u64 * 4096),
        pids_count: 8 + (index % 4) as u64,
        timestamp: Instant::now(),
    }
}

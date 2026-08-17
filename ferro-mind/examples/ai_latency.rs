use ferro_mind::wasm::{LinearWasmEngine, WasmInferenceEngine, WasmRequest};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

fn latency_model_path() -> std::path::PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ferro-mind-latency-model-{}-{timestamp}-{sequence}.json",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn model_paths_are_unique_per_invocation() {
        let first = super::latency_model_path();
        let second = super::latency_model_path();
        assert_ne!(first, second);
    }
}

fn main() {
    let iterations: u64 = std::env::var("FERROCRATE_AI_ITER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);

    let model_path = latency_model_path();
    let mut model = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&model_path)
        .expect("create model");
    model
        .write_all(
            br#"{"input_dim":3,"output_dim":2,"weights":[1.0,2.0,3.0,-1.0,0.5,0.0],"bias":[0.5,1.0]}"#,
        )
        .expect("write model");

    let mut input = Vec::with_capacity(12);
    for value in [1.0_f32, 2.0_f32, 3.0_f32] {
        input.extend_from_slice(&value.to_le_bytes());
    }

    let engine = LinearWasmEngine;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = engine
            .infer(WasmRequest {
                input: input.clone(),
                model: model_path.display().to_string(),
            })
            .expect("infer");
    }
    let elapsed = start.elapsed().as_nanos();
    let per = elapsed / iterations as u128;
    println!("perf.ai_inference_ns={}", per);
    let _ = std::fs::remove_file(model_path);
}

use ferro_mind::wasm::{LinearWasmEngine, WasmInferenceEngine, WasmRequest};
use std::io::Write;
use std::time::Instant;

fn main() {
    let iterations: u64 = std::env::var("FERROCRATE_AI_ITER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);

    let model_path = std::env::temp_dir().join("ferro-mind-latency-model.json");
    let mut model = std::fs::File::create(&model_path).expect("create model");
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
}

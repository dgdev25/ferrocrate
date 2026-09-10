//! WebAssembly inference engine integration
//!
//! Provides abstractions for pluggable WASM-based model inference engines.

use std::collections::HashMap;
use std::time::Instant;

/// A WebAssembly inference request
#[derive(Debug, Clone)]
pub struct WasmRequest {
    /// Raw input bytes for the model
    pub input: Vec<u8>,
    /// Model identifier
    pub model: String,
}

/// A WebAssembly inference response
#[derive(Debug, Clone)]
pub struct WasmResponse {
    /// Raw output bytes from the model
    pub output: Vec<u8>,
    /// Metadata about the inference result
    pub metadata: HashMap<String, String>,
}

/// Trait for WebAssembly-based inference engines
pub trait WasmInferenceEngine: Send + Sync {
    /// Get the name of this engine
    fn name(&self) -> &str;
    /// Run inference on a request
    fn infer(&self, request: WasmRequest) -> Result<WasmResponse, String>;
}

/// Registry for managing multiple WASM inference engines
#[derive(Default)]
pub struct WasmRegistry {
    /// Map of engine name to engine instance
    engines: HashMap<String, Box<dyn WasmInferenceEngine>>,
}

impl WasmRegistry {
    /// Register a new inference engine
    pub fn register<E: WasmInferenceEngine + 'static>(&mut self, engine: E) {
        self.engines
            .insert(engine.name().to_string(), Box::new(engine));
    }

    /// Run inference using the specified engine
    pub fn infer(&self, engine: &str, request: WasmRequest) -> Result<WasmResponse, String> {
        let handler = self
            .engines
            .get(engine)
            .ok_or_else(|| format!("wasm engine not found: {engine}"))?;
        handler.infer(request)
    }
}

/// Explicitly unsupported WASM engine retained only for compatibility with
/// callers that used the old test fixture. It must never report a successful
/// inference: echoing input is not model execution and could silently produce
/// invalid decisions in production.
#[derive(Default)]
pub struct NoopWasmEngine;

impl WasmInferenceEngine for NoopWasmEngine {
    fn name(&self) -> &str {
        "noop"
    }

    fn infer(&self, request: WasmRequest) -> Result<WasmResponse, String> {
        let _ = request;
        Err(
            "noop WASM inference is unsupported; configure a validated inference engine"
                .to_string(),
        )
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LinearModel {
    input_dim: usize,
    output_dim: usize,
    weights: Vec<f32>,
    #[serde(default)]
    bias: Vec<f32>,
}

/// Inference engine backed by a simple linear model persisted as JSON.
///
/// Request `model` is a filesystem path to a JSON model:
/// `{ "input_dim": 3, "output_dim": 2, "weights": [...], "bias": [...] }`.
#[derive(Default)]
pub struct LinearWasmEngine;

impl WasmInferenceEngine for LinearWasmEngine {
    fn name(&self) -> &str {
        "linear"
    }

    fn infer(&self, request: WasmRequest) -> Result<WasmResponse, String> {
        let started = Instant::now();
        let model_bytes = std::fs::read(&request.model)
            .map_err(|err| format!("failed to read model '{}': {err}", request.model))?;
        let model: LinearModel = serde_json::from_slice(&model_bytes)
            .map_err(|err| format!("invalid model json: {err}"))?;

        if model.input_dim == 0 || model.output_dim == 0 {
            return Err("model dimensions must be greater than zero".to_string());
        }
        let expected_weights = model
            .input_dim
            .checked_mul(model.output_dim)
            .ok_or_else(|| "model dimensions overflow".to_string())?;
        if model.weights.len() != expected_weights {
            return Err(format!(
                "invalid weights length: expected {}, got {}",
                expected_weights,
                model.weights.len()
            ));
        }

        let input = decode_f32_le(&request.input)?;
        if input.len() != model.input_dim {
            return Err(format!(
                "input dimension mismatch: expected {}, got {}",
                model.input_dim,
                input.len()
            ));
        }

        let output = infer_linear(&model, &input);

        let mut metadata = HashMap::new();
        metadata.insert("engine".to_string(), "linear".to_string());
        metadata.insert("model".to_string(), request.model);
        metadata.insert("input_dim".to_string(), model.input_dim.to_string());
        metadata.insert("output_dim".to_string(), model.output_dim.to_string());
        metadata.insert(
            "inference_micros".to_string(),
            started.elapsed().as_micros().to_string(),
        );

        Ok(WasmResponse {
            output: encode_f32_le(&output),
            metadata,
        })
    }
}

fn decode_f32_le(bytes: &[u8]) -> Result<Vec<f32>, String> {
    if !bytes.len().is_multiple_of(4) {
        return Err(format!(
            "input byte length must be multiple of 4, got {}",
            bytes.len()
        ));
    }
    let (chunks, _) = bytes.as_chunks::<4>();
    Ok(chunks
        .iter()
        .map(|chunk| f32::from_le_bytes(*chunk))
        .collect())
}

fn encode_f32_le(values: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 4);
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

fn infer_linear(model: &LinearModel, input: &[f32]) -> Vec<f32> {
    let mut output = vec![0.0f32; model.output_dim];
    for (row, y) in output.iter_mut().enumerate() {
        let mut acc = *model.bias.get(row).unwrap_or(&0.0);
        let row_start = row * model.input_dim;
        for (col, x) in input.iter().enumerate() {
            acc += model.weights[row_start + col] * x;
        }
        *y = acc;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(values: &[f32]) -> Vec<u8> {
        encode_f32_le(values)
    }

    fn decode(bytes: &[u8]) -> Vec<f32> {
        decode_f32_le(bytes).expect("decode output")
    }

    #[test]
    fn linear_engine_runs_inference() {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_path = temp.path().join("linear.json");
        let model = serde_json::json!({
            "input_dim": 3,
            "output_dim": 2,
            "weights": [
                1.0, 2.0, 3.0,
                -1.0, 0.5, 0.0
            ],
            "bias": [0.5, 1.0]
        });
        std::fs::write(&model_path, serde_json::to_vec(&model).expect("json"))
            .expect("write model");

        let request = WasmRequest {
            input: encode(&[2.0, 1.0, 0.0]),
            model: model_path.display().to_string(),
        };
        let engine = LinearWasmEngine;
        let response = engine.infer(request).expect("inference");
        let output = decode(&response.output);

        assert_eq!(output.len(), 2);
        assert!((output[0] - 4.5).abs() < 1e-6); // (1*2 + 2*1 + 3*0) + 0.5
        assert!((output[1] + 0.5).abs() < 1e-6); // (-1*2 + 0.5*1 + 0*0) + 1.0
        assert_eq!(response.metadata.get("engine"), Some(&"linear".to_string()));
    }

    #[test]
    fn linear_engine_rejects_bad_input_shape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_path = temp.path().join("linear.json");
        let model = serde_json::json!({
            "input_dim": 3,
            "output_dim": 1,
            "weights": [1.0, 2.0, 3.0],
            "bias": [0.0]
        });
        std::fs::write(&model_path, serde_json::to_vec(&model).expect("json"))
            .expect("write model");

        let request = WasmRequest {
            input: encode(&[1.0, 2.0]),
            model: model_path.display().to_string(),
        };
        let engine = LinearWasmEngine;
        let err = engine.infer(request).expect_err("dimension mismatch");
        assert!(err.contains("input dimension mismatch"));
    }

    #[test]
    fn registry_dispatches_linear_engine() {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_path = temp.path().join("linear.json");
        let model = serde_json::json!({
            "input_dim": 1,
            "output_dim": 1,
            "weights": [2.0],
            "bias": [3.0]
        });
        std::fs::write(&model_path, serde_json::to_vec(&model).expect("json"))
            .expect("write model");

        let mut registry = WasmRegistry::default();
        registry.register(LinearWasmEngine);
        let response = registry
            .infer(
                "linear",
                WasmRequest {
                    input: encode(&[4.0]),
                    model: model_path.display().to_string(),
                },
            )
            .expect("registry infer");
        let output = decode(&response.output);
        assert_eq!(output, vec![11.0]);
    }

    #[test]
    fn noop_engine_fails_closed_instead_of_echoing_input() {
        let error = NoopWasmEngine
            .infer(WasmRequest {
                input: vec![0, 0, 0, 0],
                model: "unused".to_string(),
            })
            .expect_err("unsupported inference must not report success");
        assert!(error.contains("unsupported"));
    }
}

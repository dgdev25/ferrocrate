use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct WasmRequest {
    pub input: Vec<u8>,
    pub model: String,
}

#[derive(Debug, Clone)]
pub struct WasmResponse {
    pub output: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

pub trait WasmInferenceEngine: Send + Sync {
    fn name(&self) -> &str;
    fn infer(&self, request: WasmRequest) -> Result<WasmResponse, String>;
}

#[derive(Default)]
pub struct WasmRegistry {
    engines: HashMap<String, Box<dyn WasmInferenceEngine>>,
}

impl WasmRegistry {
    pub fn register<E: WasmInferenceEngine + 'static>(&mut self, engine: E) {
        self.engines.insert(engine.name().to_string(), Box::new(engine));
    }

    pub fn infer(&self, engine: &str, request: WasmRequest) -> Result<WasmResponse, String> {
        let handler = self
            .engines
            .get(engine)
            .ok_or_else(|| format!("wasm engine not found: {engine}"))?;
        handler.infer(request)
    }
}

#[derive(Default)]
pub struct NoopWasmEngine;

impl WasmInferenceEngine for NoopWasmEngine {
    fn name(&self) -> &str {
        "noop"
    }

    fn infer(&self, request: WasmRequest) -> Result<WasmResponse, String> {
        let mut metadata = HashMap::new();
        metadata.insert("engine".to_string(), "noop".to_string());
        metadata.insert("model".to_string(), request.model);
        Ok(WasmResponse {
            output: request.input,
            metadata,
        })
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
    Ok(bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
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
}

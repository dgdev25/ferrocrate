use std::collections::HashMap;

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

# ADR-007: WASM for AI Inference

## Status

**Amended** (February 11, 2026 - Revised WASM latency targets and added pluggable architecture per AI consensus)

## Context

FerroCrate includes an AI layer (ferro-mind) for:
- Predictive resource allocation
- Intelligent container restart decisions
- Anomaly detection
- Build cache optimization

**AI Inference Options:**

| Option | Latency | Dependencies | Offline | Cost |
|--------|---------|--------------|---------|------|
| Cloud API (Claude/GPT) | 500-2000ms | Network | No | $$$ |
| Local LLM (Ollama) | 100-500ms | 4-16GB RAM | Yes | $$ |
| ONNX Runtime | 1-10ms | Native lib | Yes | $ |
| WASM (ruv-FANN) | 1-5ms (2-5x overhead vs native) | None | Yes | Free |

**Requirements from PRD:**
- PERF-08: AI inference latency 1-5ms (realistic WASM performance)
- AI-01: Fast prediction latency with near-zero external API calls in WASM tier
- AI-04: Cost-tiered routing (WASM free -> local LLM -> cloud API)
- AI-10: AI features must be completely optional

**WASM for Neural Inference:**
- ruv-FANN: Fast Artificial Neural Network in WASM
- No external dependencies; compiled into binary
- Sub-millisecond inference on CPU
- No GPU required
- Portable across all platforms

## Decision

**Use WASM (ruv-FANN) as pluggable primary inference engine with native fallback. Cloud/local LLM for complex analysis only.**

**Pluggable Architecture:**
- WASM inference is **optional**; can be disabled entirely via `--no-wasm-inference`
- Native inference fallback available (ONNX Runtime or direct syscall analysis) when WASM is disabled
- All inference backends (WASM, native, cloud) expose identical interfaces; decisions are backend-agnostic

Inference Tier System:

```
Tier 1: WASM Neural (1-5ms, free)
├── Resource prediction
├── Anomaly scoring
├── Restart decision
└── Cache optimization

Tier 2: Local LLM (100-500ms, optional)
├── Log analysis
├── Error explanation
└── Simple diagnostics

Tier 3: Cloud API (500-2000ms, Claude API)
├── Complex debugging
├── Multi-agent orchestration
└── Natural language queries
```

Implementation:
1. **Embed WASM runtime**: Wasmtime (19.0+) compiled into ferro-mind
2. **Pre-trained models**: Neural networks for each prediction task (ONNX/GGUF compatible)
3. **Zero-config**: Models loaded at startup; no user setup required
4. **Offline-first**: All Tier 1 features work without network
5. **Fallback graceful**: If WASM unavailable, system degrades to Tier 2/3 with logged warning

## Consequences

### Positive

- **Sub-millisecond latency**: Meets PERF-08 requirement
- **Zero external dependencies**: No API keys, no network required
- **Free operation**: No per-inference cost
- **Portable**: WASM runs on all supported architectures
- **Offline capable**: Edge deployments without cloud connectivity
- **Small footprint**: WASM models are KB, not GB

### Negative

- **Limited model complexity**: Small neural networks only
- **Training required**: Models must be pre-trained; no runtime learning
- **Accuracy trade-off**: Simpler models may be less accurate than LLMs

### Neutral

- **Tier management**: Must intelligently route requests to appropriate tier

## Alternatives Considered

### Cloud API Only (Claude/GPT)

**Pros:**
- Most capable models
- No local compute required
- Continuous improvement from provider

**Cons:**
- 500-2000ms latency violates PERF-08
- Requires network connectivity
- Per-request costs
- Data leaves the system (privacy)

**Decision**: Rejected. Latency and cost requirements not met.

### Local LLM Only (Ollama/llama.cpp)

**Pros:**
- Good for complex reasoning
- Offline capable
- No per-request cost

**Cons:**
- 100-500ms latency
- 4-16GB RAM requirement
- Not suitable for real-time decisions

**Decision**: Rejected. Latency and memory too high for real-time tier.

### ONNX Runtime

**Pros:**
- Industry standard
- Good performance (1-10ms)
- GPU acceleration available
- Wide model ecosystem

**Cons:**
- Native library dependency
- Less portable than WASM
- Larger binary size impact

**Decision**: Reserved as native fallback option. WASM preferred for zero-dependency deployments, but ONNX available for deployments requiring native performance or GPU acceleration.

## Implementation Notes

**WASM Runtime:**
```toml
[dependencies]
wasmtime = "19.0"   # Primary WASM runtime
# Optional fallbacks
onnx-runtime = "1.17"  # Native inference fallback
```

**Pluggable Backend Architecture:**
```rust
trait InferenceBackend {
    fn predict_memory(&self, features: &[f64]) -> Result<u64>;
    fn detect_anomaly(&self, metrics: &Metrics) -> Result<AnomalyScore>;
}

struct WasmBackend {
    engine: wasmtime::Engine,
    modules: WasmModules,
}

struct OnnxBackend {
    session: Session,
}

impl InferenceEngine {
    fn new(config: &Config) -> Result<Self> {
        let backend: Box<dyn InferenceBackend> = match config.backend {
            InferenceBackendType::Wasm => Box::new(WasmBackend::new()?),
            InferenceBackendType::Onnx => Box::new(OnnxBackend::new()?),
            InferenceBackendType::Auto => {
                // Try WASM first, fall back to ONNX if unavailable
                WasmBackend::new()
                    .map(|b| Box::new(b) as Box<dyn InferenceBackend>)
                    .or_else(|_| OnnxBackend::new().map(|b| Box::new(b) as Box<dyn InferenceBackend>))?
            }
        };
        Ok(InferenceEngine { backend })
    }
}
```

**Tier Routing:**
```rust
enum InferenceTier {
    Wasm,      // Free, 1-5ms, zero dependencies
    LocalLLM,  // Optional, 100-500ms, requires setup
    CloudAPI,  // Complex, 500-2000ms, requires network
}

fn route_request(request: &Request) -> InferenceTier {
    match request.complexity {
        Complexity::Simple => InferenceTier::Wasm,
        Complexity::Moderate if local_llm_available() => InferenceTier::LocalLLM,
        Complexity::Complex => InferenceTier::CloudAPI,
        _ if wasm_unavailable() => InferenceTier::LocalLLM, // Graceful degradation
    }
}
```

## References

- [ruv-FANN](https://github.com/ruvnet/ruv-FANN)
- [Wasmtime](https://wasmtime.dev/)
- [OCI Image Spec - Media Types](https://github.com/opencontainers/image-spec/blob/main/media-types.md)
- PRD Requirements: AI-01, AI-04, AI-10, PERF-08

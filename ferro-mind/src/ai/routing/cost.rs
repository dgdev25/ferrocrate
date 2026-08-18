use crate::wasm::{WasmRegistry, WasmRequest};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Provider {
    pub name: String,
    pub cost_per_1k_tokens: f32,
    pub quality: f32,
    pub avg_latency_ms: u32,
    pub local: bool,
}

/// A scored provider together with an explicit executable backend.
///
/// The command is launched directly (never through a shell) and receives the
/// prompt on stdin. This keeps the routing primitive useful for local WASM,
/// model-server, or test adapters without silently inventing a cloud API.
#[derive(Debug, Clone)]
pub struct ProviderEndpoint {
    pub provider: Provider,
    pub command: std::path::PathBuf,
    pub args: Vec<String>,
}

/// Wire format for a remote model endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpProviderProtocol {
    /// OpenAI-compatible `/chat/completions` request and response shape.
    OpenAiCompatible,
    /// Anthropic `/messages` request and response shape.
    AnthropicMessages,
}

/// A remote provider endpoint with an explicit, non-shell HTTP transport.
#[derive(Debug, Clone)]
pub struct HttpProviderEndpoint {
    pub provider: Provider,
    pub url: String,
    pub api_key: Option<String>,
    pub model: String,
    pub protocol: HttpProviderProtocol,
}

/// A local inference tier backed by a registered WASM engine.
///
/// The registry is shared so callers can register validated engines once and
/// route multiple prompts through the same immutable dispatch surface.
#[derive(Clone)]
pub struct WasmProviderEndpoint {
    pub provider: Provider,
    pub registry: Arc<WasmRegistry>,
    pub engine: String,
    pub model: String,
}

impl std::fmt::Debug for WasmProviderEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmProviderEndpoint")
            .field("provider", &self.provider)
            .field("engine", &self.engine)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

/// A provider candidate backed by either a local executable or a structured
/// HTTP endpoint. Keeping the adapter explicit makes tier selection auditable
/// and prevents an unavailable tier from being silently substituted.
#[derive(Debug, Clone)]
pub enum ProviderAdapter {
    Command(ProviderEndpoint),
    Http(HttpProviderEndpoint),
    Wasm(WasmProviderEndpoint),
}

impl ProviderAdapter {
    fn provider(&self) -> &Provider {
        match self {
            Self::Command(endpoint) => &endpoint.provider,
            Self::Http(endpoint) => &endpoint.provider,
            Self::Wasm(endpoint) => &endpoint.provider,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("no provider satisfies the routing policy")]
    NoProvider,
    #[error("provider command failed to start: {0}")]
    Spawn(String),
    #[error("provider command timed out after {0} ms")]
    Timeout(u64),
    #[error("provider command exited with status {status}: {stderr}")]
    NonZeroExit { status: i32, stderr: String },
    #[error("provider returned an empty response")]
    EmptyResponse,
    #[error("provider HTTP client failed: {0}")]
    HttpClient(String),
    #[error("provider HTTP request returned status {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("provider returned an invalid response: {0}")]
    InvalidResponse(String),
    #[error("provider endpoint is invalid: {0}")]
    InvalidEndpoint(String),
    #[error("WASM provider failed: {0}")]
    Wasm(String),
    #[error("provider token budget exceeded: used {used}, budget {budget}")]
    TokenBudgetExceeded { used: u64, budget: u64 },
}

/// Concurrent-safe token budget for provider calls. A zero budget is unlimited.
#[derive(Debug, Clone)]
pub struct TokenBudget {
    used: Arc<AtomicU64>,
    budget: u64,
}

impl TokenBudget {
    pub fn new(budget: u64) -> Self {
        Self {
            used: Arc::new(AtomicU64::new(0)),
            budget,
        }
    }

    fn reserve(&self, count: u64) -> Result<(), ExecutionError> {
        if self.budget == 0 {
            return Ok(());
        }
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(count)
                .ok_or(ExecutionError::TokenBudgetExceeded {
                    used: u64::MAX,
                    budget: self.budget,
                })?;
            if next > self.budget {
                return Err(ExecutionError::TokenBudgetExceeded {
                    used: next,
                    budget: self.budget,
                });
            }
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    /// Reconcile one reservation after a provider reports exact usage. The
    /// compare-and-swap loop preserves concurrent reservations while releasing
    /// an overestimate or charging an underestimate without allowing the
    /// accounting counter to underflow.
    fn reconcile(&self, reserved: u64, actual: u64) -> Result<(), ExecutionError> {
        if self.budget == 0 || reserved == actual {
            return Ok(());
        }
        if actual > reserved {
            return self.reserve(actual - reserved);
        }
        let release = reserved - actual;
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            if current < release {
                return Err(ExecutionError::TokenBudgetExceeded {
                    used: current,
                    budget: self.budget,
                });
            }
            match self.used.compare_exchange_weak(
                current,
                current - release,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    pub fn used_tokens(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }
}

/// Conservative, provider-independent token estimate used when a backend does
/// not expose tokenizer usage metadata. Four UTF-8 bytes are treated as one
/// token, with a minimum of one for non-empty calls.
pub fn estimate_tokens(text: &str) -> u64 {
    if text.is_empty() {
        0
    } else {
        (text.len() as u64).saturating_add(3) / 4
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProviderTokenUsage {
    prompt_tokens: u64,
    completion_tokens: u64,
}

#[derive(Debug, Clone)]
pub struct RoutingPolicy {
    pub min_quality: f32,
    pub max_cost_per_1k_tokens: Option<f32>,
    pub max_latency_ms: Option<u32>,
    pub estimated_tokens: u32,
    pub quality_weight: f32,
    pub cost_weight: f32,
    pub latency_weight: f32,
    pub local_bonus: f32,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self {
            min_quality: 0.0,
            max_cost_per_1k_tokens: None,
            max_latency_ms: None,
            estimated_tokens: 2_000,
            quality_weight: 0.5,
            cost_weight: 0.35,
            latency_weight: 0.15,
            local_bonus: 0.05,
        }
    }
}

pub fn choose_provider<'a>(
    providers: &'a [Provider],
    policy: &RoutingPolicy,
) -> Option<&'a Provider> {
    let valid: Vec<&Provider> = providers
        .iter()
        .filter(|p| p.quality.is_finite() && p.cost_per_1k_tokens.is_finite())
        .filter(|p| p.quality >= policy.min_quality)
        .filter(|p| {
            policy
                .max_cost_per_1k_tokens
                .map(|max| p.cost_per_1k_tokens <= max)
                .unwrap_or(true)
        })
        .filter(|p| {
            policy
                .max_latency_ms
                .map(|max| p.avg_latency_ms <= max)
                .unwrap_or(true)
        })
        .collect();

    if valid.is_empty() {
        return None;
    }

    let max_cost = valid
        .iter()
        .map(|p| p.cost_per_1k_tokens)
        .fold(0.0f32, f32::max)
        .max(0.0001);
    let max_latency = valid
        .iter()
        .map(|p| p.avg_latency_ms)
        .max()
        .unwrap_or(1)
        .max(1) as f32;

    valid.into_iter().max_by(|a, b| {
        let score_a = provider_score(a, policy, max_cost, max_latency);
        let score_b = provider_score(b, policy, max_cost, max_latency);
        score_a
            .partial_cmp(&score_b)
            .unwrap_or(std::cmp::Ordering::Equal)
    })
}

/// Select a provider and execute its direct local command backend.
///
/// The command receives `prompt` as UTF-8 on stdin. A timeout is mandatory in
/// practice: zero means no wait budget and is rejected, while the child is
/// killed and reaped on expiry. The returned provider name makes the selected
/// tier auditable by callers.
pub fn execute_routed_prompt(
    providers: &[ProviderEndpoint],
    policy: &RoutingPolicy,
    prompt: &str,
    timeout: std::time::Duration,
) -> Result<(String, String), ExecutionError> {
    if timeout.is_zero() {
        return Err(ExecutionError::Timeout(0));
    }
    let candidates: Vec<Provider> = providers
        .iter()
        .map(|entry| entry.provider.clone())
        .collect();
    let selected = choose_provider(&candidates, policy).ok_or(ExecutionError::NoProvider)?;
    let endpoint = providers
        .iter()
        .find(|entry| entry.provider.name == selected.name)
        .ok_or(ExecutionError::NoProvider)?;

    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(&endpoint.command)
        .args(&endpoint.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| ExecutionError::Spawn(error.to_string()))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ExecutionError::Spawn("provider stdin unavailable".to_string()))?;
    stdin
        .write_all(prompt.as_bytes())
        .map_err(|error| ExecutionError::Spawn(error.to_string()))?;
    drop(stdin);

    let started = std::time::Instant::now();
    loop {
        match child
            .try_wait()
            .map_err(|error| ExecutionError::Spawn(error.to_string()))?
        {
            Some(status) => {
                let output = child
                    .wait_with_output()
                    .map_err(|error| ExecutionError::Spawn(error.to_string()))?;
                if !status.success() {
                    return Err(ExecutionError::NonZeroExit {
                        status: status.code().unwrap_or(-1),
                        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
                    });
                }
                let response = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if response.is_empty() {
                    return Err(ExecutionError::EmptyResponse);
                }
                return Ok((endpoint.provider.name.clone(), response));
            }
            None if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ExecutionError::Timeout(timeout.as_millis() as u64));
            }
            None => std::thread::sleep(std::time::Duration::from_millis(5)),
        }
    }
}

/// Select and execute one provider across local and HTTP adapter tiers.
pub fn execute_routed_prompt_with_adapters(
    adapters: &[ProviderAdapter],
    policy: &RoutingPolicy,
    prompt: &str,
    timeout: std::time::Duration,
) -> Result<(String, String), ExecutionError> {
    let providers: Vec<Provider> = adapters
        .iter()
        .map(|adapter| adapter.provider().clone())
        .collect();
    let selected = choose_provider(&providers, policy).ok_or(ExecutionError::NoProvider)?;
    let adapter = adapters
        .iter()
        .find(|adapter| adapter.provider().name == selected.name)
        .ok_or(ExecutionError::NoProvider)?;
    match adapter {
        ProviderAdapter::Command(endpoint) => {
            execute_routed_prompt(std::slice::from_ref(endpoint), policy, prompt, timeout)
        }
        ProviderAdapter::Http(endpoint) => {
            execute_routed_http_prompt(std::slice::from_ref(endpoint), policy, prompt, timeout)
        }
        ProviderAdapter::Wasm(endpoint) => {
            execute_routed_wasm_prompt(std::slice::from_ref(endpoint), policy, prompt, timeout)
        }
    }
}

/// Execute provider adapters in deterministic score order, trying at most
/// `max_attempts` eligible providers. A failed provider is removed before the
/// next selection, so a retry cannot replay the same backend. If every attempt
/// fails, the final backend error is returned unchanged.
pub fn execute_routed_prompt_with_adapters_failover(
    adapters: &[ProviderAdapter],
    policy: &RoutingPolicy,
    prompt: &str,
    timeout: std::time::Duration,
    max_attempts: usize,
) -> Result<(String, String), ExecutionError> {
    if max_attempts == 0 {
        return Err(ExecutionError::NoProvider);
    }
    let mut remaining = adapters.iter().collect::<Vec<_>>();
    let mut last_error = None;
    for _ in 0..max_attempts {
        if remaining.is_empty() {
            break;
        }
        let providers = remaining
            .iter()
            .map(|adapter| adapter.provider().clone())
            .collect::<Vec<_>>();
        let selected = choose_provider(&providers, policy).ok_or(ExecutionError::NoProvider)?;
        let index = remaining
            .iter()
            .position(|adapter| adapter.provider().name == selected.name)
            .ok_or(ExecutionError::NoProvider)?;
        let adapter = remaining.remove(index);
        let result = match adapter {
            ProviderAdapter::Command(endpoint) => {
                execute_routed_prompt(std::slice::from_ref(endpoint), policy, prompt, timeout)
            }
            ProviderAdapter::Http(endpoint) => execute_routed_http_prompt(
                std::slice::from_ref(endpoint),
                policy,
                prompt,
                timeout,
            ),
            ProviderAdapter::Wasm(endpoint) => execute_routed_wasm_prompt(
                std::slice::from_ref(endpoint),
                policy,
                prompt,
                timeout,
            ),
        };
        match result {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(ExecutionError::NoProvider))
}

/// Execute a routed provider call while enforcing a shared token budget.
/// Prompt usage is reserved before the backend is invoked; estimated response
/// usage is reserved before the response is released. A backend failure keeps
/// the already-accounted prompt usage observable and never bypasses the budget.
pub fn execute_routed_prompt_with_adapters_metered(
    adapters: &[ProviderAdapter],
    policy: &RoutingPolicy,
    prompt: &str,
    timeout: std::time::Duration,
    budget: &TokenBudget,
) -> Result<(String, String, u64), ExecutionError> {
    let accounted_prompt_tokens = estimate_tokens(prompt);
    budget.reserve(accounted_prompt_tokens)?;
    let providers: Vec<Provider> = adapters
        .iter()
        .map(|adapter| adapter.provider().clone())
        .collect();
    let selected = choose_provider(&providers, policy).ok_or(ExecutionError::NoProvider)?;
    let adapter = adapters
        .iter()
        .find(|adapter| adapter.provider().name == selected.name)
        .ok_or(ExecutionError::NoProvider)?;
    let (provider, response, response_tokens) = match adapter {
        ProviderAdapter::Command(endpoint) => {
            let (provider, response) =
                execute_routed_prompt(std::slice::from_ref(endpoint), policy, prompt, timeout)?;
            let response_tokens = estimate_tokens(&response);
            (provider, response, response_tokens)
        }
        ProviderAdapter::Http(endpoint) => {
            let (provider, response, usage) = execute_routed_http_prompt_with_usage(
                std::slice::from_ref(endpoint),
                policy,
                prompt,
                timeout,
            )?;
            let response_tokens = if let Some(usage) = usage {
                budget.reconcile(accounted_prompt_tokens, usage.prompt_tokens)?;
                usage.completion_tokens
            } else {
                estimate_tokens(&response)
            };
            (provider, response, response_tokens)
        }
        ProviderAdapter::Wasm(endpoint) => {
            let (provider, response) =
                execute_routed_wasm_prompt(std::slice::from_ref(endpoint), policy, prompt, timeout)?;
            let response_tokens = estimate_tokens(&response);
            (provider, response, response_tokens)
        }
    };
    budget.reserve(response_tokens)?;
    Ok((provider, response, budget.used_tokens()))
}

/// Metered variant of [`execute_routed_prompt_with_adapters_failover`]. The
/// prompt is reserved once for the whole attempt sequence; response usage is
/// reserved only for a response that can be returned. A failed or over-budget
/// provider is removed before the next bounded attempt.
pub fn execute_routed_prompt_with_adapters_metered_failover(
    adapters: &[ProviderAdapter],
    policy: &RoutingPolicy,
    prompt: &str,
    timeout: std::time::Duration,
    budget: &TokenBudget,
    max_attempts: usize,
) -> Result<(String, String, u64), ExecutionError> {
    if max_attempts == 0 {
        return Err(ExecutionError::NoProvider);
    }
    let mut accounted_prompt_tokens = estimate_tokens(prompt);
    budget.reserve(accounted_prompt_tokens)?;
    let mut remaining = adapters.iter().collect::<Vec<_>>();
    let mut last_error = None;
    for _ in 0..max_attempts {
        if remaining.is_empty() {
            break;
        }
        let providers = remaining
            .iter()
            .map(|adapter| adapter.provider().clone())
            .collect::<Vec<_>>();
        let selected = choose_provider(&providers, policy).ok_or(ExecutionError::NoProvider)?;
        let index = remaining
            .iter()
            .position(|adapter| adapter.provider().name == selected.name)
            .ok_or(ExecutionError::NoProvider)?;
        let adapter = remaining.remove(index);
        let result = match adapter {
            ProviderAdapter::Command(endpoint) => {
                execute_routed_prompt(std::slice::from_ref(endpoint), policy, prompt, timeout)
                    .map(|(provider, response)| (provider, response, None))
            }
            ProviderAdapter::Http(endpoint) => execute_routed_http_prompt_with_usage(
                std::slice::from_ref(endpoint),
                policy,
                prompt,
                timeout,
            ),
            ProviderAdapter::Wasm(endpoint) => {
                execute_routed_wasm_prompt(std::slice::from_ref(endpoint), policy, prompt, timeout)
                    .map(|(provider, response)| (provider, response, None))
            }
        };
        match result {
            Ok((provider, response, usage)) => {
                let response_tokens = if let Some(usage) = usage {
                    budget.reconcile(accounted_prompt_tokens, usage.prompt_tokens)?;
                    accounted_prompt_tokens = usage.prompt_tokens;
                    usage.completion_tokens
                } else {
                    estimate_tokens(&response)
                };
                match budget.reserve(response_tokens) {
                    Ok(()) => return Ok((provider, response, budget.used_tokens())),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(ExecutionError::NoProvider))
}

/// Select and execute a remote provider using its declared wire protocol.
///
/// The request is built as structured JSON and sent directly through
/// `reqwest`; no shell, command interpolation, or implicit credential lookup is
/// involved. Callers should provide an HTTPS URL for non-local endpoints and a
/// bounded timeout. The selected provider name is returned for audit traces.
pub fn execute_routed_http_prompt(
    providers: &[HttpProviderEndpoint],
    policy: &RoutingPolicy,
    prompt: &str,
    timeout: std::time::Duration,
) -> Result<(String, String), ExecutionError> {
    let (provider, response, _) =
        execute_routed_http_prompt_with_usage(providers, policy, prompt, timeout)?;
    Ok((provider, response))
}

/// Execute a selected local WASM provider through its registered engine.
///
/// The timeout is still required at the routing boundary. Engine execution is
/// synchronous and must be bounded by the engine implementation itself; a
/// zero timeout is rejected so callers cannot accidentally claim an unbounded
/// tier-chain operation is safe.
fn execute_routed_wasm_prompt(
    providers: &[WasmProviderEndpoint],
    policy: &RoutingPolicy,
    prompt: &str,
    timeout: std::time::Duration,
) -> Result<(String, String), ExecutionError> {
    if timeout.is_zero() {
        return Err(ExecutionError::Timeout(0));
    }
    let candidates: Vec<Provider> = providers
        .iter()
        .map(|entry| entry.provider.clone())
        .collect();
    let selected = choose_provider(&candidates, policy).ok_or(ExecutionError::NoProvider)?;
    let endpoint = providers
        .iter()
        .find(|entry| entry.provider.name == selected.name)
        .ok_or(ExecutionError::NoProvider)?;
    if endpoint.engine.trim().is_empty() || endpoint.model.trim().is_empty() {
        return Err(ExecutionError::InvalidEndpoint(
            "WASM engine and model must not be empty".into(),
        ));
    }
    let response = endpoint
        .registry
        .infer(
            &endpoint.engine,
            WasmRequest {
                input: prompt.as_bytes().to_vec(),
                model: endpoint.model.clone(),
            },
        )
        .map_err(ExecutionError::Wasm)?;
    let text = String::from_utf8(response.output)
        .map_err(|error| ExecutionError::InvalidResponse(error.to_string()))?;
    let text = text.trim();
    if text.is_empty() {
        return Err(ExecutionError::EmptyResponse);
    }
    Ok((endpoint.provider.name.clone(), text.to_string()))
}

fn execute_routed_http_prompt_with_usage(
    providers: &[HttpProviderEndpoint],
    policy: &RoutingPolicy,
    prompt: &str,
    timeout: std::time::Duration,
) -> Result<(String, String, Option<ProviderTokenUsage>), ExecutionError> {
    if timeout.is_zero() {
        return Err(ExecutionError::Timeout(0));
    }
    let candidates: Vec<Provider> = providers
        .iter()
        .map(|entry| entry.provider.clone())
        .collect();
    let selected = choose_provider(&candidates, policy).ok_or(ExecutionError::NoProvider)?;
    let endpoint = providers
        .iter()
        .find(|entry| entry.provider.name == selected.name)
        .ok_or(ExecutionError::NoProvider)?;

    validate_http_provider_endpoint(endpoint)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|error| ExecutionError::HttpClient(error.to_string()))?;
    let mut request = client.post(&endpoint.url);
    let body = match endpoint.protocol {
        HttpProviderProtocol::OpenAiCompatible => serde_json::json!({
            "model": endpoint.model,
            "messages": [{"role": "user", "content": prompt}],
        }),
        HttpProviderProtocol::AnthropicMessages => serde_json::json!({
            "model": endpoint.model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }),
    };
    request = request.json(&body);
    if let Some(key) = endpoint.api_key.as_deref() {
        request = match endpoint.protocol {
            HttpProviderProtocol::OpenAiCompatible => request.bearer_auth(key),
            HttpProviderProtocol::AnthropicMessages => request
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01"),
        };
    }
    let response = request
        .send()
        .map_err(|error| ExecutionError::HttpClient(error.to_string()))?;
    let status = response.status();
    let body_text = response
        .text()
        .map_err(|error| ExecutionError::HttpClient(error.to_string()))?;
    if !status.is_success() {
        return Err(ExecutionError::HttpStatus {
            status: status.as_u16(),
            body: body_text.chars().take(512).collect(),
        });
    }
    let value: serde_json::Value = serde_json::from_str(&body_text)
        .map_err(|error| ExecutionError::InvalidResponse(error.to_string()))?;
    let text = match endpoint.protocol {
        HttpProviderProtocol::OpenAiCompatible => value
            .pointer("/choices/0/message/content")
            .and_then(serde_json::Value::as_str),
        HttpProviderProtocol::AnthropicMessages => value
            .pointer("/content/0/text")
            .and_then(serde_json::Value::as_str),
    }
    .map(str::trim)
    .filter(|text| !text.is_empty())
    .ok_or_else(|| ExecutionError::InvalidResponse("missing non-empty text content".into()))?;
    let usage = match endpoint.protocol {
        HttpProviderProtocol::OpenAiCompatible => value
            .pointer("/usage/prompt_tokens")
            .and_then(serde_json::Value::as_u64)
            .zip(
                value
                    .pointer("/usage/completion_tokens")
                    .and_then(serde_json::Value::as_u64),
            )
            .map(|(prompt_tokens, completion_tokens)| ProviderTokenUsage {
                prompt_tokens,
                completion_tokens,
            }),
        HttpProviderProtocol::AnthropicMessages => value
            .pointer("/usage/input_tokens")
            .and_then(serde_json::Value::as_u64)
            .zip(
                value
                    .pointer("/usage/output_tokens")
                    .and_then(serde_json::Value::as_u64),
            )
            .map(|(prompt_tokens, completion_tokens)| ProviderTokenUsage {
                prompt_tokens,
                completion_tokens,
            }),
    };
    Ok((endpoint.provider.name.clone(), text.to_string(), usage))
}

fn validate_http_provider_endpoint(endpoint: &HttpProviderEndpoint) -> Result<(), ExecutionError> {
    let url = reqwest::Url::parse(&endpoint.url)
        .map_err(|error| ExecutionError::InvalidEndpoint(error.to_string()))?;
    if url.username() != "" || url.password().is_some() {
        return Err(ExecutionError::InvalidEndpoint(
            "credentials in provider URL are not allowed; use api_key".into(),
        ));
    }
    if url.fragment().is_some() {
        return Err(ExecutionError::InvalidEndpoint(
            "URL fragments are not allowed".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ExecutionError::InvalidEndpoint("provider URL has no host".into()))?;
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(ExecutionError::InvalidEndpoint(
            "HTTPS is required for non-loopback provider endpoints".into(),
        ));
    }
    if endpoint.api_key.as_deref().is_some_and(str::is_empty) {
        return Err(ExecutionError::InvalidEndpoint(
            "api_key must not be empty".into(),
        ));
    }
    Ok(())
}

fn provider_score(
    provider: &Provider,
    policy: &RoutingPolicy,
    max_cost_per_1k: f32,
    max_latency_ms: f32,
) -> f32 {
    let quality_score = provider.quality.clamp(0.0, 1.0);
    let estimated_call_cost =
        provider.cost_per_1k_tokens * (policy.estimated_tokens.max(1) as f32 / 1000.0);
    let worst_case_cost = max_cost_per_1k * (policy.estimated_tokens.max(1) as f32 / 1000.0);
    let cost_score = if worst_case_cost > 0.0 {
        (1.0 - (estimated_call_cost / worst_case_cost)).clamp(0.0, 1.0)
    } else {
        1.0
    };
    let latency_score =
        (1.0 - provider.avg_latency_ms as f32 / max_latency_ms.max(1.0)).clamp(0.0, 1.0);

    let mut score = (policy.quality_weight * quality_score)
        + (policy.cost_weight * cost_score)
        + (policy.latency_weight * latency_score);
    if provider.local {
        score += policy.local_bonus.max(0.0);
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::{WasmInferenceEngine, WasmResponse};
    use std::collections::HashMap;

    struct EchoWasmEngine;

    impl WasmInferenceEngine for EchoWasmEngine {
        fn name(&self) -> &str {
            "echo"
        }

        fn infer(&self, request: crate::wasm::WasmRequest) -> Result<WasmResponse, String> {
            let mut output = b"wasm:".to_vec();
            output.extend_from_slice(&request.input);
            Ok(WasmResponse {
                output,
                metadata: HashMap::new(),
            })
        }
    }

    fn sample_providers() -> Vec<Provider> {
        vec![
            Provider {
                name: "local-wasm".to_string(),
                cost_per_1k_tokens: 0.0,
                quality: 0.62,
                avg_latency_ms: 4,
                local: true,
            },
            Provider {
                name: "local-onnx".to_string(),
                cost_per_1k_tokens: 0.0,
                quality: 0.74,
                avg_latency_ms: 12,
                local: true,
            },
            Provider {
                name: "cloud-premium".to_string(),
                cost_per_1k_tokens: 8.0,
                quality: 0.96,
                avg_latency_ms: 380,
                local: false,
            },
        ]
    }

    #[test]
    fn selects_local_fast_tier_when_quality_floor_allows() {
        let providers = sample_providers();
        let policy = RoutingPolicy {
            min_quality: 0.6,
            max_cost_per_1k_tokens: Some(0.5),
            max_latency_ms: Some(50),
            estimated_tokens: 1800,
            quality_weight: 0.45,
            cost_weight: 0.4,
            latency_weight: 0.15,
            local_bonus: 0.08,
        };
        let selected = choose_provider(&providers, &policy).expect("provider");
        assert_eq!(selected.name, "local-wasm");
    }

    #[test]
    fn selects_higher_quality_cloud_tier_when_required() {
        let providers = sample_providers();
        let policy = RoutingPolicy {
            min_quality: 0.9,
            max_cost_per_1k_tokens: None,
            max_latency_ms: None,
            estimated_tokens: 3000,
            quality_weight: 0.8,
            cost_weight: 0.15,
            latency_weight: 0.05,
            local_bonus: 0.0,
        };
        let selected = choose_provider(&providers, &policy).expect("provider");
        assert_eq!(selected.name, "cloud-premium");
    }

    #[test]
    fn returns_none_when_constraints_filter_everything() {
        let providers = sample_providers();
        let policy = RoutingPolicy {
            min_quality: 0.95,
            max_cost_per_1k_tokens: Some(1.0),
            max_latency_ms: Some(10),
            estimated_tokens: 1000,
            ..RoutingPolicy::default()
        };
        assert!(choose_provider(&providers, &policy).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn executes_selected_provider_without_shell_interpolation() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let script = temp.path().join("provider.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nread prompt\nprintf 'reply:%s\\n' \"$prompt\"\n",
        )
        .expect("script");
        let mut permissions = std::fs::metadata(&script).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).expect("permissions");
        let providers = vec![ProviderEndpoint {
            provider: Provider {
                name: "local-test".to_string(),
                cost_per_1k_tokens: 0.0,
                quality: 0.9,
                avg_latency_ms: 5,
                local: true,
            },
            command: script,
            args: Vec::new(),
        }];
        let (name, response) = execute_routed_prompt(
            &providers,
            &RoutingPolicy::default(),
            "hello; touch SHOULD_NOT_RUN",
            std::time::Duration::from_secs(1),
        )
        .expect("provider response");
        assert_eq!(name, "local-test");
        assert_eq!(response, "reply:hello; touch SHOULD_NOT_RUN");
        assert!(!temp.path().join("SHOULD_NOT_RUN").exists());
    }

    #[test]
    fn executes_selected_provider_through_registered_wasm_engine() {
        let mut registry = WasmRegistry::default();
        registry.register(EchoWasmEngine);
        let adapters = vec![ProviderAdapter::Wasm(WasmProviderEndpoint {
            provider: Provider {
                name: "local-wasm".into(),
                cost_per_1k_tokens: 0.0,
                quality: 0.8,
                avg_latency_ms: 4,
                local: true,
            },
            registry: Arc::new(registry),
            engine: "echo".into(),
            model: "fixture-model".into(),
        })];
        let result = execute_routed_prompt_with_adapters(
            &adapters,
            &RoutingPolicy {
                min_quality: 0.7,
                ..RoutingPolicy::default()
            },
            "hello",
            std::time::Duration::from_secs(1),
        )
        .expect("WASM provider response");
        assert_eq!(result, ("local-wasm".into(), "wasm:hello".into()));
    }

    #[test]
    fn execution_rejects_zero_timeout_before_spawning() {
        let error = execute_routed_prompt(
            &[],
            &RoutingPolicy::default(),
            "prompt",
            std::time::Duration::ZERO,
        )
        .expect_err("zero timeout must fail closed");
        assert!(matches!(error, ExecutionError::Timeout(0)));
    }

    #[cfg(unix)]
    #[test]
    fn adapter_failover_tries_next_scored_provider_once() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let failing = temp.path().join("failing.sh");
        let healthy = temp.path().join("healthy.sh");
        std::fs::write(&failing, "#!/bin/sh\nexit 9\n").expect("failing script");
        std::fs::write(&healthy, "#!/bin/sh\nread prompt\nprintf 'fallback:%s' \"$prompt\"\n")
            .expect("healthy script");
        for path in [&failing, &healthy] {
            let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).expect("permissions");
        }
        let provider = |name: &str, quality: f32, command: std::path::PathBuf| {
            ProviderAdapter::Command(ProviderEndpoint {
                provider: Provider {
                    name: name.into(),
                    cost_per_1k_tokens: 0.0,
                    quality,
                    avg_latency_ms: 1,
                    local: true,
                },
                command,
                args: Vec::new(),
            })
        };
        let adapters = vec![
            provider("preferred-but-failing", 0.99, failing),
            provider("healthy-fallback", 0.80, healthy),
        ];
        let result = execute_routed_prompt_with_adapters_failover(
            &adapters,
            &RoutingPolicy::default(),
            "hello",
            std::time::Duration::from_secs(5),
            2,
        )
        .expect("fallback response");
        assert_eq!(result.0, "healthy-fallback");
        assert_eq!(result.1, "fallback:hello");
    }

    #[cfg(unix)]
    #[test]
    fn adapter_failover_respects_attempt_limit_and_returns_final_error() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let first = temp.path().join("first.sh");
        let second = temp.path().join("second.sh");
        std::fs::write(&first, "#!/bin/sh\nexit 7\n").expect("first script");
        std::fs::write(&second, "#!/bin/sh\nexit 8\n").expect("second script");
        for path in [&first, &second] {
            let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).expect("permissions");
        }
        let make = |name: &str, quality: f32, command| {
            ProviderAdapter::Command(ProviderEndpoint {
                provider: Provider {
                    name: name.into(),
                    cost_per_1k_tokens: 0.0,
                    quality,
                    avg_latency_ms: 1,
                    local: true,
                },
                command,
                args: Vec::new(),
            })
        };
        let error = execute_routed_prompt_with_adapters_failover(
            &[make("first", 0.99, first), make("second", 0.80, second)],
            &RoutingPolicy::default(),
            "hello",
            std::time::Duration::from_secs(5),
            1,
        )
        .unwrap_err();
        assert!(matches!(error, ExecutionError::NonZeroExit { status: 7, .. }));
    }

    #[cfg(unix)]
    #[test]
    fn metered_failover_charges_prompt_once_and_only_returns_within_budget() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let failing = temp.path().join("failing.sh");
        let healthy = temp.path().join("healthy.sh");
        std::fs::write(&failing, "#!/bin/sh\nexit 9\n").expect("failing script");
        std::fs::write(&healthy, "#!/bin/sh\nread prompt\nprintf 'ok'\n").expect("healthy script");
        for path in [&failing, &healthy] {
            let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).expect("permissions");
        }
        let make = |name: &str, quality: f32, command| {
            ProviderAdapter::Command(ProviderEndpoint {
                provider: Provider {
                    name: name.into(),
                    cost_per_1k_tokens: 0.0,
                    quality,
                    avg_latency_ms: 1,
                    local: true,
                },
                command,
                args: Vec::new(),
            })
        };
        let budget = TokenBudget::new(4);
        let result = execute_routed_prompt_with_adapters_metered_failover(
            &[make("preferred", 0.99, failing), make("fallback", 0.8, healthy)],
            &RoutingPolicy::default(),
            "hello",
            std::time::Duration::from_secs(5),
            &budget,
            2,
        )
        .expect("fallback response within budget");
        assert_eq!(result, ("fallback".into(), "ok".into(), 3));
        assert_eq!(budget.used_tokens(), estimate_tokens("hello") + estimate_tokens("ok"));
    }

    #[cfg(unix)]
    #[test]
    fn metered_routing_reserves_prompt_and_response_before_release() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let script = temp.path().join("provider.sh");
        std::fs::write(&script, "#!/bin/sh\nread prompt\nprintf 'reply'\n").expect("script");
        let mut permissions = std::fs::metadata(&script).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).expect("permissions");
        let provider = ProviderAdapter::Command(ProviderEndpoint {
            provider: Provider {
                name: "metered-local".into(),
                cost_per_1k_tokens: 0.0,
                quality: 0.9,
                avg_latency_ms: 1,
                local: true,
            },
            command: script,
            args: Vec::new(),
        });
        let budget = TokenBudget::new(3);
        let error = execute_routed_prompt_with_adapters_metered(
            &[provider],
            &RoutingPolicy::default(),
            "hello",
            std::time::Duration::from_secs(5),
            &budget,
        )
        .unwrap_err();
        assert!(matches!(error, ExecutionError::TokenBudgetExceeded { .. }));
        assert_eq!(budget.used_tokens(), estimate_tokens("hello"));
    }

    #[cfg(unix)]
    #[test]
    fn metered_routing_keeps_prompt_usage_when_backend_fails() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let script = temp.path().join("provider.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 9\n").expect("script");
        let mut permissions = std::fs::metadata(&script).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).expect("permissions");
        let provider = ProviderAdapter::Command(ProviderEndpoint {
            provider: Provider {
                name: "failing-local".into(),
                cost_per_1k_tokens: 0.0,
                quality: 0.9,
                avg_latency_ms: 1,
                local: true,
            },
            command: script,
            args: Vec::new(),
        });
        let budget = TokenBudget::new(20);
        let error = execute_routed_prompt_with_adapters_metered(
            &[provider],
            &RoutingPolicy::default(),
            "hello",
            std::time::Duration::from_secs(1),
            &budget,
        )
        .unwrap_err();
        assert!(matches!(error, ExecutionError::NonZeroExit { status: 9, .. }));
        assert_eq!(budget.used_tokens(), estimate_tokens("hello"));
    }

    #[test]
    fn token_budget_reconciles_a_reserved_estimate_to_provider_usage() {
        let budget = TokenBudget::new(100);
        budget.reserve(10).expect("reserve estimate");
        budget.reconcile(10, 4).expect("release overestimate");
        assert_eq!(budget.used_tokens(), 4);
        budget.reconcile(4, 12).expect("charge underestimation");
        assert_eq!(budget.used_tokens(), 12);
    }

    #[test]
    fn provider_endpoint_validation_requires_tls_off_loopback() {
        let endpoint = HttpProviderEndpoint {
            provider: Provider {
                name: "remote".into(),
                cost_per_1k_tokens: 1.0,
                quality: 0.9,
                avg_latency_ms: 100,
                local: false,
            },
            url: "http://models.example.invalid/v1/chat/completions".into(),
            api_key: Some("key".into()),
            model: "model".into(),
            protocol: HttpProviderProtocol::OpenAiCompatible,
        };
        let error = validate_http_provider_endpoint(&endpoint).expect_err("TLS required");
        assert!(
            matches!(error, ExecutionError::InvalidEndpoint(message) if message.contains("HTTPS"))
        );
    }

    #[test]
    fn provider_endpoint_validation_rejects_url_credentials_and_empty_keys() {
        let mut endpoint = HttpProviderEndpoint {
            provider: Provider {
                name: "local".into(),
                cost_per_1k_tokens: 0.0,
                quality: 0.9,
                avg_latency_ms: 10,
                local: true,
            },
            url: "http://user:password@127.0.0.1:8080".into(),
            api_key: Some("key".into()),
            model: "model".into(),
            protocol: HttpProviderProtocol::OpenAiCompatible,
        };
        let error = validate_http_provider_endpoint(&endpoint).expect_err("URL credentials");
        assert!(
            matches!(error, ExecutionError::InvalidEndpoint(message) if message.contains("credentials"))
        );
        endpoint.url = "http://127.0.0.1:8080".into();
        endpoint.api_key = Some(String::new());
        let error = validate_http_provider_endpoint(&endpoint).expect_err("empty key");
        assert!(
            matches!(error, ExecutionError::InvalidEndpoint(message) if message.contains("empty"))
        );
    }

    #[test]
    fn executes_openai_compatible_http_provider_with_structured_request() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let address = listener.local_addr().expect("address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request");
            let mut request = [0u8; 8192];
            let size = stream.read(&mut request).expect("request bytes");
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.contains("\"model\":\"test-model\""));
            assert!(request.contains("provider prompt"));
            let body = r#"{"choices":[{"message":{"content":"openai reply"}}],"usage":{"prompt_tokens":2,"completion_tokens":1}}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("response");
        });
        let providers = vec![ProviderAdapter::Http(HttpProviderEndpoint {
            provider: Provider {
                name: "local-openai-compatible".into(),
                cost_per_1k_tokens: 0.0,
                quality: 0.8,
                avg_latency_ms: 10,
                local: true,
            },
            url: format!("http://{address}/v1/chat/completions"),
            api_key: Some("test-key".into()),
            model: "test-model".into(),
            protocol: HttpProviderProtocol::OpenAiCompatible,
        })];
        let budget = TokenBudget::new(5);
        let result = execute_routed_prompt_with_adapters_metered(
            &providers,
            &RoutingPolicy::default(),
            "provider prompt",
            std::time::Duration::from_secs(2),
            &budget,
        )
        .expect("HTTP provider response");
        server.join().expect("server");
        assert_eq!(
            result,
            ("local-openai-compatible".into(), "openai reply".into(), 3)
        );
    }

    #[test]
    fn executes_anthropic_http_provider_and_reports_http_errors() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let address = listener.local_addr().expect("address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request");
            // Consume the request before closing the connection.  Under the
            // full workspace test load, replying and dropping the socket
            // before the client's request body is read can produce an
            // indistinguishable connection reset instead of the intended
            // HTTP 503 assertion.
            let mut request = [0u8; 8192];
            let _ = stream.read(&mut request).expect("request bytes");
            let body = r#"{"error":"upstream unavailable"}"#;
            write!(
                stream,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("response");
        });
        let providers = vec![HttpProviderEndpoint {
            provider: Provider {
                name: "cloud-anthropic".into(),
                cost_per_1k_tokens: 8.0,
                quality: 0.96,
                avg_latency_ms: 380,
                local: false,
            },
            url: format!("http://{address}/v1/messages"),
            api_key: Some("test-key".into()),
            model: "claude-test".into(),
            protocol: HttpProviderProtocol::AnthropicMessages,
        }];
        let error = execute_routed_http_prompt(
            &providers,
            &RoutingPolicy {
                min_quality: 0.9,
                ..RoutingPolicy::default()
            },
            "provider prompt",
            std::time::Duration::from_secs(2),
        )
        .expect_err("upstream status must fail closed");
        server.join().expect("server");
        assert!(matches!(
            error,
            ExecutionError::HttpStatus { status: 503, .. }
        ));
    }

    #[test]
    fn reconciles_anthropic_reported_input_and_output_usage() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let address = listener.local_addr().expect("address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request");
            let mut request = [0u8; 8192];
            let size = stream.read(&mut request).expect("request bytes");
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.contains("\"model\":\"claude-test\""));
            assert!(request.contains("anthropic prompt"));
            let body =
                r#"{"content":[{"type":"text","text":"anthropic reply"}],"usage":{"input_tokens":2,"output_tokens":1}}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("response");
        });
        let providers = vec![ProviderAdapter::Http(HttpProviderEndpoint {
            provider: Provider {
                name: "cloud-anthropic".into(),
                cost_per_1k_tokens: 8.0,
                quality: 0.96,
                avg_latency_ms: 380,
                local: false,
            },
            url: format!("http://{address}/v1/messages"),
            api_key: Some("test-key".into()),
            model: "claude-test".into(),
            protocol: HttpProviderProtocol::AnthropicMessages,
        })];
        let budget = TokenBudget::new(5);
        let result = execute_routed_prompt_with_adapters_metered(
            &providers,
            &RoutingPolicy {
                min_quality: 0.9,
                ..RoutingPolicy::default()
            },
            "anthropic prompt",
            std::time::Duration::from_secs(2),
            &budget,
        )
        .expect("HTTP provider response");
        server.join().expect("server");
        assert_eq!(
            result,
            ("cloud-anthropic".into(), "anthropic reply".into(), 3)
        );
    }
}

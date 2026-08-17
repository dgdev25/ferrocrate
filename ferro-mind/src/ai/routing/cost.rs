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

/// A provider candidate backed by either a local executable or a structured
/// HTTP endpoint. Keeping the adapter explicit makes tier selection auditable
/// and prevents an unavailable tier from being silently substituted.
#[derive(Debug, Clone)]
pub enum ProviderAdapter {
    Command(ProviderEndpoint),
    Http(HttpProviderEndpoint),
}

impl ProviderAdapter {
    fn provider(&self) -> &Provider {
        match self {
            Self::Command(endpoint) => &endpoint.provider,
            Self::Http(endpoint) => &endpoint.provider,
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
    }
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
    Ok((endpoint.provider.name.clone(), text.to_string()))
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
            let body = r#"{"choices":[{"message":{"content":"openai reply"}}]}"#;
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
        let result = execute_routed_prompt_with_adapters(
            &providers,
            &RoutingPolicy::default(),
            "provider prompt",
            std::time::Duration::from_secs(2),
        )
        .expect("HTTP provider response");
        server.join().expect("server");
        assert_eq!(
            result,
            ("local-openai-compatible".into(), "openai reply".into())
        );
    }

    #[test]
    fn executes_anthropic_http_provider_and_reports_http_errors() {
        use std::io::Write;
        use std::net::TcpListener;
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let address = listener.local_addr().expect("address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request");
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
}

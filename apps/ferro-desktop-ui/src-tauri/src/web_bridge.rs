use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;

use axum::extract::{Path, State};
use axum::http::{header, Request, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
#[cfg(test)]
use tokio::sync::oneshot;
use tower_http::services::{ServeDir, ServeFile};

use super::*;

#[derive(Clone, Debug)]
struct WebEvent {
    name: String,
    payload: Value,
}

#[derive(Clone)]
pub(crate) struct WebEventHub {
    sender: broadcast::Sender<WebEvent>,
}

impl WebEventHub {
    fn new() -> Self {
        let (sender, _) = broadcast::channel(256);
        Self { sender }
    }

    pub(crate) fn emit<T: Serialize>(&self, name: &str, payload: T) {
        if let Ok(payload) = serde_json::to_value(payload) {
            let _ = self.sender.send(WebEvent {
                name: name.to_string(),
                payload,
            });
        }
    }
}

#[derive(Clone)]
struct BridgeState {
    events: WebEventHub,
}

#[derive(Clone)]
struct RequestGuard {
    token: String,
    allowed_hosts: [String; 2],
}

impl RequestGuard {
    fn new(addr: SocketAddr, token: String) -> Self {
        Self {
            token,
            allowed_hosts: [addr.to_string(), format!("localhost:{}", addr.port())],
        }
    }
}

#[cfg(test)]
pub(crate) struct WebBridgeHandle {
    addr: SocketAddr,
    token: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(test)]
impl WebBridgeHandle {
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

#[cfg(test)]
pub(crate) async fn spawn_web_bridge(
    addr: SocketAddr,
    dist: PathBuf,
) -> Result<WebBridgeHandle, String> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|error| format!("failed to bind web bridge at {addr}: {error}"))?;
    let addr = listener
        .local_addr()
        .map_err(|error| format!("failed to inspect web bridge address: {error}"))?;
    let (shutdown, shutdown_rx) = oneshot::channel();
    let token = generate_session_token()?;
    let app = bridge_router(dist, WebEventHub::new(), addr, token.clone());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });
    Ok(WebBridgeHandle {
        addr,
        token,
        shutdown: Some(shutdown),
        task,
    })
}

pub(crate) async fn run_web_bridge(addr: SocketAddr, dist: PathBuf) -> Result<(), String> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|error| format!("failed to bind web bridge at {addr}: {error}"))?;
    let addr = listener
        .local_addr()
        .map_err(|error| format!("failed to inspect web bridge address: {error}"))?;
    let token = generate_session_token()?;
    let app = bridge_router(dist, WebEventHub::new(), addr, token.clone());
    println!("web bridge ready at http://{addr}/#token={token}");
    axum::serve(listener, app)
        .await
        .map_err(|error| format!("web bridge failed: {error}"))
}

fn bridge_router(dist: PathBuf, events: WebEventHub, addr: SocketAddr, token: String) -> Router {
    let index = dist.join("index.html");
    let guard = RequestGuard::new(addr, token);
    Router::new()
        .route("/__tauri/stream", get(stream_events))
        .route("/__tauri/{command}", post(invoke_command))
        .route_layer(from_fn_with_state(guard, validate_request))
        .fallback_service(ServeDir::new(dist).not_found_service(ServeFile::new(index)))
        .with_state(BridgeState { events })
}

fn generate_session_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| format!("failed to generate web bridge session token: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

async fn validate_request(
    State(guard): State<RequestGuard>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    let Some(host) = host.filter(|host| guard.allowed_hosts.iter().any(|item| item == *host))
    else {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    };

    if let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        let expected = format!("http://{host}");
        if origin != expected {
            return StatusCode::FORBIDDEN.into_response();
        }
    }

    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let stream_token = (request.uri().path() == "/__tauri/stream")
        .then(|| request.uri().query())
        .flatten()
        .and_then(|query| {
            query
                .split('&')
                .find_map(|part| part.strip_prefix("token="))
        });
    if !bearer
        .or(stream_token)
        .is_some_and(|candidate| constant_time_eq(candidate.as_bytes(), guard.token.as_bytes()))
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    next.run(request).await
}

fn constant_time_eq(candidate: &[u8], expected: &[u8]) -> bool {
    if candidate.len() != expected.len() {
        return false;
    }
    candidate
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

async fn invoke_command(
    State(state): State<BridgeState>,
    Path(command): Path<String>,
    Json(args): Json<Value>,
) -> impl IntoResponse {
    let events = state.events.clone();
    match tokio::task::spawn_blocking(move || dispatch_command(&command, args, events)).await {
        Ok(Ok(value)) => (StatusCode::OK, Json(value)),
        Ok(Err(error)) => (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("command task failed: {error}") })),
        ),
    }
}

async fn stream_events(
    State(state): State<BridgeState>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let mut receiver = state.events.sender.subscribe();
    let stream = async_stream::stream! {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    yield Ok(Event::default()
                        .event(event.name)
                        .json_data(event.payload)
                        .unwrap_or_else(|_| Event::default()));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn decode<T: DeserializeOwned>(args: Value) -> Result<T, String> {
    serde_json::from_value(args).map_err(|error| format!("invalid command arguments: {error}"))
}

fn encode<T: Serialize>(value: T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| format!("failed to encode command result: {error}"))
}

fn encode_result<T: Serialize>(value: Result<T, String>) -> Result<Value, String> {
    encode(value?)
}

#[derive(Deserialize)]
struct EmptyArgs {}

#[derive(Deserialize)]
struct TargetArgs {
    target: String,
}

#[derive(Deserialize)]
struct ContainerStatsArgs {
    ids: Vec<String>,
}

#[derive(Deserialize)]
struct TerminalArgs {
    target: String,
    shell: String,
    env: Vec<String>,
    user: Option<String>,
    workdir: Option<String>,
}

#[derive(Deserialize)]
struct TerminalWriteArgs {
    data: Vec<u8>,
}

#[derive(Deserialize)]
struct TerminalResizeArgs {
    columns: u16,
    rows: u16,
}

#[derive(Deserialize)]
struct DesktopActionArgs {
    action: DesktopAction,
    target: Option<String>,
}

#[derive(Deserialize)]
struct ComposeArgs {
    file: String,
}

#[derive(Deserialize)]
struct ComposeActionArgs {
    file: String,
    action: ComposeAction,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct BuildImageArgs {
    context: String,
    tag: String,
    #[serde(alias = "buildId")]
    build_id: String,
}

#[derive(Deserialize)]
struct VolumeActionArgs {
    action: VolumeAction,
    target: Option<String>,
}

#[derive(Deserialize)]
struct NetworkActionArgs {
    action: NetworkAction,
    target: Option<String>,
    subnet: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct ContainerResourcesArgs {
    target: String,
    memory: Option<u64>,
    #[serde(alias = "cpuQuota")]
    cpu_quota: Option<u64>,
    #[serde(alias = "cpuPeriod")]
    cpu_period: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct NewContainerArgs {
    image: String,
    name: Option<String>,
    command: Vec<String>,
    ports: Vec<String>,
    volumes: Vec<String>,
    #[serde(alias = "pullIfMissing")]
    pull_if_missing: bool,
    environment: Vec<String>,
    memory: Option<u64>,
    #[serde(alias = "cpuQuota")]
    cpu_quota: Option<u64>,
    #[serde(alias = "cpuPeriod")]
    cpu_period: Option<u64>,
}

#[derive(Deserialize)]
struct RegistryArgs {
    registry: String,
}

#[derive(Deserialize)]
struct RegistryLoginArgs {
    registry: String,
    username: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct PaidConfigArgs {
    #[serde(alias = "releaseBaseUrl")]
    release_base_url: String,
    #[serde(alias = "tokenEndpoint")]
    token_endpoint: String,
    #[serde(alias = "issuanceEndpoint")]
    issuance_endpoint: Option<String>,
}

#[derive(Deserialize)]
struct SessionTokenArgs {
    token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct AcquireSessionArgs {
    #[serde(alias = "customerId")]
    customer_id: String,
    #[serde(alias = "accessToken")]
    access_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct InstallArgs {
    confirm: bool,
    #[serde(alias = "dryRun")]
    dry_run: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct DoctorArgs {
    fix: bool,
    bootstrap: bool,
    #[serde(alias = "dryRun")]
    dry_run: bool,
    confirm: bool,
}

fn dispatch_command(command: &str, args: Value, events: WebEventHub) -> Result<Value, String> {
    match command {
        "get_desktop_snapshot" => {
            let _: EmptyArgs = decode(args)?;
            encode(get_desktop_snapshot())
        }
        "get_container_stats" => {
            let args: ContainerStatsArgs = decode(args)?;
            encode(get_container_stats(args.ids))
        }
        "get_volumes" => {
            let _: EmptyArgs = decode(args)?;
            encode_result(get_volumes())
        }
        "get_networks" => {
            let _: EmptyArgs = decode(args)?;
            encode_result(get_networks())
        }
        "get_container_detail" => {
            let args: TargetArgs = decode(args)?;
            encode_result(get_container_detail(args.target))
        }
        "get_compose_snapshot" => {
            let args: ComposeArgs = decode(args)?;
            encode_result(get_compose_snapshot(args.file))
        }
        "build_image" => {
            let args: BuildImageArgs = decode(args)?;
            encode_result(build_image_impl(
                EventSink::Web(events),
                args.context,
                args.tag,
                args.build_id,
            ))
        }
        "run_desktop_action" => {
            let args: DesktopActionArgs = decode(args)?;
            encode(run_desktop_action(args.action, args.target))
        }
        "run_compose_action" => {
            let args: ComposeActionArgs = decode(args)?;
            encode_result(run_compose_action(args.file, args.action))
        }
        "run_volume_action" => {
            let args: VolumeActionArgs = decode(args)?;
            encode_result(run_volume_action(args.action, args.target))
        }
        "run_network_action" => {
            let args: NetworkActionArgs = decode(args)?;
            encode_result(run_network_action(args.action, args.target, args.subnet))
        }
        "update_container_resources" => {
            let args: ContainerResourcesArgs = decode(args)?;
            encode_result(update_container_resources(
                args.target,
                args.memory,
                args.cpu_quota,
                args.cpu_period,
            ))
        }
        "run_new_container" => {
            let args: NewContainerArgs = decode(args)?;
            encode_result(run_new_container(
                args.image,
                args.name,
                args.command,
                args.ports,
                args.volumes,
                args.pull_if_missing,
                args.environment,
                args.memory,
                args.cpu_quota,
                args.cpu_period,
            ))
        }
        "get_registry_auth_status" => {
            let args: RegistryArgs = decode(args)?;
            encode_result(get_registry_auth_status(args.registry))
        }
        "login_registry" => {
            let args: RegistryLoginArgs = decode(args)?;
            encode_result(login_registry(args.registry, args.username, args.password))
        }
        "logout_registry" => {
            let args: RegistryArgs = decode(args)?;
            encode_result(logout_registry(args.registry))
        }
        "start_log_follow" => {
            let args: TargetArgs = decode(args)?;
            encode_result(start_log_follow_impl(EventSink::Web(events), args.target))
        }
        "stop_log_follow" => {
            let _: EmptyArgs = decode(args)?;
            encode_result(stop_log_follow())
        }
        "start_terminal" => {
            let args: TerminalArgs = decode(args)?;
            encode_result(start_terminal_impl(
                EventSink::Web(events),
                args.target,
                args.shell,
                args.env,
                args.user,
                args.workdir,
            ))
        }
        "write_terminal" => {
            let args: TerminalWriteArgs = decode(args)?;
            encode_result(write_terminal(args.data))
        }
        "resize_terminal" => {
            let args: TerminalResizeArgs = decode(args)?;
            encode_result(resize_terminal(args.columns, args.rows))
        }
        "close_terminal" => {
            let _: EmptyArgs = decode(args)?;
            encode_result(close_terminal())
        }
        "get_paid_auth_state" => {
            let _: EmptyArgs = decode(args)?;
            encode_result(get_paid_auth_state())
        }
        "save_paid_backend_config" => {
            let args: PaidConfigArgs = decode(args)?;
            encode_result(save_paid_backend_config(
                args.release_base_url,
                args.token_endpoint,
                args.issuance_endpoint,
            ))
        }
        "set_paid_session_token" => {
            let args: SessionTokenArgs = decode(args)?;
            encode_result(set_paid_session_token(args.token))
        }
        "acquire_paid_session" => {
            let args: AcquireSessionArgs = decode(args)?;
            encode_result(acquire_paid_session(args.customer_id, args.access_token))
        }
        "clear_paid_session" => {
            let _: EmptyArgs = decode(args)?;
            encode_result(clear_paid_session())
        }
        "run_paid_full_stack_install" => {
            let args: InstallArgs = decode(args)?;
            encode_result(run_paid_full_stack_install(args.confirm, args.dry_run))
        }
        "run_doctor_action" => {
            let args: DoctorArgs = decode(args)?;
            encode_result(run_doctor_action(
                args.fix,
                args.bootstrap,
                args.dry_run,
                args.confirm,
            ))
        }
        _ => Err(format!("unknown Tauri command: {command}")),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use reqwest::Client;
    use serde_json::{json, Value};

    use super::*;

    fn skip_space(source: &str, mut cursor: usize) -> usize {
        while source
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        cursor
    }

    fn skip_balanced(source: &str, start: usize, open: u8, close: u8) -> Option<usize> {
        let bytes = source.as_bytes();
        let mut cursor = start;
        let mut depth = 0_u32;
        let mut quote = None;
        let mut escaped = false;
        while let Some(&byte) = bytes.get(cursor) {
            if let Some(delimiter) = quote {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == delimiter {
                    quote = None;
                }
            } else if matches!(byte, b'\'' | b'"' | b'`') {
                quote = Some(byte);
            } else if byte == open {
                depth += 1;
            } else if byte == close {
                depth -= 1;
                if depth == 0 {
                    return Some(cursor + 1);
                }
            }
            cursor += 1;
        }
        None
    }

    fn literal_object_keys(source: &str, start: usize, end: usize) -> Vec<String> {
        let bytes = source.as_bytes();
        let mut keys = Vec::new();
        let mut cursor = start + 1;
        let mut segment_start = cursor;
        let mut braces = 0_u32;
        let mut brackets = 0_u32;
        let mut parentheses = 0_u32;
        let mut quote = None;
        let mut escaped = false;

        while cursor < end - 1 {
            let byte = bytes[cursor];
            if let Some(delimiter) = quote {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == delimiter {
                    quote = None;
                }
            } else {
                match byte {
                    b'\'' | b'"' | b'`' => quote = Some(byte),
                    b'{' => braces += 1,
                    b'}' => braces -= 1,
                    b'[' => brackets += 1,
                    b']' => brackets -= 1,
                    b'(' => parentheses += 1,
                    b')' => parentheses -= 1,
                    b',' if braces == 0 && brackets == 0 && parentheses == 0 => {
                        if let Some(key) = literal_object_key(&source[segment_start..cursor]) {
                            keys.push(key);
                        }
                        segment_start = cursor + 1;
                    }
                    _ => {}
                }
            }
            cursor += 1;
        }
        if let Some(key) = literal_object_key(&source[segment_start..end - 1]) {
            keys.push(key);
        }
        keys
    }

    fn literal_object_key(segment: &str) -> Option<String> {
        let segment = segment.trim();
        if segment.is_empty() || segment.starts_with("...") {
            return None;
        }
        let end = segment
            .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .unwrap_or(segment.len());
        (end > 0).then(|| segment[..end].to_string())
    }

    fn app_literal_invoke_payloads(source: &str) -> Vec<(String, Vec<String>)> {
        let bytes = source.as_bytes();
        let mut payloads = Vec::new();
        let mut search_from = 0;
        while let Some(offset) = source[search_from..].find("invoke") {
            let invoke_start = search_from + offset;
            let mut cursor = skip_space(source, invoke_start + "invoke".len());
            if bytes.get(cursor) == Some(&b'<') {
                cursor =
                    skip_balanced(source, cursor, b'<', b'>').expect("balanced invoke generic");
                cursor = skip_space(source, cursor);
            }
            if bytes.get(cursor) != Some(&b'(') {
                search_from = invoke_start + "invoke".len();
                continue;
            }
            cursor = skip_space(source, cursor + 1);
            let Some(&quote @ (b'\'' | b'"')) = bytes.get(cursor) else {
                search_from = invoke_start + "invoke".len();
                continue;
            };
            let command_start = cursor + 1;
            cursor = command_start;
            while bytes.get(cursor) != Some(&quote) {
                cursor += 1;
            }
            let command = source[command_start..cursor].to_string();
            cursor = skip_space(source, cursor + 1);
            let keys = if bytes.get(cursor) == Some(&b',') {
                cursor = skip_space(source, cursor + 1);
                if bytes.get(cursor) == Some(&b'{') {
                    let end = skip_balanced(source, cursor, b'{', b'}')
                        .expect("balanced invoke argument object");
                    literal_object_keys(source, cursor, end)
                } else {
                    search_from = cursor + 1;
                    continue;
                }
            } else if bytes.get(cursor) == Some(&b')') {
                Vec::new()
            } else {
                search_from = cursor + 1;
                continue;
            };
            payloads.push((command, keys));
            search_from = cursor + 1;
        }
        payloads
    }

    fn representative_payload(command: &str, keys: &[String]) -> Value {
        let mut payload = serde_json::Map::new();
        for key in keys {
            let value = match key.as_str() {
                "action" => match command {
                    "run_volume_action" => json!("create"),
                    "run_network_action" => json!("create"),
                    "run_compose_action" => json!("up"),
                    _ => json!("vm_start"),
                },
                "data" => json!([65]),
                "columns" | "rows" | "memory" | "cpuQuota" | "cpuPeriod" => json!(1),
                "env" | "environment" | "command" | "ports" | "volumes" | "ids" => json!([]),
                "fix" | "bootstrap" | "dry_run" | "confirm" | "pullIfMissing" => json!(false),
                "user" | "workdir" | "name" | "subnet" | "issuance_endpoint" | "access_token" => {
                    Value::Null
                }
                _ => json!("test-value"),
            };
            payload.insert(key.clone(), value);
        }
        Value::Object(payload)
    }

    fn assert_bridge_args_decode(command: &str, args: Value) -> Result<(), String> {
        match command {
            "get_desktop_snapshot"
            | "get_volumes"
            | "get_networks"
            | "stop_log_follow"
            | "close_terminal"
            | "get_paid_auth_state"
            | "clear_paid_session" => decode::<EmptyArgs>(args).map(drop),
            "get_container_stats" => decode::<ContainerStatsArgs>(args).map(drop),
            "get_container_detail" | "start_log_follow" => decode::<TargetArgs>(args).map(drop),
            "get_compose_snapshot" => decode::<ComposeArgs>(args).map(drop),
            "build_image" => decode::<BuildImageArgs>(args).map(drop),
            "run_desktop_action" => decode::<DesktopActionArgs>(args).map(drop),
            "run_compose_action" => decode::<ComposeActionArgs>(args).map(drop),
            "run_volume_action" => decode::<VolumeActionArgs>(args).map(drop),
            "run_network_action" => decode::<NetworkActionArgs>(args).map(drop),
            "update_container_resources" => decode::<ContainerResourcesArgs>(args).map(drop),
            "run_new_container" => decode::<NewContainerArgs>(args).map(drop),
            "get_registry_auth_status" | "logout_registry" => {
                decode::<RegistryArgs>(args).map(drop)
            }
            "login_registry" => decode::<RegistryLoginArgs>(args).map(drop),
            "start_terminal" => decode::<TerminalArgs>(args).map(drop),
            "write_terminal" => decode::<TerminalWriteArgs>(args).map(drop),
            "resize_terminal" => decode::<TerminalResizeArgs>(args).map(drop),
            "save_paid_backend_config" => decode::<PaidConfigArgs>(args).map(drop),
            "set_paid_session_token" => decode::<SessionTokenArgs>(args).map(drop),
            "acquire_paid_session" => decode::<AcquireSessionArgs>(args).map(drop),
            "run_paid_full_stack_install" => decode::<InstallArgs>(args).map(drop),
            "run_doctor_action" => decode::<DoctorArgs>(args).map(drop),
            _ => Err(format!("missing bridge argument decoder for {command}")),
        }
    }

    #[test]
    fn every_app_literal_invoke_payload_decodes_for_its_bridge_command() {
        let app = include_str!("../../src/App.tsx");
        let payloads = app_literal_invoke_payloads(app);
        assert!(payloads.len() >= 30, "expected all App.tsx invoke sites");
        for (command, keys) in payloads {
            let payload = representative_payload(&command, &keys);
            assert_bridge_args_decode(&command, payload.clone()).unwrap_or_else(|error| {
                panic!("{command} payload with keys {keys:?} did not decode: {error}; {payload}")
            });
        }
    }

    #[test]
    fn run_new_container_bridge_decodes_every_native_argument() {
        let args = decode::<NewContainerArgs>(json!({
            "image": "alpine:latest",
            "name": "demo",
            "command": ["echo", "ready"],
            "ports": ["8080:80"],
            "volumes": ["data:/data"],
            "pullIfMissing": true,
            "environment": ["MODE=test"],
            "memory": 1048576,
            "cpuQuota": 50000,
            "cpuPeriod": 100000
        }))
        .expect("browser payload");

        assert_eq!(args.command, ["echo", "ready"]);
        assert_eq!(args.ports, ["8080:80"]);
        assert_eq!(args.volumes, ["data:/data"]);
        assert!(args.pull_if_missing);
    }

    #[test]
    fn multiword_bridge_arguments_accept_native_snake_and_browser_camel_case() {
        let cases = [
            (
                "build_image",
                json!({ "context": ".", "tag": "test", "build_id": "one" }),
                json!({ "context": ".", "tag": "test", "buildId": "one" }),
            ),
            (
                "update_container_resources",
                json!({ "target": "one", "memory": 1, "cpu_quota": 2, "cpu_period": 3 }),
                json!({ "target": "one", "memory": 1, "cpuQuota": 2, "cpuPeriod": 3 }),
            ),
            (
                "run_new_container",
                json!({ "image": "one", "name": null, "command": [], "ports": [], "volumes": [], "pull_if_missing": false, "environment": [], "memory": null, "cpu_quota": 2, "cpu_period": 3 }),
                json!({ "image": "one", "name": null, "command": [], "ports": [], "volumes": [], "pullIfMissing": false, "environment": [], "memory": null, "cpuQuota": 2, "cpuPeriod": 3 }),
            ),
            (
                "save_paid_backend_config",
                json!({ "release_base_url": "one", "token_endpoint": "two", "issuance_endpoint": null }),
                json!({ "releaseBaseUrl": "one", "tokenEndpoint": "two", "issuanceEndpoint": null }),
            ),
            (
                "acquire_paid_session",
                json!({ "customer_id": "one", "access_token": null }),
                json!({ "customerId": "one", "accessToken": null }),
            ),
            (
                "run_paid_full_stack_install",
                json!({ "confirm": false, "dry_run": true }),
                json!({ "confirm": false, "dryRun": true }),
            ),
            (
                "run_doctor_action",
                json!({ "fix": false, "bootstrap": false, "dry_run": true, "confirm": false }),
                json!({ "fix": false, "bootstrap": false, "dryRun": true, "confirm": false }),
            ),
        ];

        for (command, snake_case, camel_case) in cases {
            assert_bridge_args_decode(command, snake_case)
                .unwrap_or_else(|error| panic!("{command} rejected snake_case: {error}"));
            assert_bridge_args_decode(command, camel_case)
                .unwrap_or_else(|error| panic!("{command} rejected camelCase: {error}"));
        }
    }

    #[tokio::test]
    async fn multiplexed_stream_does_not_block_eight_concurrent_posts() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dist = std::env::temp_dir().join(format!("ferro-web-bridge-concurrency-{suffix}"));
        fs::create_dir_all(&dist).expect("create dist");
        fs::write(dist.join("index.html"), "<main>Ferrocrate</main>").expect("write index");

        let bridge = spawn_web_bridge("127.0.0.1:0".parse().unwrap(), dist.clone())
            .await
            .expect("start bridge");
        let client = Client::new();
        let host = bridge.addr().to_string();
        let stream_url = format!(
            "http://{}/__tauri/stream?token={}",
            bridge.addr(),
            bridge.token()
        );
        let stream = client
            .get(stream_url)
            .header("host", &host)
            .send()
            .await
            .expect("connect multiplexed stream");
        assert_eq!(stream.status(), reqwest::StatusCode::OK);
        assert_eq!(
            stream.headers().get(reqwest::header::CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );
        let legacy_stream = client
            .get(format!(
                "http://{}/__tauri/stream/start_terminal?token={}",
                bridge.addr(),
                bridge.token()
            ))
            .header("host", &host)
            .send()
            .await
            .expect("legacy stream request");
        assert_ne!(
            legacy_stream.headers().get(reqwest::header::CONTENT_TYPE),
            Some(&reqwest::header::HeaderValue::from_static(
                "text/event-stream"
            ))
        );

        let endpoint = format!("http://{}/__tauri/get_desktop_snapshot", bridge.addr());
        let mut requests = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let client = client.clone();
            let endpoint = endpoint.clone();
            let host = host.clone();
            let token = bridge.token().to_string();
            requests.spawn(async move {
                client
                    .post(endpoint)
                    .header("host", host)
                    .bearer_auth(token)
                    .json(&json!({}))
                    .send()
                    .await
            });
        }

        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(result) = requests.join_next().await {
                let response = result.expect("post task").expect("post response");
                assert!(response.status().is_success());
            }
        })
        .await
        .expect("eight POSTs should complete while the SSE stream is open");

        drop(stream);
        bridge.shutdown().await;
        fs::remove_dir_all(dist).ok();
    }

    #[tokio::test]
    async fn bridge_boots_and_dispatches_desktop_commands() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dist = std::env::temp_dir().join(format!("ferro-web-bridge-{suffix}"));
        fs::create_dir_all(&dist).expect("create dist");
        fs::write(dist.join("index.html"), "<main>Ferrocrate</main>").expect("write index");

        let bridge = spawn_web_bridge("127.0.0.1:0".parse().unwrap(), dist.clone())
            .await
            .expect("start bridge");
        let client = Client::new();
        let endpoint = |command: &str| format!("http://{}/__tauri/{command}", bridge.addr());
        let authorized = |request: reqwest::RequestBuilder| {
            request
                .header("host", bridge.addr().to_string())
                .bearer_auth(bridge.token())
        };

        let snapshot = authorized(client.post(endpoint("get_desktop_snapshot")))
            .json(&json!({}))
            .send()
            .await
            .expect("snapshot request");
        assert!(snapshot.status().is_success());
        let snapshot: Value = snapshot.json().await.expect("snapshot json");
        assert!(snapshot.get("runtime").is_some());

        let stats = authorized(client.post(endpoint("get_container_stats")))
            .json(&json!({ "ids": [] }))
            .send()
            .await
            .expect("stats request");
        assert!(stats.status().is_success());
        let stats: Value = stats.json().await.expect("stats json");
        assert_eq!(stats["samples"], json!([]));

        let action = authorized(client.post(endpoint("run_desktop_action")))
            .json(&json!({ "action": "pull_image", "target": null }))
            .send()
            .await
            .expect("action request");
        assert!(action.status().is_success());
        let action: Value = action.json().await.expect("action json");
        assert_eq!(action["ok"], false);

        let terminal = authorized(client.post(endpoint("start_terminal")))
            .json(&json!({ "target": "", "shell": "sh", "env": [], "user": null, "workdir": null }))
            .send()
            .await
            .expect("terminal request");
        assert_eq!(terminal.status(), reqwest::StatusCode::BAD_REQUEST);
        let terminal: Value = terminal.json().await.expect("terminal error json");
        assert_eq!(terminal["error"], "target container is required");

        bridge.shutdown().await;
        fs::remove_dir_all(dist).ok();
    }

    #[tokio::test]
    async fn bridge_doctor_accepts_snake_case_and_returns_summary() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dist = std::env::temp_dir().join(format!("ferro-web-bridge-doctor-{suffix}"));
        fs::create_dir_all(&dist).expect("create dist");
        fs::write(dist.join("index.html"), "<main>Ferrocrate</main>").expect("write index");

        let bridge = spawn_web_bridge("127.0.0.1:0".parse().unwrap(), dist.clone())
            .await
            .expect("start bridge");
        let response = Client::new()
            .post(format!(
                "http://{}/__tauri/run_doctor_action",
                bridge.addr()
            ))
            .header("host", bridge.addr().to_string())
            .bearer_auth(bridge.token())
            .json(&json!({
                "fix": false,
                "bootstrap": false,
                "dry_run": true,
                "confirm": false
            }))
            .send()
            .await
            .expect("doctor request");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let summary: DoctorSummary = response.json().await.expect("DoctorSummary response");
        assert!(summary.raw.is_object());

        bridge.shutdown().await;
        fs::remove_dir_all(dist).ok();
    }

    #[tokio::test]
    async fn bridge_rejects_unauthorized_and_untrusted_browser_requests() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dist = std::env::temp_dir().join(format!("ferro-web-bridge-auth-{suffix}"));
        fs::create_dir_all(&dist).expect("create dist");
        fs::write(dist.join("index.html"), "<main>Ferrocrate</main>").expect("write index");

        let bridge = spawn_web_bridge("127.0.0.1:0".parse().unwrap(), dist.clone())
            .await
            .expect("start bridge");
        let client = Client::new();
        let endpoint = format!("http://{}/__tauri/get_desktop_snapshot", bridge.addr());
        let host = bridge.addr().to_string();

        let missing = client
            .post(&endpoint)
            .header("host", &host)
            .json(&json!({}))
            .send()
            .await
            .expect("missing token request");
        assert_eq!(missing.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(missing.bytes().await.expect("empty response").len(), 0);

        let wrong_host = client
            .post(&endpoint)
            .header("host", "attacker.example")
            .bearer_auth(bridge.token())
            .json(&json!({}))
            .send()
            .await
            .expect("wrong host request");
        assert_eq!(
            wrong_host.status(),
            reqwest::StatusCode::MISDIRECTED_REQUEST
        );

        let foreign_origin = client
            .post(&endpoint)
            .header("host", &host)
            .header("origin", "https://attacker.example")
            .bearer_auth(bridge.token())
            .json(&json!({}))
            .send()
            .await
            .expect("foreign origin request");
        assert_eq!(foreign_origin.status(), reqwest::StatusCode::FORBIDDEN);

        let valid = client
            .post(&endpoint)
            .header("host", &host)
            .bearer_auth(bridge.token())
            .json(&json!({}))
            .send()
            .await
            .expect("valid request");
        assert_eq!(valid.status(), reqwest::StatusCode::OK);

        bridge.shutdown().await;
        fs::remove_dir_all(dist).ok();
    }
}

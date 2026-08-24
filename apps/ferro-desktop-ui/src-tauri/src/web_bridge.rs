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
#[serde(rename_all = "camelCase")]
struct BuildImageArgs {
    context: String,
    tag: String,
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
#[serde(rename_all = "camelCase")]
struct ContainerResourcesArgs {
    target: String,
    memory: Option<u64>,
    cpu_quota: Option<u64>,
    cpu_period: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewContainerArgs {
    image: String,
    name: Option<String>,
    environment: Vec<String>,
    memory: Option<u64>,
    cpu_quota: Option<u64>,
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
#[serde(rename_all = "camelCase")]
struct PaidConfigArgs {
    release_base_url: String,
    token_endpoint: String,
    issuance_endpoint: Option<String>,
}

#[derive(Deserialize)]
struct SessionTokenArgs {
    token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcquireSessionArgs {
    customer_id: String,
    access_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallArgs {
    confirm: bool,
    dry_run: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DoctorArgs {
    fix: bool,
    bootstrap: bool,
    dry_run: bool,
    confirm: bool,
}

fn dispatch_command(command: &str, args: Value, events: WebEventHub) -> Result<Value, String> {
    match command {
        "get_desktop_snapshot" => {
            let _: EmptyArgs = decode(args)?;
            encode(get_desktop_snapshot())
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

    use super::spawn_web_bridge;

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
    async fn bridge_boots_and_dispatches_three_desktop_commands() {
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

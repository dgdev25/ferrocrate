//! Shared browser transport for Ferrocrate's desktop and dashboard surfaces.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Request, StatusCode, Uri};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, oneshot};

use axum_server::tls_rustls::RustlsConfig;

const MAX_REPLAY_EVENTS: usize = 512;
const MAX_REPLAY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct EventRecord {
    id: u64,
    name: String,
    payload: Value,
}

impl EventRecord {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn payload(&self) -> &Value {
        &self.payload
    }
}

#[derive(Debug)]
pub struct EventReplay {
    pub events: Vec<EventRecord>,
    pub baseline: u64,
    pub gap: bool,
}

#[derive(Default)]
struct ReplayState {
    next_id: u64,
    events: VecDeque<EventRecord>,
    bytes: usize,
}

#[derive(Clone)]
pub struct EventHub {
    sender: broadcast::Sender<EventRecord>,
    replay: Arc<Mutex<ReplayState>>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(256);
        Self {
            sender,
            replay: Arc::new(Mutex::new(ReplayState::default())),
        }
    }

    pub fn emit<T: Serialize>(&self, name: &str, payload: T) {
        let Ok(payload) = serde_json::to_value(payload) else {
            return;
        };
        let Ok(mut replay) = self.replay.lock() else {
            return;
        };
        replay.next_id = replay.next_id.saturating_add(1);
        let event = EventRecord {
            id: replay.next_id,
            name: name.to_string(),
            payload,
        };
        let event_bytes = event.name.len()
            + serde_json::to_vec(&event.payload)
                .map(|payload| payload.len())
                .unwrap_or(MAX_REPLAY_BYTES.saturating_add(1));
        if event_bytes <= MAX_REPLAY_BYTES {
            replay.bytes = replay.bytes.saturating_add(event_bytes);
            replay.events.push_back(event.clone());
            while replay.events.len() > MAX_REPLAY_EVENTS || replay.bytes > MAX_REPLAY_BYTES {
                if let Some(removed) = replay.events.pop_front() {
                    replay.bytes = replay.bytes.saturating_sub(
                        removed.name.len()
                            + serde_json::to_vec(&removed.payload)
                                .map(|payload| payload.len())
                                .unwrap_or(0),
                    );
                } else {
                    replay.bytes = 0;
                    break;
                }
            }
        }
        let _ = self.sender.send(event);
    }

    pub fn replay_after(&self, requested_id: u64) -> EventReplay {
        let Ok(replay) = self.replay.lock() else {
            return EventReplay {
                events: Vec::new(),
                baseline: requested_id,
                gap: true,
            };
        };
        let baseline = requested_id.min(replay.next_id);
        let gap = replay.events.front().is_some_and(|first| {
            baseline < replay.next_id && first.id > baseline.saturating_add(1)
        });
        let events = replay
            .events
            .iter()
            .filter(|event| event.id > baseline)
            .cloned()
            .collect();
        EventReplay {
            events,
            baseline,
            gap,
        }
    }
}

pub trait StaticAssets: Send + Sync {
    fn get(&self, path: &str) -> Option<(Vec<u8>, &'static str)>;
}

pub trait CommandDispatcher: Send + Sync {
    fn dispatch(&self, request: CommandRequest, events: EventHub) -> Result<Value, String>;
}

#[derive(Clone)]
struct BridgeState {
    events: EventHub,
    assets: Arc<dyn StaticAssets>,
    dispatcher: Arc<dyn CommandDispatcher>,
}

#[derive(Clone)]
struct RequestGuard {
    token: String,
    allowed_hosts: Vec<String>,
    allow_ip_literals: bool,
}

impl RequestGuard {
    fn new(addr: SocketAddr, token: String) -> Self {
        let mut allowed_hosts = vec![addr.to_string(), format!("localhost:{}", addr.port())];
        if addr.ip().is_ipv6() {
            allowed_hosts.push(format!("[::1]:{}", addr.port()));
        }
        Self {
            token,
            allowed_hosts,
            allow_ip_literals: addr.ip().is_unspecified(),
        }
    }

    fn allows_host(&self, host: &str) -> bool {
        self.allowed_hosts.iter().any(|item| item == host)
            || (self.allow_ip_literals
                && host
                    .parse::<SocketAddr>()
                    .is_ok_and(|address| address.port() == self.port()))
    }

    fn port(&self) -> u16 {
        self.allowed_hosts
            .first()
            .and_then(|host| host.parse::<SocketAddr>().ok())
            .map_or(0, |address| address.port())
    }
}

pub struct Server {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), String>>,
    events: EventHub,
}

impl Server {
    pub async fn spawn_loopback(
        addr: SocketAddr,
        token: String,
        assets: Arc<dyn StaticAssets>,
        dispatcher: Arc<dyn CommandDispatcher>,
    ) -> Result<Self, String> {
        if !addr.ip().is_loopback() {
            return Err(format!("refusing non-loopback dashboard bind {addr}"));
        }
        Self::spawn(addr, token, assets, dispatcher).await
    }

    pub async fn spawn(
        addr: SocketAddr,
        token: String,
        assets: Arc<dyn StaticAssets>,
        dispatcher: Arc<dyn CommandDispatcher>,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|error| format!("failed to bind web server at {addr}: {error}"))?;
        let addr = listener
            .local_addr()
            .map_err(|error| format!("failed to inspect web server address: {error}"))?;
        let events = EventHub::new();
        let app = router(addr, token, assets, dispatcher, events.clone());
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .map_err(|error| format!("web server failed: {error}"))
        });
        Ok(Self {
            addr,
            shutdown: Some(shutdown),
            task,
            events,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    pub fn events(&self) -> &EventHub {
        &self.events
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }

    pub async fn wait(mut self) -> Result<(), String> {
        let _shutdown = self.shutdown.take();
        self.task
            .await
            .map_err(|error| format!("web server task failed: {error}"))?
    }
}

pub fn generate_session_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| format!("failed to generate web session token: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub async fn serve_tls(
    addr: SocketAddr,
    token: String,
    cert: &std::path::Path,
    key: &std::path::Path,
    assets: Arc<dyn StaticAssets>,
    dispatcher: Arc<dyn CommandDispatcher>,
) -> Result<(), String> {
    install_tls_crypto_provider();
    let config = RustlsConfig::from_pem_file(cert, key)
        .await
        .map_err(|error| format!("failed to load dashboard TLS identity: {error}"))?;
    let listener = std::net::TcpListener::bind(addr)
        .map_err(|error| format!("failed to bind TLS web server at {addr}: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("failed to configure TLS web listener: {error}"))?;
    let addr = listener
        .local_addr()
        .map_err(|error| format!("failed to inspect TLS web listener: {error}"))?;
    let app = router(addr, token, assets, dispatcher, EventHub::new());
    axum_server::from_tcp_rustls(listener, config)
        .map_err(|error| format!("failed to configure TLS web server: {error}"))?
        .serve(app.into_make_service())
        .await
        .map_err(|error| format!("TLS web server failed: {error}"))
}

fn install_tls_crypto_provider() {
    // The workspace also uses crates that enable rustls' ring backend. Select
    // one provider explicitly so TLS startup does not depend on feature
    // unification across the final binary.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn router(
    addr: SocketAddr,
    token: String,
    assets: Arc<dyn StaticAssets>,
    dispatcher: Arc<dyn CommandDispatcher>,
    events: EventHub,
) -> Router {
    let guard = RequestGuard::new(addr, token);
    Router::new()
        .route("/__tauri/stream", get(stream_events))
        .route("/__tauri/{command}", post(invoke_command))
        .fallback(serve_asset)
        .route_layer(from_fn_with_state(guard, validate_request))
        .with_state(BridgeState {
            events,
            assets,
            dispatcher,
        })
}

async fn validate_request(
    State(guard): State<RequestGuard>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let host = request_host(&request);
    let Some(host) = host.filter(|host| guard.allows_host(host)) else {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    };
    if let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        let scheme = request.uri().scheme_str().unwrap_or("http");
        if origin != format!("{scheme}://{host}") && origin != format!("https://{host}") {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    if request.uri().path().starts_with("/__tauri/") {
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
    }
    next.run(request).await
}

fn request_host(request: &Request<Body>) -> Option<&str> {
    request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str())
        })
}

fn constant_time_eq(candidate: &[u8], expected: &[u8]) -> bool {
    candidate.len() == expected.len()
        && candidate
            .iter()
            .zip(expected)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

async fn serve_asset(State(state): State<BridgeState>, uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let asset = state
        .assets
        .get(if path.is_empty() { "index.html" } else { path })
        .or_else(|| state.assets.get("index.html"));
    match asset {
        Some((bytes, mime)) => ([(header::CONTENT_TYPE, mime)], bytes).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn invoke_command(
    State(state): State<BridgeState>,
    Path(command): Path<String>,
    Json(args): Json<Value>,
) -> impl IntoResponse {
    let request = match CommandRequest::decode(&command, args) {
        Ok(request) => request,
        Err(error) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))),
    };
    let dispatcher = state.dispatcher.clone();
    let events = state.events.clone();
    match tokio::task::spawn_blocking(move || dispatcher.dispatch(request, events)).await {
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
    headers: HeaderMap,
) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let mut receiver = state.events.sender.subscribe();
    let requested_id = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let hub = state.events.clone();
    let replay = requested_id
        .map(|id| hub.replay_after(id))
        .unwrap_or_else(|| hub.replay_after(u64::MAX));
    let mut last_sent = replay.baseline;
    let stream = async_stream::stream! {
        if replay.gap { yield Ok(Event::default().event("terminal-error").json_data("Terminal output continuity was lost; some buffered output is unavailable.").unwrap_or_else(|_| Event::default())); }
        for event in replay.events {
            last_sent = event.id;
            yield Ok(to_sse(event));
        }
        loop {
            match receiver.recv().await {
                Ok(event) if event.id > last_sent => { last_sent = event.id; yield Ok(to_sse(event)); }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let replay = hub.replay_after(last_sent);
                    if replay.gap { yield Ok(Event::default().event("terminal-error").json_data("Terminal output continuity was lost; some buffered output is unavailable.").unwrap_or_else(|_| Event::default())); }
                    for event in replay.events { last_sent = event.id; yield Ok(to_sse(event)); }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn to_sse(event: EventRecord) -> Event {
    Event::default()
        .id(event.id.to_string())
        .event(event.name)
        .json_data(event.payload)
        .unwrap_or_else(|_| Event::default())
}

fn decode<T: DeserializeOwned>(args: Value) -> Result<T, String> {
    serde_json::from_value(args).map_err(|error| format!("invalid command arguments: {error}"))
}

macro_rules! args_struct {
    ($name:ident { $($field:ident : $kind:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize)]
        pub struct $name { $(pub $field: $kind),* }
    };
}

args_struct!(TargetArgs { target: String });
args_struct!(ContainerStatsArgs { ids: Vec<String> });
args_struct!(TerminalArgs { target: String, shell: String, env: Vec<String>, user: Option<String>, workdir: Option<String> });
args_struct!(TerminalWriteArgs { data: Vec<u8> });
args_struct!(TerminalResizeArgs {
    columns: u16,
    rows: u16
});
args_struct!(DesktopActionArgs { action: Value, target: Option<String> });
args_struct!(ComposeArgs { file: String });
args_struct!(ComposeActionArgs {
    file: String,
    action: Value
});
args_struct!(VolumeActionArgs { action: Value, target: Option<String> });
args_struct!(NetworkActionArgs { action: Value, target: Option<String>, subnet: Option<String> });
args_struct!(RegistryArgs { registry: String });
args_struct!(RegistryLoginArgs {
    registry: String,
    username: String,
    password: String
});
args_struct!(SessionTokenArgs { token: String });

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BuildImageArgs {
    pub context: String,
    pub tag: String,
    #[serde(alias = "buildId")]
    pub build_id: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContainerResourcesArgs {
    pub target: String,
    pub memory: Option<u64>,
    #[serde(alias = "cpuQuota")]
    pub cpu_quota: Option<u64>,
    #[serde(alias = "cpuPeriod")]
    pub cpu_period: Option<u64>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NewContainerArgs {
    pub image: String,
    pub name: Option<String>,
    pub command: Vec<String>,
    pub ports: Vec<String>,
    pub volumes: Vec<String>,
    #[serde(alias = "pullIfMissing")]
    pub pull_if_missing: bool,
    pub environment: Vec<String>,
    pub memory: Option<u64>,
    #[serde(alias = "cpuQuota")]
    pub cpu_quota: Option<u64>,
    #[serde(alias = "cpuPeriod")]
    pub cpu_period: Option<u64>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PaidConfigArgs {
    #[serde(alias = "releaseBaseUrl")]
    pub release_base_url: String,
    #[serde(alias = "tokenEndpoint")]
    pub token_endpoint: String,
    #[serde(alias = "issuanceEndpoint")]
    pub issuance_endpoint: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AcquireSessionArgs {
    #[serde(alias = "customerId")]
    pub customer_id: String,
    #[serde(alias = "accessToken")]
    pub access_token: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InstallArgs {
    pub confirm: bool,
    #[serde(alias = "dryRun")]
    pub dry_run: bool,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DoctorArgs {
    pub fix: bool,
    pub bootstrap: bool,
    #[serde(alias = "dryRun")]
    pub dry_run: bool,
    pub confirm: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LaunchPortsArgs {
    pub ports: Vec<u16>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct ReplacePortArgs {
    pub port: u16,
    pub expected: Value,
    pub confirmation: String,
}

#[derive(Clone, Debug)]
pub enum CommandRequest {
    GetDesktopSnapshot,
    GetContainerStats(ContainerStatsArgs),
    GetVolumes,
    GetNetworks,
    GetContainerDetail(TargetArgs),
    GetComposeSnapshot(ComposeArgs),
    BuildImage(BuildImageArgs),
    RunDesktopAction(DesktopActionArgs),
    RunComposeAction(ComposeActionArgs),
    RunVolumeAction(VolumeActionArgs),
    RunNetworkAction(NetworkActionArgs),
    UpdateContainerResources(ContainerResourcesArgs),
    RunNewContainer(NewContainerArgs),
    PreflightContainerPorts(LaunchPortsArgs),
    ReplacePortConflict(ReplacePortArgs),
    GetRegistryAuthStatus(RegistryArgs),
    LoginRegistry(RegistryLoginArgs),
    LogoutRegistry(RegistryArgs),
    StartLogFollow { target: String },
    StopLogFollow,
    StartTerminal(TerminalArgs),
    WriteTerminal(TerminalWriteArgs),
    ResizeTerminal(TerminalResizeArgs),
    CloseTerminal,
    GetPaidAuthState,
    SavePaidBackendConfig(PaidConfigArgs),
    SetPaidSessionToken(SessionTokenArgs),
    AcquirePaidSession(AcquireSessionArgs),
    ClearPaidSession,
    RunPaidFullStackInstall(InstallArgs),
    RunDoctorAction(DoctorArgs),
}

impl CommandRequest {
    pub fn decode(command: &str, args: Value) -> Result<Self, String> {
        Ok(match command {
            "get_desktop_snapshot" => {
                decode::<serde_json::Map<String, Value>>(args)?;
                Self::GetDesktopSnapshot
            }
            "get_container_stats" => Self::GetContainerStats(decode(args)?),
            "get_volumes" => {
                decode::<serde_json::Map<String, Value>>(args)?;
                Self::GetVolumes
            }
            "get_networks" => {
                decode::<serde_json::Map<String, Value>>(args)?;
                Self::GetNetworks
            }
            "get_container_detail" => Self::GetContainerDetail(decode(args)?),
            "get_compose_snapshot" => Self::GetComposeSnapshot(decode(args)?),
            "build_image" => Self::BuildImage(decode(args)?),
            "run_desktop_action" => Self::RunDesktopAction(decode(args)?),
            "run_compose_action" => Self::RunComposeAction(decode(args)?),
            "run_volume_action" => Self::RunVolumeAction(decode(args)?),
            "run_network_action" => Self::RunNetworkAction(decode(args)?),
            "update_container_resources" => Self::UpdateContainerResources(decode(args)?),
            "preflight_container_ports" => Self::PreflightContainerPorts(decode(args)?),
            "replace_port_conflict" => Self::ReplacePortConflict(decode(args)?),
            "run_new_container" => Self::RunNewContainer(decode(args)?),
            "get_registry_auth_status" => Self::GetRegistryAuthStatus(decode(args)?),
            "login_registry" => Self::LoginRegistry(decode(args)?),
            "logout_registry" => Self::LogoutRegistry(decode(args)?),
            "start_log_follow" => Self::StartLogFollow {
                target: decode::<TargetArgs>(args)?.target,
            },
            "stop_log_follow" => {
                decode::<serde_json::Map<String, Value>>(args)?;
                Self::StopLogFollow
            }
            "start_terminal" => Self::StartTerminal(decode(args)?),
            "write_terminal" => Self::WriteTerminal(decode(args)?),
            "resize_terminal" => Self::ResizeTerminal(decode(args)?),
            "close_terminal" => {
                decode::<serde_json::Map<String, Value>>(args)?;
                Self::CloseTerminal
            }
            "get_paid_auth_state" => {
                decode::<serde_json::Map<String, Value>>(args)?;
                Self::GetPaidAuthState
            }
            "save_paid_backend_config" => Self::SavePaidBackendConfig(decode(args)?),
            "set_paid_session_token" => Self::SetPaidSessionToken(decode(args)?),
            "acquire_paid_session" => Self::AcquirePaidSession(decode(args)?),
            "clear_paid_session" => {
                decode::<serde_json::Map<String, Value>>(args)?;
                Self::ClearPaidSession
            }
            "run_paid_full_stack_install" => Self::RunPaidFullStackInstall(decode(args)?),
            "run_doctor_action" => Self::RunDoctorAction(decode(args)?),
            _ => return Err(format!("unknown Tauri command: {command}")),
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::GetDesktopSnapshot => "get_desktop_snapshot",
            Self::GetContainerStats(_) => "get_container_stats",
            Self::GetVolumes => "get_volumes",
            Self::GetNetworks => "get_networks",
            Self::GetContainerDetail(_) => "get_container_detail",
            Self::GetComposeSnapshot(_) => "get_compose_snapshot",
            Self::BuildImage(_) => "build_image",
            Self::RunDesktopAction(_) => "run_desktop_action",
            Self::RunComposeAction(_) => "run_compose_action",
            Self::RunVolumeAction(_) => "run_volume_action",
            Self::RunNetworkAction(_) => "run_network_action",
            Self::UpdateContainerResources(_) => "update_container_resources",
            Self::PreflightContainerPorts(_) => "preflight_container_ports",
            Self::ReplacePortConflict(_) => "replace_port_conflict",
            Self::RunNewContainer(_) => "run_new_container",
            Self::GetRegistryAuthStatus(_) => "get_registry_auth_status",
            Self::LoginRegistry(_) => "login_registry",
            Self::LogoutRegistry(_) => "logout_registry",
            Self::StartLogFollow { .. } => "start_log_follow",
            Self::StopLogFollow => "stop_log_follow",
            Self::StartTerminal(_) => "start_terminal",
            Self::WriteTerminal(_) => "write_terminal",
            Self::ResizeTerminal(_) => "resize_terminal",
            Self::CloseTerminal => "close_terminal",
            Self::GetPaidAuthState => "get_paid_auth_state",
            Self::SavePaidBackendConfig(_) => "save_paid_backend_config",
            Self::SetPaidSessionToken(_) => "set_paid_session_token",
            Self::AcquirePaidSession(_) => "acquire_paid_session",
            Self::ClearPaidSession => "clear_paid_session",
            Self::RunPaidFullStackInstall(_) => "run_paid_full_stack_install",
            Self::RunDoctorAction(_) => "run_doctor_action",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::{json, Value};

    use super::{
        install_tls_crypto_provider, request_host, CommandDispatcher, CommandRequest, EventHub,
        RequestGuard, Server, StaticAssets, MAX_REPLAY_BYTES,
    };

    #[derive(Clone)]
    struct TestAssets;

    impl StaticAssets for TestAssets {
        fn get(&self, path: &str) -> Option<(Vec<u8>, &'static str)> {
            match path {
                "index.html" => Some((b"<main>Ferrocrate</main>".to_vec(), "text/html")),
                "assets/app.js" => Some((b"console.log('forge')".to_vec(), "text/javascript")),
                _ => None,
            }
        }
    }

    #[derive(Clone)]
    struct TestDispatcher;

    impl CommandDispatcher for TestDispatcher {
        fn dispatch(&self, request: CommandRequest, events: EventHub) -> Result<Value, String> {
            match request {
                CommandRequest::GetDesktopSnapshot => Ok(json!({ "surface": "dashboard" })),
                CommandRequest::StartLogFollow { target } => {
                    events.emit("container-log-batch", json!({ "text": target }));
                    Ok(Value::Null)
                }
                other => Err(format!("unsupported test command: {}", other.name())),
            }
        }
    }

    #[tokio::test]
    async fn server_guards_requests_and_serves_spa_assets() {
        let server = Server::spawn_loopback(
            "127.0.0.1:0".parse().unwrap(),
            "test-token".to_string(),
            Arc::new(TestAssets),
            Arc::new(TestDispatcher),
        )
        .await
        .expect("start server");
        let client = reqwest::Client::new();
        let endpoint = format!("http://{}/__tauri/get_desktop_snapshot", server.addr());
        let host = server.addr().to_string();

        assert_eq!(
            client
                .post(&endpoint)
                .header("host", &host)
                .json(&json!({}))
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        assert_eq!(
            client
                .post(&endpoint)
                .header("host", "attacker.invalid")
                .bearer_auth("test-token")
                .json(&json!({}))
                .send()
                .await
                .unwrap()
                .status(),
            421
        );
        assert_eq!(
            client
                .post(&endpoint)
                .header("host", &host)
                .header("origin", "https://attacker.invalid")
                .bearer_auth("test-token")
                .json(&json!({}))
                .send()
                .await
                .unwrap()
                .status(),
            403
        );

        let response = client
            .post(&endpoint)
            .header("host", &host)
            .bearer_auth("test-token")
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.json::<Value>().await.unwrap()["surface"],
            "dashboard"
        );

        let spa = client
            .get(format!("http://{}/containers/mine", server.addr()))
            .header("host", &host)
            .bearer_auth("test-token")
            .send()
            .await
            .unwrap();
        assert_eq!(spa.status(), 200);
        assert!(spa.text().await.unwrap().contains("Ferrocrate"));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn event_hub_replays_multiplexed_events_after_last_event_id() {
        let hub = EventHub::new();
        hub.emit("terminal-output", json!({ "data": [65] }));
        hub.emit("container-log-batch", json!({ "text": "line" }));
        let replay = hub.replay_after(1);
        assert_eq!(replay.events.len(), 1);
        assert_eq!(replay.events[0].name(), "container-log-batch");
        assert!(!replay.gap);
    }

    #[test]
    fn event_hub_bounds_replay_payload_memory() {
        let hub = EventHub::new();
        let payload = "x".repeat(64 * 1024);
        for _ in 0..512 {
            hub.emit("container-log-batch", json!({ "text": payload }));
        }

        let replay = hub.replay_after(0);
        let retained = replay
            .events
            .iter()
            .map(|event| serde_json::to_vec(event.payload()).unwrap().len())
            .sum::<usize>();
        assert!(retained <= MAX_REPLAY_BYTES);
        assert!(replay.gap);
    }

    #[tokio::test]
    async fn wait_keeps_the_listener_alive_until_the_waiter_is_cancelled() {
        let server = Server::spawn_loopback(
            "127.0.0.1:0".parse().unwrap(),
            "test-token".to_string(),
            Arc::new(TestAssets),
            Arc::new(TestDispatcher),
        )
        .await
        .expect("start server");
        let addr = server.addr();
        let waiter = tokio::spawn(server.wait());
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(
            !waiter.is_finished(),
            "wait must retain the shutdown sender"
        );
        let response = reqwest::get(format!("http://{addr}/"))
            .await
            .expect("listener remains reachable");
        assert_eq!(response.status(), 200);
        waiter.abort();
    }

    #[test]
    fn typed_dispatch_accepts_browser_camel_case_aliases() {
        let request = CommandRequest::decode(
            "run_new_container",
            json!({
                "image": "alpine",
                "name": "worker",
                "command": [],
                "ports": [],
                "volumes": [],
                "pullIfMissing": true,
                "environment": [],
                "memory": null,
                "cpuQuota": 50000,
                "cpuPeriod": 100000
            }),
        )
        .expect("decode request");
        let CommandRequest::RunNewContainer(args) = request else {
            panic!("wrong request variant");
        };
        assert!(args.pull_if_missing);
        assert_eq!(args.cpu_quota, Some(50_000));
    }

    #[test]
    fn tls_crypto_provider_is_installed_explicitly() {
        install_tls_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn wildcard_bind_accepts_ip_hosts_but_not_dns_rebinding_hosts() {
        let guard = RequestGuard::new("0.0.0.0:8443".parse().unwrap(), "token".to_string());
        assert!(guard.allows_host("127.0.0.1:8443"));
        assert!(guard.allows_host("192.0.2.10:8443"));
        assert!(!guard.allows_host("192.0.2.10:8000"));
        assert!(!guard.allows_host("attacker.example:8443"));
    }

    #[test]
    fn host_guard_reads_http2_uri_authority() {
        let request = axum::http::Request::builder()
            .uri("https://127.0.0.1:8443/__tauri/get_desktop_snapshot")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(request_host(&request), Some("127.0.0.1:8443"));
    }
}

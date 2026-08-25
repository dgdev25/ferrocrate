use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, Request, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use ferro_web::StaticAssets;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::oneshot};

use super::{AuditJournal, AuditResult, BrowserIdentity, SessionStore};

pub trait FleetUiBackend: Send + Sync {
    fn snapshot(&self) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + '_>>;
    fn operate(
        &self,
        command: &str,
        arguments: Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + '_>>;
}

#[derive(Clone)]
struct UiState {
    assets: Arc<dyn StaticAssets>,
    backend: Arc<dyn FleetUiBackend>,
    audit: Arc<AuditJournal>,
    logins: Arc<SessionStore>,
    sessions: Arc<SessionStore>,
    session_ttl_seconds: i64,
}

pub struct FleetUi {
    state: UiState,
}

pub struct FleetUiServer {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

impl FleetUi {
    pub fn new(
        assets: Arc<dyn StaticAssets>,
        backend: Arc<dyn FleetUiBackend>,
        audit: Arc<AuditJournal>,
        session_ttl_seconds: i64,
    ) -> Result<Self, String> {
        if session_ttl_seconds <= 0 || session_ttl_seconds > 900 {
            return Err("fleet browser session lifetime must be 1-900 seconds".into());
        }
        Ok(Self {
            state: UiState {
                assets,
                backend,
                audit,
                logins: Arc::new(SessionStore::new()),
                sessions: Arc::new(SessionStore::new()),
                session_ttl_seconds,
            },
        })
    }

    pub fn mint_login(
        &self,
        identity: BrowserIdentity,
        ttl_seconds: i64,
    ) -> Result<String, String> {
        self.state.logins.mint(identity, unix_now(), ttl_seconds)
    }

    pub async fn spawn_insecure_loopback(&self, addr: SocketAddr) -> Result<FleetUiServer, String> {
        if !addr.ip().is_loopback() {
            return Err(format!(
                "--insecure-loopback requires a loopback listener, got {addr}"
            ));
        }
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|error| format!("failed to bind fleet UI at {addr}: {error}"))?;
        let addr = listener
            .local_addr()
            .map_err(|error| format!("failed to inspect fleet UI listener: {error}"))?;
        let app = router(self.state.clone());
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .map_err(|error| format!("fleet UI server failed: {error}"))
        });
        Ok(FleetUiServer {
            addr,
            shutdown: Some(shutdown),
            task,
        })
    }

    pub async fn serve_tls(
        &self,
        addr: SocketAddr,
        certificate: &std::path::Path,
        private_key: &std::path::Path,
    ) -> Result<(), String> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(certificate, private_key)
            .await
            .map_err(|error| format!("failed to load fleet UI TLS identity: {error}"))?;
        axum_server::bind_rustls(addr, config)
            .serve(router(self.state.clone()).into_make_service())
            .await
            .map_err(|error| format!("fleet UI TLS server failed: {error}"))
    }
}

impl FleetUiServer {
    pub fn addr(&self) -> SocketAddr {
        self.addr
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
            .map_err(|error| format!("fleet UI task failed: {error}"))?
    }
}

fn router(state: UiState) -> Router {
    Router::new()
        .route("/fleet/login", post(login))
        .route("/__tauri/{command}", post(invoke))
        .fallback(asset)
        .with_state(state)
}

#[derive(Deserialize)]
struct LoginRequest {
    credential: String,
}

async fn login(State(state): State<UiState>, Json(request): Json<LoginRequest>) -> Response {
    let now = unix_now();
    let Some(identity) = state.logins.authenticate(&request.credential, now) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"login rejected"})),
        )
            .into_response();
    };
    let role = identity.role;
    let principal = identity.principal.clone();
    match state
        .sessions
        .mint(identity, now, state.session_ttl_seconds)
    {
        Ok(token) => Json(json!({
            "token": token,
            "principal": principal,
            "role": role,
            "expires_at": now.saturating_add(state.session_ttl_seconds),
        }))
        .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":error})),
        )
            .into_response(),
    }
}

async fn invoke(
    State(state): State<UiState>,
    Path(command): Path<String>,
    headers: axum::http::HeaderMap,
    Json(arguments): Json<Value>,
) -> Response {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(identity) = state.sessions.authenticate(token, unix_now()) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if command == "get_fleet_snapshot" {
        return match state.backend.snapshot().await {
            Ok(snapshot) => Json(snapshot).into_response(),
            Err(error) => (StatusCode::BAD_GATEWAY, Json(json!({"error":error}))).into_response(),
        };
    }
    if !matches!(
        command.as_str(),
        "fleet_command"
            | "fleet_deploy"
            | "fleet_rollback"
            | "fleet_revoke"
            | "fleet_enrollment_token"
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"unknown fleet command"})),
        )
            .into_response();
    }
    let read_only_command = command == "fleet_command"
        && arguments
            .get("action")
            .and_then(Value::as_str)
            .is_some_and(|action| {
                matches!(
                    action,
                    "list_containers" | "container_logs" | "inspect_container" | "doctor"
                )
            });
    if !read_only_command && !identity.role.can_operate() {
        let _ = state.audit.append(
            &identity.principal,
            identity.role,
            &command,
            &arguments,
            AuditResult::Denied,
            unix_now(),
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"operate role required"})),
        )
            .into_response();
    }
    let result = state.backend.operate(&command, arguments.clone()).await;
    let audit_result = match &result {
        Ok(_) => AuditResult::Succeeded,
        Err(error) => AuditResult::Failed(error.clone()),
    };
    if let Err(error) = state.audit.append(
        &identity.principal,
        identity.role,
        &command,
        &arguments,
        audit_result,
        unix_now(),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":format!("fleet witness failed: {error}")})),
        )
            .into_response();
    }
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::BAD_GATEWAY, Json(json!({"error":error}))).into_response(),
    }
}

async fn asset(State(state): State<UiState>, request: Request<Body>) -> Response {
    let uri: &Uri = request.uri();
    let path = uri.path().trim_start_matches('/');
    match state
        .assets
        .get(if path.is_empty() { "index.html" } else { path })
        .or_else(|| state.assets.get("index.html"))
    {
        Some((bytes, mime)) => ([(header::CONTENT_TYPE, mime)], bytes).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

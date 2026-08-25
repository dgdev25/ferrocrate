mod linux_native;
mod macos_vm;
mod wsl2;

pub use linux_native::{LinuxNativeBackend, LinuxNativeConfig};
pub use macos_vm::{MacosVmBackend, MacosVmConfig};
pub use wsl2::{Wsl2Backend, Wsl2Config};

use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Linux,
    Windows,
    Macos,
    Unsupported,
}

impl Platform {
    pub const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else {
            Self::Unsupported
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub terminal: bool,
    pub registry: bool,
    pub containers: bool,
    pub networks: bool,
    pub volumes: bool,
    pub custom_networks: bool,
    pub streaming_exec: bool,
}

impl BackendCapabilities {
    pub const fn native() -> Self {
        Self {
            terminal: true,
            registry: true,
            containers: true,
            networks: true,
            volumes: true,
            custom_networks: true,
            streaming_exec: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendStatus {
    pub backend: String,
    pub platform: Platform,
    pub state: BackendState,
    pub healthy: bool,
    pub endpoint: String,
    pub reason: Option<String>,
    pub capabilities: BackendCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

impl CommandSpec {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((name.into(), value.into()));
        self
    }

    fn to_command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args).envs(self.env.iter().cloned());
        command
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    UnixSocket(PathBuf),
    Loopback(SocketAddr),
    AuthenticatedLoopback {
        addr: SocketAddr,
        bearer_token: String,
    },
}

impl fmt::Display for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnixSocket(path) => write!(formatter, "{}", path.display()),
            Self::Loopback(addr) | Self::AuthenticatedLoopback { addr, .. } => {
                write!(formatter, "http://{addr}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl TransportRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Vec<u8>,
}

impl ExecRequest {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            stdin: Vec::new(),
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn stdin(mut self, stdin: Vec<u8>) -> Self {
        self.stdin = stdin;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResponse {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait ExecStream: Read + Send {
    fn wait(&mut self) -> Result<i32, BackendError>;
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("backend is unavailable: {0}")]
    Unavailable(String),
    #[error("backend command failed: {0}")]
    Command(String),
    #[error("backend transport failed: {0}")]
    Transport(String),
    #[error("backend state is unavailable")]
    State,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub trait BackendHost: Send + Sync {
    fn start(&self, command: &CommandSpec) -> Result<(), BackendError>;
    fn stop(&self) -> Result<(), BackendError>;
    fn is_running(&self) -> Result<bool, BackendError>;
    fn health(&self, transport: &Transport) -> Result<bool, BackendError>;
    fn request(
        &self,
        transport: &Transport,
        request: &TransportRequest,
    ) -> Result<TransportResponse, BackendError>;
    fn exec(
        &self,
        command: &CommandSpec,
        request: &ExecRequest,
    ) -> Result<ExecResponse, BackendError>;
    fn exec_stream(
        &self,
        command: &CommandSpec,
        request: &ExecRequest,
    ) -> Result<Box<dyn ExecStream>, BackendError>;
}

pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;
    fn platform(&self) -> Platform;
    fn capabilities(&self) -> BackendCapabilities;
    fn start(&self) -> Result<BackendStatus, BackendError>;
    fn stop(&self) -> Result<BackendStatus, BackendError>;
    fn status(&self) -> BackendStatus;
    fn health(&self) -> Result<bool, BackendError>;
    fn exec(&self, request: ExecRequest) -> Result<ExecResponse, BackendError>;
    fn exec_stream(&self, request: ExecRequest) -> Result<Box<dyn ExecStream>, BackendError>;
    fn request(&self, request: TransportRequest) -> Result<TransportResponse, BackendError>;
    fn socket_path(&self) -> Option<PathBuf>;
}

pub(crate) struct BackendCore {
    pub name: &'static str,
    pub platform: Platform,
    pub capabilities: BackendCapabilities,
    pub start_command: CommandSpec,
    pub exec_command: CommandSpec,
    pub transport: Transport,
    pub host: Arc<dyn BackendHost>,
    state: Mutex<BackendState>,
    failure: Mutex<Option<String>>,
}

impl BackendCore {
    pub fn new(
        name: &'static str,
        platform: Platform,
        start_command: CommandSpec,
        exec_command: CommandSpec,
        transport: Transport,
        host: Arc<dyn BackendHost>,
    ) -> Self {
        Self {
            name,
            platform,
            capabilities: BackendCapabilities::native(),
            start_command,
            exec_command,
            transport,
            host,
            state: Mutex::new(BackendState::Stopped),
            failure: Mutex::new(None),
        }
    }

    pub fn start(&self) -> Result<BackendStatus, BackendError> {
        *self.state.lock().map_err(|_| BackendError::State)? = BackendState::Starting;
        match self.host.start(&self.start_command) {
            Ok(()) => {
                *self.state.lock().map_err(|_| BackendError::State)? = BackendState::Running;
                *self.failure.lock().map_err(|_| BackendError::State)? = None;
                Ok(self.status())
            }
            Err(error) => {
                *self.state.lock().map_err(|_| BackendError::State)? = BackendState::Failed;
                *self.failure.lock().map_err(|_| BackendError::State)? = Some(error.to_string());
                Err(error)
            }
        }
    }

    pub fn stop(&self) -> Result<BackendStatus, BackendError> {
        *self.state.lock().map_err(|_| BackendError::State)? = BackendState::Stopping;
        match self.host.stop() {
            Ok(()) => {
                *self.state.lock().map_err(|_| BackendError::State)? = BackendState::Stopped;
                *self.failure.lock().map_err(|_| BackendError::State)? = None;
                Ok(self.status())
            }
            Err(error) => {
                *self.state.lock().map_err(|_| BackendError::State)? = BackendState::Failed;
                *self.failure.lock().map_err(|_| BackendError::State)? = Some(error.to_string());
                Err(error)
            }
        }
    }

    pub fn status(&self) -> BackendStatus {
        let mut state = self
            .state
            .lock()
            .map(|value| *value)
            .unwrap_or(BackendState::Failed);
        let mut reason = self.failure.lock().ok().and_then(|value| value.clone());
        let running = self.host.is_running().unwrap_or(false);
        if state == BackendState::Running && !running {
            state = BackendState::Failed;
            reason = Some("backend process is not running".into());
        }
        let healthy =
            state == BackendState::Running && self.host.health(&self.transport).unwrap_or(false);
        if state == BackendState::Running && !healthy && reason.is_none() {
            reason = Some("backend health check failed".into());
        }
        BackendStatus {
            backend: self.name.into(),
            platform: self.platform,
            state,
            healthy,
            endpoint: self.transport.to_string(),
            reason,
            capabilities: self.capabilities,
        }
    }
}

pub struct SystemBackendHost {
    child: Mutex<Option<Child>>,
}

impl Default for SystemBackendHost {
    fn default() -> Self {
        Self {
            child: Mutex::new(None),
        }
    }
}

impl SystemBackendHost {
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl BackendHost for SystemBackendHost {
    fn start(&self, command: &CommandSpec) -> Result<(), BackendError> {
        let mut slot = self.child.lock().map_err(|_| BackendError::State)?;
        if let Some(child) = slot.as_mut() {
            if child.try_wait()?.is_none() {
                return Ok(());
            }
        }
        let child = command
            .to_command()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        *slot = Some(child);
        Ok(())
    }

    fn stop(&self) -> Result<(), BackendError> {
        if let Some(mut child) = self.child.lock().map_err(|_| BackendError::State)?.take() {
            child.kill()?;
            child.wait()?;
        }
        Ok(())
    }

    fn is_running(&self) -> Result<bool, BackendError> {
        let mut slot = self.child.lock().map_err(|_| BackendError::State)?;
        Ok(match slot.as_mut() {
            Some(child) => child.try_wait()?.is_none(),
            None => false,
        })
    }

    fn health(&self, transport: &Transport) -> Result<bool, BackendError> {
        let response = self.request(transport, &TransportRequest::new("GET", "/_ping"));
        Ok(matches!(response, Ok(response) if response.status == 200 && response.body == b"OK"))
    }

    fn request(
        &self,
        transport: &Transport,
        request: &TransportRequest,
    ) -> Result<TransportResponse, BackendError> {
        match transport {
            Transport::UnixSocket(path) => request_unix(path, request),
            Transport::Loopback(addr) => request_tcp(*addr, None, request),
            Transport::AuthenticatedLoopback { addr, bearer_token } => {
                request_tcp(*addr, Some(bearer_token), request)
            }
        }
    }

    fn exec(
        &self,
        command: &CommandSpec,
        request: &ExecRequest,
    ) -> Result<ExecResponse, BackendError> {
        let mut process = command.to_command();
        process
            .arg(&request.program)
            .args(&request.args)
            .stdin(Stdio::piped());
        let mut child = process
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if !request.stdin.is_empty() {
            child
                .stdin
                .take()
                .ok_or_else(|| BackendError::Command("stdin is unavailable".into()))?
                .write_all(&request.stdin)?;
        }
        let output = child.wait_with_output()?;
        Ok(ExecResponse {
            code: output.status.code().unwrap_or(1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn exec_stream(
        &self,
        command: &CommandSpec,
        request: &ExecRequest,
    ) -> Result<Box<dyn ExecStream>, BackendError> {
        let mut process = command.to_command();
        process
            .arg(&request.program)
            .args(&request.args)
            .stdin(Stdio::piped());
        let mut child = process
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        if !request.stdin.is_empty() {
            child
                .stdin
                .take()
                .ok_or_else(|| BackendError::Command("stdin is unavailable".into()))?
                .write_all(&request.stdin)?;
        }
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BackendError::Command("stdout is unavailable".into()))?;
        Ok(Box::new(ProcessExecStream { child, stdout }))
    }
}

struct ProcessExecStream {
    child: Child,
    stdout: ChildStdout,
}

impl Read for ProcessExecStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stdout.read(buffer)
    }
}

impl ExecStream for ProcessExecStream {
    fn wait(&mut self) -> Result<i32, BackendError> {
        Ok(self.child.wait()?.code().unwrap_or(1))
    }
}

fn serialize_request(request: &TransportRequest, token: Option<&str>) -> Vec<u8> {
    let mut wire = format!(
        "{} {} HTTP/1.1\r\nHost: ferrocrate-desktop\r\nConnection: close\r\nContent-Length: {}\r\n",
        request.method,
        request.path,
        request.body.len()
    );
    if let Some(token) = token {
        wire.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    for (name, value) in &request.headers {
        wire.push_str(&format!("{name}: {value}\r\n"));
    }
    wire.push_str("\r\n");
    let mut bytes = wire.into_bytes();
    bytes.extend_from_slice(&request.body);
    bytes
}

fn parse_response(stream: impl Read) -> Result<TransportResponse, BackendError> {
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| BackendError::Transport("malformed HTTP status".into()))?;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().into()));
        }
    }
    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    Ok(TransportResponse {
        status,
        headers,
        body,
    })
}

fn request_tcp(
    addr: SocketAddr,
    token: Option<&str>,
    request: &TransportRequest,
) -> Result<TransportResponse, BackendError> {
    if !addr.ip().is_loopback() {
        return Err(BackendError::Transport(format!(
            "backend relay must use loopback, got {addr}"
        )));
    }
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(&serialize_request(request, token))?;
    parse_response(stream)
}

#[cfg(unix)]
fn request_unix(
    path: &Path,
    request: &TransportRequest,
) -> Result<TransportResponse, BackendError> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(&serialize_request(request, None))?;
    parse_response(stream)
}

#[cfg(not(unix))]
fn request_unix(
    _path: &Path,
    _request: &TransportRequest,
) -> Result<TransportResponse, BackendError> {
    Err(BackendError::Unavailable(
        "Unix sockets are unavailable on this host".into(),
    ))
}

pub fn select_backend() -> Result<Box<dyn Backend>, BackendError> {
    select_backend_for(
        Platform::current(),
        SystemBackendHost::shared(),
        LinuxNativeConfig::default(),
        Wsl2Config::default(),
        MacosVmConfig::default(),
    )
}

pub fn select_backend_for(
    platform: Platform,
    host: Arc<dyn BackendHost>,
    linux: LinuxNativeConfig,
    wsl2: Wsl2Config,
    macos: MacosVmConfig,
) -> Result<Box<dyn Backend>, BackendError> {
    match platform {
        Platform::Linux => Ok(Box::new(LinuxNativeBackend::with_host(linux, host))),
        Platform::Windows => Ok(Box::new(Wsl2Backend::with_host(wsl2, host))),
        Platform::Macos => Ok(Box::new(MacosVmBackend::with_host(macos, host))),
        Platform::Unsupported => Err(BackendError::Unavailable(
            "unsupported desktop platform".into(),
        )),
    }
}

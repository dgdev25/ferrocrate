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
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
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

    pub fn launcher() -> Self {
        Self::new(PathBuf::new())
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

    fn exec_command(&self, request: &ExecRequest) -> Command {
        if self.program.as_os_str().is_empty() {
            let mut command = Command::new(&request.program);
            command.args(&self.args).envs(self.env.iter().cloned());
            command
        } else {
            let mut command = self.to_command();
            command.arg(&request.program);
            command
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    UnixSocket(PathBuf),
    WslUnixSocket {
        distro: String,
        path: PathBuf,
    },
    ProcessDuplex {
        command: CommandSpec,
        endpoint: String,
    },
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
            Self::WslUnixSocket { distro, path } => {
                write!(formatter, "wsl://{distro}/$HOME/{}", path.display())
            }
            Self::ProcessDuplex { endpoint, .. } => formatter.write_str(endpoint),
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
    pub env: Vec<(String, String)>,
    pub stdin: Vec<u8>,
}

impl ExecRequest {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
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

    pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((name.into(), value.into()));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResponse {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalRequest {
    pub container: String,
    pub command: Vec<String>,
    pub env: Vec<String>,
    pub user: Option<String>,
    pub workdir: Option<String>,
}

pub trait DuplexStream: Read + Write + Send {
    fn try_clone_stream(&self) -> Result<Box<dyn DuplexStream>, BackendError>;
    fn shutdown_write(&self) -> Result<(), BackendError>;
    fn cancel(&self) -> Result<(), BackendError> {
        self.shutdown_write()
    }
}

pub struct TerminalSession {
    pub exec_id: String,
    pub stream: Box<dyn DuplexStream>,
}

pub trait ExecStream: Read + Write + Send {
    fn take_stdin(&mut self) -> Result<Box<dyn Write + Send>, BackendError>;
    fn take_stdout(&mut self) -> Result<Box<dyn Read + Send>, BackendError>;
    fn take_stderr(&mut self) -> Result<Box<dyn Read + Send>, BackendError>;
    fn close_stdin(&mut self) -> Result<(), BackendError>;
    fn kill(&mut self) -> Result<(), BackendError>;
    fn try_wait(&mut self) -> Result<Option<i32>, BackendError>;
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
    fn readiness_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
    fn maintain(&self) -> Result<(), BackendError> {
        Ok(())
    }
    fn control(&self, command: &CommandSpec) -> Result<(), BackendError> {
        let status = command.to_command().status()?;
        if status.success() {
            Ok(())
        } else {
            Err(BackendError::Command(format!(
                "{} exited with {status}",
                command.program.display()
            )))
        }
    }
    fn open_terminal(
        &self,
        transport: &Transport,
        request: &TerminalRequest,
    ) -> Result<TerminalSession, BackendError> {
        open_terminal_via_host(self, transport, request)
    }
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
    fn open_terminal(&self, request: TerminalRequest) -> Result<TerminalSession, BackendError>;
    fn resize_terminal(&self, exec_id: &str, columns: u16, rows: u16) -> Result<(), BackendError>;
    fn socket_path(&self) -> Option<PathBuf>;
}

pub(crate) struct BackendCore {
    pub name: &'static str,
    pub platform: Platform,
    pub capabilities: BackendCapabilities,
    pub start_commands: Vec<CommandSpec>,
    pub exec_command: CommandSpec,
    pub transport: Transport,
    pub host: Arc<dyn BackendHost>,
    state: Mutex<BackendState>,
    failure: Mutex<Option<String>>,
    owned: Mutex<bool>,
    readiness_timeout: Option<Duration>,
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
            start_commands: vec![start_command],
            exec_command,
            transport,
            host,
            state: Mutex::new(BackendState::Stopped),
            failure: Mutex::new(None),
            owned: Mutex::new(false),
            readiness_timeout: None,
        }
    }
}

fn open_terminal_via_host<H: BackendHost + ?Sized>(
    host: &H,
    transport: &Transport,
    request: &TerminalRequest,
) -> Result<TerminalSession, BackendError> {
    if request.container.trim().is_empty() || request.command.is_empty() {
        return Err(BackendError::Transport(
            "terminal container and command are required".into(),
        ));
    }
    let create_body = serde_json::to_vec(&serde_json::json!({
        "Cmd": request.command,
        "AttachStdin": true,
        "AttachStdout": true,
        "AttachStderr": true,
        "Tty": true,
        "Env": request.env,
        "User": request.user,
        "WorkingDir": request.workdir,
    }))
    .map_err(|error| BackendError::Transport(error.to_string()))?;
    let create = TransportRequest::new(
        "POST",
        format!(
            "/containers/{}/exec",
            percent_encode_path(&request.container)
        ),
    )
    .header("content-type", "application/json")
    .body(create_body);
    let response = host.request(transport, &create)?;
    if !(200..300).contains(&response.status) {
        return Err(BackendError::Transport(format!(
            "terminal create returned HTTP {}",
            response.status
        )));
    }
    let exec_id = serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|value| value.get("Id")?.as_str().map(str::to_owned))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| BackendError::Transport("terminal create omitted Id".into()))?;
    let body = br#"{"Detach":false,"Tty":true}"#;
    let mut stream = connect_transport(transport)?;
    let token = match transport {
        Transport::AuthenticatedLoopback { bearer_token, .. } => Some(bearer_token.as_str()),
        _ => None,
    };
    let mut wire = format!(
            "POST /exec/{}/start HTTP/1.1\r\nHost: ferrocrate-desktop\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            percent_encode_path(&exec_id),
            body.len()
        );
    if let Some(token) = token {
        wire.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    wire.push_str("\r\n");
    stream.write_all(wire.as_bytes())?;
    stream.write_all(body)?;
    let status = read_http_status(stream.as_mut())?;
    if status != 101 {
        return Err(BackendError::Transport(format!(
            "terminal attach returned HTTP {status}"
        )));
    }
    Ok(TerminalSession { exec_id, stream })
}

impl BackendCore {
    pub fn with_auxiliary_start(mut self, command: CommandSpec) -> Self {
        self.start_commands.push(command);
        self
    }

    pub fn with_readiness_timeout(mut self, timeout: Duration) -> Self {
        self.readiness_timeout = Some(timeout);
        self
    }

    pub fn start(&self) -> Result<BackendStatus, BackendError> {
        self.start_with_commands(&self.start_commands)
    }

    pub(crate) fn start_with_commands(
        &self,
        start_commands: &[CommandSpec],
    ) -> Result<BackendStatus, BackendError> {
        *self.state.lock().map_err(|_| BackendError::State)? = BackendState::Starting;
        if self.host.health(&self.transport).unwrap_or(false) {
            *self.owned.lock().map_err(|_| BackendError::State)? = false;
            *self.state.lock().map_err(|_| BackendError::State)? = BackendState::Running;
            *self.failure.lock().map_err(|_| BackendError::State)? = None;
            return Ok(self.status());
        }
        let start_result = start_commands
            .iter()
            .try_for_each(|command| self.host.start(command));
        match start_result {
            Ok(()) => {
                *self.owned.lock().map_err(|_| BackendError::State)? = true;
                let deadline = std::time::Instant::now()
                    + self
                        .readiness_timeout
                        .unwrap_or_else(|| self.host.readiness_timeout());
                loop {
                    self.host.maintain()?;
                    if self.host.health(&self.transport).unwrap_or(false) {
                        *self.state.lock().map_err(|_| BackendError::State)? =
                            BackendState::Running;
                        *self.failure.lock().map_err(|_| BackendError::State)? = None;
                        return Ok(self.status());
                    }
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                let reason = "backend did not become healthy before the readiness deadline";
                let _ = self.host.stop();
                *self.owned.lock().map_err(|_| BackendError::State)? = false;
                *self.state.lock().map_err(|_| BackendError::State)? = BackendState::Failed;
                *self.failure.lock().map_err(|_| BackendError::State)? = Some(reason.into());
                Err(BackendError::Unavailable(reason.into()))
            }
            Err(error) => {
                let _ = self.host.stop();
                *self.owned.lock().map_err(|_| BackendError::State)? = false;
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
                *self.owned.lock().map_err(|_| BackendError::State)? = false;
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
        let owned = self.owned.lock().map(|value| *value).unwrap_or(false);
        let running = self.host.is_running().unwrap_or(false);
        if state == BackendState::Running && owned && !running {
            state = BackendState::Failed;
            reason = Some("backend process is not running".into());
        }
        let healthy =
            state == BackendState::Running && self.host.health(&self.transport).unwrap_or(false);
        if state == BackendState::Running && !healthy && reason.is_none() {
            state = BackendState::Failed;
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

    pub fn open_terminal(&self, request: TerminalRequest) -> Result<TerminalSession, BackendError> {
        self.host.open_terminal(&self.transport, &request)
    }

    pub fn resize_terminal(
        &self,
        exec_id: &str,
        columns: u16,
        rows: u16,
    ) -> Result<(), BackendError> {
        if columns == 0 || rows == 0 {
            return Err(BackendError::Transport(
                "terminal dimensions must be non-zero".into(),
            ));
        }
        let path = format!(
            "/exec/{}/resize?w={columns}&h={rows}",
            percent_encode_path(exec_id)
        );
        let response = self
            .host
            .request(&self.transport, &TransportRequest::new("POST", path))?;
        if (200..300).contains(&response.status) {
            Ok(())
        } else {
            Err(BackendError::Transport(format!(
                "terminal resize returned HTTP {}",
                response.status
            )))
        }
    }
}

impl Drop for BackendCore {
    fn drop(&mut self) {
        if self.owned.lock().map(|owned| *owned).unwrap_or(false) {
            let _ = self.host.stop();
        }
    }
}

pub struct SystemBackendHost {
    children: Mutex<Vec<OwnedChild>>,
    desired: Mutex<Vec<CommandSpec>>,
}

struct OwnedChild {
    command: CommandSpec,
    child: Child,
}

impl Default for SystemBackendHost {
    fn default() -> Self {
        Self {
            children: Mutex::new(Vec::new()),
            desired: Mutex::new(Vec::new()),
        }
    }
}

impl SystemBackendHost {
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn reap_stale(&self) -> Result<(), BackendError> {
        self.children
            .lock()
            .map_err(|_| BackendError::State)?
            .retain_mut(|owned| matches!(owned.child.try_wait(), Ok(None)));
        Ok(())
    }
}

impl BackendHost for SystemBackendHost {
    fn start(&self, command: &CommandSpec) -> Result<(), BackendError> {
        self.reap_stale()?;
        if self
            .children
            .lock()
            .map_err(|_| BackendError::State)?
            .iter()
            .any(|owned| owned.command == *command)
        {
            return Ok(());
        }
        let child = command
            .to_command()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        self.children
            .lock()
            .map_err(|_| BackendError::State)?
            .push(OwnedChild {
                command: command.clone(),
                child,
            });
        let mut desired = self.desired.lock().map_err(|_| BackendError::State)?;
        if !desired.contains(command) {
            desired.push(command.clone());
        }
        Ok(())
    }

    fn stop(&self) -> Result<(), BackendError> {
        let mut children = self.children.lock().map_err(|_| BackendError::State)?;
        for mut owned in children.drain(..) {
            owned.child.kill()?;
            owned.child.wait()?;
        }
        self.desired
            .lock()
            .map_err(|_| BackendError::State)?
            .clear();
        Ok(())
    }

    fn is_running(&self) -> Result<bool, BackendError> {
        self.reap_stale()?;
        let children = self.children.lock().map_err(|_| BackendError::State)?;
        let desired = self.desired.lock().map_err(|_| BackendError::State)?;
        if desired.is_empty() {
            return Ok(false);
        }
        Ok(desired
            .iter()
            .all(|command| children.iter().any(|owned| &owned.command == command)))
    }

    fn maintain(&self) -> Result<(), BackendError> {
        self.reap_stale()?;
        let desired = self
            .desired
            .lock()
            .map_err(|_| BackendError::State)?
            .clone();
        for command in desired {
            self.start(&command)?;
        }
        Ok(())
    }

    fn health(&self, transport: &Transport) -> Result<bool, BackendError> {
        let response = self.request(transport, &TransportRequest::new("GET", "/_ping"));
        Ok(matches!(response, Ok(response) if response.status == 200 && daemon_ping_response_is_healthy(&response.body)))
    }

    fn request(
        &self,
        transport: &Transport,
        request: &TransportRequest,
    ) -> Result<TransportResponse, BackendError> {
        match transport {
            Transport::UnixSocket(path) => request_unix(path, request),
            Transport::WslUnixSocket { .. } | Transport::ProcessDuplex { .. } => {
                request_duplex(transport, request)
            }
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
        let mut process = command.exec_command(request);
        process
            .args(&request.args)
            .envs(request.env.iter().cloned())
            .stdin(Stdio::piped());
        let mut child = process
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| BackendError::Command("stdin is unavailable".into()))?;
        if !request.stdin.is_empty() {
            stdin.write_all(&request.stdin)?;
        }
        drop(stdin);
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
        let mut process = command.exec_command(request);
        process
            .args(&request.args)
            .envs(request.env.iter().cloned())
            .stdin(Stdio::piped());
        let mut child = process
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| BackendError::Command("stdin is unavailable".into()))?;
        if !request.stdin.is_empty() {
            stdin.write_all(&request.stdin)?;
        }
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BackendError::Command("stdout is unavailable".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BackendError::Command("stderr is unavailable".into()))?;
        Ok(Box::new(ProcessExecStream {
            child,
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr: Some(stderr),
        }))
    }
}

struct ProcessExecStream {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl Read for ProcessExecStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stdout
            .as_mut()
            .ok_or_else(|| std::io::Error::other("stdout was taken"))?
            .read(buffer)
    }
}

impl Write for ProcessExecStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.stdin
            .as_mut()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stdin is closed"))?
            .write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stdin
            .as_mut()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stdin is closed"))?
            .flush()
    }
}

impl ExecStream for ProcessExecStream {
    fn take_stdin(&mut self) -> Result<Box<dyn Write + Send>, BackendError> {
        self.stdin
            .take()
            .map(|stdin| Box::new(stdin) as Box<dyn Write + Send>)
            .ok_or_else(|| BackendError::Command("stdin is closed".into()))
    }

    fn close_stdin(&mut self) -> Result<(), BackendError> {
        self.stdin.take();
        Ok(())
    }

    fn take_stdout(&mut self) -> Result<Box<dyn Read + Send>, BackendError> {
        self.stdout
            .take()
            .map(|stdout| Box::new(stdout) as Box<dyn Read + Send>)
            .ok_or_else(|| BackendError::Command("stdout was already taken".into()))
    }

    fn take_stderr(&mut self) -> Result<Box<dyn Read + Send>, BackendError> {
        self.stderr
            .take()
            .map(|stderr| Box::new(stderr) as Box<dyn Read + Send>)
            .ok_or_else(|| BackendError::Command("stderr was already taken".into()))
    }

    fn kill(&mut self) -> Result<(), BackendError> {
        self.child.kill()?;
        Ok(())
    }

    fn wait(&mut self) -> Result<i32, BackendError> {
        Ok(self.child.wait()?.code().unwrap_or(1))
    }

    fn try_wait(&mut self) -> Result<Option<i32>, BackendError> {
        Ok(self
            .child
            .try_wait()?
            .map(|status| status.code().unwrap_or(1)))
    }
}

enum TransportStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

struct WslDuplexStream {
    inner: Arc<WslDuplexInner>,
}

struct WslDuplexInner {
    child: Mutex<Child>,
    stdin: Mutex<Option<ChildStdin>>,
    stdout: Mutex<ChildStdout>,
}

impl Drop for WslDuplexInner {
    fn drop(&mut self) {
        if let Ok(stdin) = self.stdin.get_mut() {
            stdin.take();
        }
        if let Ok(child) = self.child.get_mut() {
            if matches!(child.try_wait(), Ok(None)) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

impl Read for WslDuplexStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner
            .stdout
            .lock()
            .map_err(|_| std::io::Error::other("WSL stdout state is unavailable"))?
            .read(buffer)
    }
}

impl Write for WslDuplexStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.inner
            .stdin
            .lock()
            .map_err(|_| std::io::Error::other("WSL stdin state is unavailable"))?
            .as_mut()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "WSL stdin is closed")
            })?
            .write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner
            .stdin
            .lock()
            .map_err(|_| std::io::Error::other("WSL stdin state is unavailable"))?
            .as_mut()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "WSL stdin is closed")
            })?
            .flush()
    }
}

impl DuplexStream for WslDuplexStream {
    fn try_clone_stream(&self) -> Result<Box<dyn DuplexStream>, BackendError> {
        Ok(Box::new(Self {
            inner: self.inner.clone(),
        }))
    }

    fn shutdown_write(&self) -> Result<(), BackendError> {
        self.inner
            .stdin
            .lock()
            .map_err(|_| BackendError::State)?
            .take();
        Ok(())
    }

    fn cancel(&self) -> Result<(), BackendError> {
        self.shutdown_write()?;
        let mut child = self.inner.child.lock().map_err(|_| BackendError::State)?;
        if matches!(child.try_wait(), Ok(None)) {
            child.kill()?;
        }
        Ok(())
    }
}

impl Read for TransportStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buffer),
        }
    }
}

impl Write for TransportStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buffer),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
        }
    }
}

impl DuplexStream for TransportStream {
    fn try_clone_stream(&self) -> Result<Box<dyn DuplexStream>, BackendError> {
        Ok(match self {
            Self::Tcp(stream) => Box::new(Self::Tcp(stream.try_clone()?)),
            #[cfg(unix)]
            Self::Unix(stream) => Box::new(Self::Unix(stream.try_clone()?)),
        })
    }

    fn shutdown_write(&self) -> Result<(), BackendError> {
        match self {
            Self::Tcp(stream) => stream.shutdown(std::net::Shutdown::Write)?,
            #[cfg(unix)]
            Self::Unix(stream) => stream.shutdown(std::net::Shutdown::Write)?,
        }
        Ok(())
    }
}

fn connect_transport(transport: &Transport) -> Result<Box<dyn DuplexStream>, BackendError> {
    match transport {
        Transport::UnixSocket(path) => {
            #[cfg(unix)]
            {
                Ok(Box::new(TransportStream::Unix(
                    std::os::unix::net::UnixStream::connect(path)?,
                )))
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                Err(BackendError::Unavailable(
                    "Unix sockets are unavailable".into(),
                ))
            }
        }
        Transport::WslUnixSocket { distro, path } => {
            if path.is_absolute() {
                return Err(BackendError::Transport(
                    "WSL socket path must be relative to the guest home".into(),
                ));
            }
            let mut child = Command::new("wsl.exe")
                .args(["-d", distro, "--exec", "sh", "-lc"])
                .arg("exec socat STDIO \"UNIX-CONNECT:$HOME/$1\"")
                .arg("ferrocrate-wsl")
                .arg(path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| BackendError::Transport("WSL socket stdin is unavailable".into()))?;
            let stdout = child.stdout.take().ok_or_else(|| {
                BackendError::Transport("WSL socket stdout is unavailable".into())
            })?;
            Ok(Box::new(WslDuplexStream {
                inner: Arc::new(WslDuplexInner {
                    child: Mutex::new(child),
                    stdin: Mutex::new(Some(stdin)),
                    stdout: Mutex::new(stdout),
                }),
            }))
        }
        Transport::ProcessDuplex { command, .. } => {
            let mut child = command
                .to_command()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
            let stdin = child.stdin.take().ok_or_else(|| {
                BackendError::Transport("guest relay stdin is unavailable".into())
            })?;
            let stdout = child.stdout.take().ok_or_else(|| {
                BackendError::Transport("guest relay stdout is unavailable".into())
            })?;
            Ok(Box::new(WslDuplexStream {
                inner: Arc::new(WslDuplexInner {
                    child: Mutex::new(child),
                    stdin: Mutex::new(Some(stdin)),
                    stdout: Mutex::new(stdout),
                }),
            }))
        }
        Transport::Loopback(addr) | Transport::AuthenticatedLoopback { addr, .. } => {
            if !addr.ip().is_loopback() {
                return Err(BackendError::Transport(
                    "backend relay must use loopback".into(),
                ));
            }
            Ok(Box::new(TransportStream::Tcp(TcpStream::connect_timeout(
                addr,
                Duration::from_secs(2),
            )?)))
        }
    }
}

fn request_duplex(
    transport: &Transport,
    request: &TransportRequest,
) -> Result<TransportResponse, BackendError> {
    let mut stream = connect_transport(transport)?;
    stream.write_all(&serialize_request(request, None))?;
    stream.shutdown_write()?;
    parse_response_with_timeout(stream, Duration::from_secs(5))
}

fn read_http_status(stream: &mut dyn DuplexStream) -> Result<u16, BackendError> {
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        headers.push(byte[0]);
        if headers.len() > 64 * 1024 {
            return Err(BackendError::Transport("HTTP headers are too large".into()));
        }
    }
    std::str::from_utf8(&headers)
        .ok()
        .and_then(|value| value.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| BackendError::Transport("malformed HTTP status".into()))
}

fn percent_encode_path(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn daemon_ping_response_is_healthy(body: &[u8]) -> bool {
    std::str::from_utf8(body)
        .is_ok_and(|value| value.trim() == "OK")
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

fn parse_response_with_timeout(
    stream: Box<dyn DuplexStream>,
    timeout: Duration,
) -> Result<TransportResponse, BackendError> {
    let controller = stream.try_clone_stream()?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(parse_response(stream));
    });
    match receiver.recv_timeout(timeout) {
        Ok(response) => response,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            controller.cancel()?;
            Err(BackendError::Transport(format!(
                "backend response timed out after {} ms",
                timeout.as_millis()
            )))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(BackendError::Transport(
            "backend response worker disconnected".into(),
        )),
    }
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

#[cfg(test)]
mod timeout_tests {
    use super::*;
    use std::sync::Condvar;

    struct DelayedDuplex {
        canceled: Arc<(Mutex<bool>, Condvar)>,
    }

    impl Read for DelayedDuplex {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            let (lock, condition) = &*self.canceled;
            let canceled = lock.lock().expect("cancel state");
            let _ = condition
                .wait_timeout(canceled, Duration::from_millis(200))
                .expect("delayed read");
            Ok(0)
        }
    }

    impl Write for DelayedDuplex {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl DuplexStream for DelayedDuplex {
        fn try_clone_stream(&self) -> Result<Box<dyn DuplexStream>, BackendError> {
            Ok(Box::new(Self {
                canceled: self.canceled.clone(),
            }))
        }

        fn shutdown_write(&self) -> Result<(), BackendError> {
            Ok(())
        }

        fn cancel(&self) -> Result<(), BackendError> {
            let (lock, condition) = &*self.canceled;
            *lock.lock().map_err(|_| BackendError::State)? = true;
            condition.notify_all();
            Ok(())
        }
    }

    #[test]
    fn daemon_ping_accepts_the_newline_terminated_engine_response() {
        assert!(daemon_ping_response_is_healthy(b"OK\n"));
        assert!(!daemon_ping_response_is_healthy(b"not ready\n"));
    }

    #[test]
    fn transport_response_timeout_returns_before_a_blocking_read_finishes() {
        let canceled = Arc::new((Mutex::new(false), Condvar::new()));
        let started = std::time::Instant::now();
        let error = parse_response_with_timeout(
            Box::new(DelayedDuplex {
                canceled: canceled.clone(),
            }),
            Duration::from_millis(20),
        )
        .expect_err("blocking response must time out");

        assert!(started.elapsed() < Duration::from_millis(150));
        assert!(error.to_string().contains("timed out"));
        assert!(*canceled.0.lock().expect("cancel state"));
    }
}

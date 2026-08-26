use super::*;

#[derive(Debug, Clone)]
pub struct Wsl2Config {
    pub distro: String,
    pub relay_addr: SocketAddr,
    pub relay_token: String,
    pub ferrocrate_binary: PathBuf,
}

impl Default for Wsl2Config {
    fn default() -> Self {
        Self {
            distro: std::env::var("FERROCRATE_WSL_DISTRO").unwrap_or_else(|_| "Ubuntu".into()),
            relay_addr: "127.0.0.1:4288".parse().expect("constant loopback address"),
            relay_token: std::env::var("FERROCRATE_WEB_BRIDGE_TOKEN").unwrap_or_default(),
            ferrocrate_binary: std::env::var_os("FERROCRATE_WSL_ENGINE_PATH")
                .map(PathBuf::from)
                .unwrap_or_default(),
        }
    }
}

pub struct Wsl2Backend {
    core: BackendCore,
    ferrocrate_binary: Mutex<Option<PathBuf>>,
}

const RESOLVE_FERROCRATE_COMMAND: &str = "PATH=\"$HOME/.local/bin:$PATH\"; command -v ferrocrate";

fn guest_exec_request(
    request: ExecRequest,
    ferrocrate_binary: Option<&Path>,
) -> Result<ExecRequest, BackendError> {
    let ExecRequest {
        program,
        args,
        env,
        stdin,
    } = request;
    let mut guest_args = Vec::with_capacity(env.len() + args.len() + 1);
    guest_args.extend(
        env.into_iter()
            .map(|(name, value)| format!("{name}={value}")),
    );
    guest_args.push(if program == "ferrocrate" {
        ferrocrate_binary
            .ok_or_else(|| {
                BackendError::Unavailable(
                    "WSL guest engine path is unresolved; start the backend first".into(),
                )
            })?
            .display()
            .to_string()
    } else {
        program
    });
    guest_args.extend(args);
    Ok(ExecRequest::new("env").args(guest_args).stdin(stdin))
}

fn posix_shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn daemon_start_command(
    exec_command: &CommandSpec,
    ferrocrate_binary: &Path,
    socket_path: &Path,
) -> CommandSpec {
    CommandSpec::new(exec_command.program.clone())
        .args(exec_command.args.clone())
        .args(vec![
            "sh".to_string(),
            "-lc".to_string(),
            format!(
                "exec {} daemon --socket \"$HOME/$1\" --docker-compat",
                posix_shell_quote(&ferrocrate_binary.display().to_string())
            ),
            "ferrocrate-wsl".to_string(),
            socket_path.to_string_lossy().into_owned(),
        ])
}

impl Wsl2Backend {
    pub fn new(config: Wsl2Config) -> Self {
        Self::with_host(config, SystemBackendHost::shared())
    }
    pub fn with_host(config: Wsl2Config, host: Arc<dyn BackendHost>) -> Self {
        let socket_path = PathBuf::from(".local/state/ferrocrate/ferrocrate.sock");
        let prefix = ["-d", config.distro.as_str(), "--exec"];
        let exec = CommandSpec::new("wsl.exe").args(prefix);
        let start = daemon_start_command(&exec, &config.ferrocrate_binary, &socket_path);
        let ferrocrate_binary =
            (!config.ferrocrate_binary.as_os_str().is_empty()).then_some(config.ferrocrate_binary);
        Self {
            core: BackendCore::new(
                "wsl2",
                Platform::Windows,
                start,
                exec,
                Transport::WslUnixSocket {
                    distro: config.distro,
                    path: socket_path,
                },
                host,
            ),
            ferrocrate_binary: Mutex::new(ferrocrate_binary),
        }
    }

    fn resolve_ferrocrate_binary(&self) -> Result<PathBuf, BackendError> {
        if let Some(path) = self
            .ferrocrate_binary
            .lock()
            .map_err(|_| BackendError::State)?
            .clone()
        {
            return Ok(path);
        }
        let response = self.core.host.exec(
            &self.core.exec_command,
            &ExecRequest::new("sh").args(["-lc", RESOLVE_FERROCRATE_COMMAND]),
        )?;
        if response.code != 0 {
            return Err(BackendError::Command(format!(
                "failed to resolve ferrocrate inside WSL: {}",
                String::from_utf8_lossy(&response.stderr).trim()
            )));
        }
        let resolved = String::from_utf8(response.stdout)
            .map_err(|error| BackendError::Command(error.to_string()))?;
        let resolved = resolved.trim();
        if !resolved.starts_with('/') {
            return Err(BackendError::Command(format!(
                "WSL resolved a non-absolute ferrocrate path: {resolved:?}"
            )));
        }
        let resolved = PathBuf::from(resolved);
        *self
            .ferrocrate_binary
            .lock()
            .map_err(|_| BackendError::State)? = Some(resolved.clone());
        Ok(resolved)
    }

    fn resolved_ferrocrate_binary(&self) -> Result<Option<PathBuf>, BackendError> {
        self.ferrocrate_binary
            .lock()
            .map_err(|_| BackendError::State)
            .map(|path| path.clone())
    }
}

impl Backend for Wsl2Backend {
    fn name(&self) -> &'static str {
        self.core.name
    }
    fn platform(&self) -> Platform {
        self.core.platform
    }
    fn capabilities(&self) -> BackendCapabilities {
        self.core.capabilities
    }
    fn start(&self) -> Result<BackendStatus, BackendError> {
        let ferrocrate_binary = self.resolve_ferrocrate_binary()?;
        let socket_path = match &self.core.transport {
            Transport::WslUnixSocket { path, .. } => path,
            _ => return Err(BackendError::State),
        };
        self.core.start_with_commands(&[daemon_start_command(
            &self.core.exec_command,
            &ferrocrate_binary,
            socket_path,
        )])
    }
    fn stop(&self) -> Result<BackendStatus, BackendError> {
        self.core.stop()
    }
    fn status(&self) -> BackendStatus {
        self.core.status()
    }
    fn health(&self) -> Result<bool, BackendError> {
        self.core.host.health(&self.core.transport)
    }
    fn exec(&self, request: ExecRequest) -> Result<ExecResponse, BackendError> {
        let ferrocrate_binary = self.resolved_ferrocrate_binary()?;
        self.core.host.exec(
            &self.core.exec_command,
            &guest_exec_request(request, ferrocrate_binary.as_deref())?,
        )
    }
    fn exec_stream(&self, request: ExecRequest) -> Result<Box<dyn ExecStream>, BackendError> {
        let ferrocrate_binary = self.resolved_ferrocrate_binary()?;
        self.core.host.exec_stream(
            &self.core.exec_command,
            &guest_exec_request(request, ferrocrate_binary.as_deref())?,
        )
    }
    fn request(&self, request: TransportRequest) -> Result<TransportResponse, BackendError> {
        self.core.host.request(&self.core.transport, &request)
    }
    fn open_terminal(&self, request: TerminalRequest) -> Result<TerminalSession, BackendError> {
        self.core.open_terminal(request)
    }
    fn resize_terminal(&self, exec_id: &str, columns: u16, rows: u16) -> Result<(), BackendError> {
        self.core.resize_terminal(exec_id, columns, rows)
    }
    fn socket_path(&self) -> Option<PathBuf> {
        match &self.core.transport {
            Transport::WslUnixSocket { path, .. } => Some(path.clone()),
            _ => None,
        }
    }
}

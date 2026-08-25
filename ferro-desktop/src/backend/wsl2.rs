use super::*;

#[derive(Debug, Clone)]
pub struct Wsl2Config {
    pub distro: String,
    pub relay_addr: SocketAddr,
    pub relay_token: String,
}

impl Default for Wsl2Config {
    fn default() -> Self {
        Self {
            distro: std::env::var("FERROCRATE_WSL_DISTRO").unwrap_or_else(|_| "Ubuntu".into()),
            relay_addr: "127.0.0.1:4288".parse().expect("constant loopback address"),
            relay_token: std::env::var("FERROCRATE_WEB_BRIDGE_TOKEN").unwrap_or_default(),
        }
    }
}

pub struct Wsl2Backend {
    core: BackendCore,
}

fn guest_exec_request(request: ExecRequest) -> ExecRequest {
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
    guest_args.push(program);
    guest_args.extend(args);
    ExecRequest::new("env").args(guest_args).stdin(stdin)
}

impl Wsl2Backend {
    pub fn new(config: Wsl2Config) -> Self {
        Self::with_host(config, SystemBackendHost::shared())
    }
    pub fn with_host(config: Wsl2Config, host: Arc<dyn BackendHost>) -> Self {
        let socket_path = PathBuf::from(".local/state/ferrocrate/ferrocrate.sock");
        let prefix = ["-d", config.distro.as_str(), "--exec"];
        let start = CommandSpec::new("wsl.exe").args(prefix).args([
            "sh",
            "-lc",
            "exec ferrocrate daemon --socket \"$HOME/$1\" --docker-compat",
            "ferrocrate-wsl",
            socket_path.to_string_lossy().as_ref(),
        ]);
        let exec = CommandSpec::new("wsl.exe").args(prefix);
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
        }
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
        self.core.start()
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
        self.core
            .host
            .exec(&self.core.exec_command, &guest_exec_request(request))
    }
    fn exec_stream(&self, request: ExecRequest) -> Result<Box<dyn ExecStream>, BackendError> {
        self.core
            .host
            .exec_stream(&self.core.exec_command, &guest_exec_request(request))
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

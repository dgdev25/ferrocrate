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
                .unwrap_or_else(|| PathBuf::from("/home/USER/.local/bin/ferrocrate")),
        }
    }
}

pub struct Wsl2Backend {
    core: BackendCore,
    ferrocrate_binary: PathBuf,
}

fn guest_exec_request(request: ExecRequest, ferrocrate_binary: &Path) -> ExecRequest {
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
    guest_args.push(
        (program == "ferrocrate")
            .then(|| ferrocrate_binary.display().to_string())
            .unwrap_or(program),
    );
    guest_args.extend(args);
    ExecRequest::new("env").args(guest_args).stdin(stdin)
}

fn posix_shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

impl Wsl2Backend {
    pub fn new(config: Wsl2Config) -> Self {
        Self::with_host(config, SystemBackendHost::shared())
    }
    pub fn with_host(config: Wsl2Config, host: Arc<dyn BackendHost>) -> Self {
        let socket_path = PathBuf::from(".local/state/ferrocrate/ferrocrate.sock");
        let prefix = ["-d", config.distro.as_str(), "--exec"];
        let start = CommandSpec::new("wsl.exe").args(prefix).args(vec![
            "sh".to_string(),
            "-lc".to_string(),
            format!(
                "exec {} daemon --socket \"$HOME/$1\" --docker-compat",
                posix_shell_quote(&config.ferrocrate_binary.display().to_string())
            ),
            "ferrocrate-wsl".to_string(),
            socket_path.to_string_lossy().into_owned(),
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
            ferrocrate_binary: config.ferrocrate_binary,
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
            .exec(
                &self.core.exec_command,
                &guest_exec_request(request, &self.ferrocrate_binary),
            )
    }
    fn exec_stream(&self, request: ExecRequest) -> Result<Box<dyn ExecStream>, BackendError> {
        self.core
            .host
            .exec_stream(
                &self.core.exec_command,
                &guest_exec_request(request, &self.ferrocrate_binary),
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

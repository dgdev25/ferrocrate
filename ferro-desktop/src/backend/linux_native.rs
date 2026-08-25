use super::*;

#[derive(Debug, Clone)]
pub struct LinuxNativeConfig {
    pub socket_path: PathBuf,
    pub ferrocrate_binary: PathBuf,
}

impl Default for LinuxNativeConfig {
    fn default() -> Self {
        let runtime_dir = std::env::var_os("FERROCRATE_RUNTIME_DIR")
            .or_else(|| std::env::var_os("XDG_RUNTIME_DIR"))
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        Self {
            socket_path: runtime_dir.join("ferrocrate.sock"),
            ferrocrate_binary: std::env::var_os("FERROCRATE_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("ferrocrate")),
        }
    }
}

pub struct LinuxNativeBackend {
    core: BackendCore,
}

impl LinuxNativeBackend {
    pub fn new(config: LinuxNativeConfig) -> Self {
        Self::with_host(config, SystemBackendHost::shared())
    }

    pub fn with_host(config: LinuxNativeConfig, host: Arc<dyn BackendHost>) -> Self {
        let socket = config.socket_path.display().to_string();
        let start = CommandSpec::new(config.ferrocrate_binary.clone()).args([
            "daemon".to_string(),
            "--socket".into(),
            socket,
            "--docker-compat".into(),
        ]);
        let exec = CommandSpec::launcher();
        Self {
            core: BackendCore::new(
                "linux-native",
                Platform::Linux,
                start,
                exec,
                Transport::UnixSocket(config.socket_path),
                host,
            ),
        }
    }
}

impl Backend for LinuxNativeBackend {
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
        let status = self.core.status();
        if status.state == BackendState::Failed
            && status.reason.as_deref() == Some("backend process is not running")
        {
            return self.core.start().unwrap_or(status);
        }
        status
    }
    fn health(&self) -> Result<bool, BackendError> {
        self.core.host.health(&self.core.transport)
    }
    fn exec(&self, request: ExecRequest) -> Result<ExecResponse, BackendError> {
        self.core.host.exec(&self.core.exec_command, &request)
    }
    fn exec_stream(&self, request: ExecRequest) -> Result<Box<dyn ExecStream>, BackendError> {
        self.core
            .host
            .exec_stream(&self.core.exec_command, &request)
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
            Transport::UnixSocket(path) => Some(path.clone()),
            _ => None,
        }
    }
}

use super::*;

#[derive(Debug, Clone)]
pub struct MacosVmConfig {
    pub launcher: PathBuf,
    pub vm_config: PathBuf,
    pub relay_addr: SocketAddr,
    pub ssh_port: u16,
    pub guest_user: String,
    pub ssh_key: PathBuf,
}

impl Default for MacosVmConfig {
    fn default() -> Self {
        let root = std::env::var_os("FERROCRATE_VM_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("ferrocrate-vm"));
        Self {
            launcher: std::env::var_os("FERROCRATE_VM_LAUNCHER")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("vfkit")),
            vm_config: root.join("vm.json"),
            relay_addr: "127.0.0.1:4288".parse().expect("constant loopback address"),
            ssh_port: 2222,
            guest_user: "ferrocrate".into(),
            ssh_key: root.join("id_ed25519"),
        }
    }
}

pub struct MacosVmBackend {
    core: BackendCore,
}

impl MacosVmBackend {
    pub fn new(config: MacosVmConfig) -> Self {
        Self::with_host(config, SystemBackendHost::shared())
    }
    pub fn with_host(config: MacosVmConfig, host: Arc<dyn BackendHost>) -> Self {
        let start = CommandSpec::new(config.launcher)
            .args(["--config", config.vm_config.to_string_lossy().as_ref()]);
        let exec = CommandSpec::new("ssh").args([
            "-i".to_string(),
            config.ssh_key.display().to_string(),
            "-p".into(),
            config.ssh_port.to_string(),
            format!("{}@127.0.0.1", config.guest_user),
            "--".into(),
        ]);
        Self {
            core: BackendCore::new(
                "macos-vm",
                Platform::Macos,
                start,
                exec,
                Transport::Loopback(config.relay_addr),
                host,
            ),
        }
    }
}

impl Backend for MacosVmBackend {
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
    fn socket_path(&self) -> Option<PathBuf> {
        None
    }
}

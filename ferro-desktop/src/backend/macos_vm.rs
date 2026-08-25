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
        let root = std::env::var_os("FERROCRATE_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(std::env::temp_dir)
                    .join(".ferrocrate")
            });
        let vm_root = std::env::var_os("FERROCRATE_VM_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("vm"));
        Self {
            launcher: std::env::var_os("FERROCRATE_VM_LAUNCHER")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("ferro-desktop")),
            vm_config: std::env::var_os("FERROCRATE_DESKTOP_VM_STATE")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("desktop-vm.json")),
            relay_addr: std::env::var("FERROCRATE_VM_API_PORT")
                .ok()
                .and_then(|port| format!("127.0.0.1:{port}").parse().ok())
                .unwrap_or_else(|| "127.0.0.1:4288".parse().expect("constant loopback address")),
            ssh_port: std::env::var("FERROCRATE_VM_SSH_PORT")
                .ok()
                .and_then(|port| port.parse().ok())
                .unwrap_or(2222),
            guest_user: std::env::var("FERROCRATE_VM_GUEST_USER")
                .unwrap_or_else(|_| "ferro".into()),
            ssh_key: std::env::var_os("FERROCRATE_VM_SSH_KEY")
                .map(PathBuf::from)
                .unwrap_or_else(|| vm_root.join("desktop_vm_ed25519")),
        }
    }
}

pub struct MacosVmBackend {
    core: BackendCore,
    stop_command: CommandSpec,
    managed: std::sync::atomic::AtomicBool,
}

impl MacosVmBackend {
    pub fn new(config: MacosVmConfig) -> Self {
        Self::with_host(config, SystemBackendHost::shared())
    }
    pub fn with_host(config: MacosVmConfig, host: Arc<dyn BackendHost>) -> Self {
        let start = CommandSpec::new(config.launcher).args([
            "vm",
            "--state-file",
            config.vm_config.to_string_lossy().as_ref(),
            "start",
            "--foreground",
        ]);
        let stop_command = CommandSpec::new(start.program.clone()).args([
            "vm",
            "--state-file",
            config.vm_config.to_string_lossy().as_ref(),
            "stop",
        ]);
        let guest_socket = PathBuf::from(".local/state/ferrocrate/ferrocrate.sock");
        let exec = CommandSpec::new("ssh").args([
            "-i".to_string(),
            config.ssh_key.display().to_string(),
            "-p".into(),
            config.ssh_port.to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            format!("{}@127.0.0.1", config.guest_user),
            "--".into(),
        ]);
        let tunnel = CommandSpec::new("ssh").args([
            "-i".to_string(),
            config.ssh_key.display().to_string(),
            "-p".into(),
            config.ssh_port.to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "ExitOnForwardFailure=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-N".into(),
            "-L".into(),
            format!(
                "{}:/home/{}/{}",
                config.relay_addr,
                config.guest_user,
                guest_socket.display()
            ),
            format!("{}@127.0.0.1", config.guest_user),
        ]);
        Self {
            core: BackendCore::new(
                "macos-vm",
                Platform::Macos,
                start,
                exec,
                Transport::Loopback(config.relay_addr),
                host,
            )
            .with_auxiliary_start(tunnel)
            .with_readiness_timeout(Duration::from_secs(180)),
            stop_command,
            managed: std::sync::atomic::AtomicBool::new(false),
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
        match self.core.start() {
            Ok(status) => {
                self.managed
                    .store(true, std::sync::atomic::Ordering::Release);
                Ok(status)
            }
            Err(error) => {
                let _ = self.core.host.control(&self.stop_command);
                Err(error)
            }
        }
    }
    fn stop(&self) -> Result<BackendStatus, BackendError> {
        let control = self
            .managed
            .swap(false, std::sync::atomic::Ordering::AcqRel)
            .then(|| self.core.host.control(&self.stop_command))
            .transpose();
        let stopped = self.core.stop();
        control?;
        stopped
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
    fn open_terminal(&self, request: TerminalRequest) -> Result<TerminalSession, BackendError> {
        self.core.open_terminal(request)
    }
    fn resize_terminal(&self, exec_id: &str, columns: u16, rows: u16) -> Result<(), BackendError> {
        self.core.resize_terminal(exec_id, columns, rows)
    }
    fn socket_path(&self) -> Option<PathBuf> {
        Some(PathBuf::from(".local/state/ferrocrate/ferrocrate.sock"))
    }
}

impl Drop for MacosVmBackend {
    fn drop(&mut self) {
        if self
            .managed
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            let _ = self.core.host.control(&self.stop_command);
        }
    }
}

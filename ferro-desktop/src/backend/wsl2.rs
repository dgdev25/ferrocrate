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
            distro: std::env::var("FERROCRATE_WSL_DISTRO")
                .unwrap_or_else(|_| "FerrocrateDesktop".into()),
            relay_addr: "127.0.0.1:4288".parse().expect("constant loopback address"),
            relay_token: std::env::var("FERROCRATE_WEB_BRIDGE_TOKEN").unwrap_or_default(),
        }
    }
}

pub struct Wsl2Backend {
    core: BackendCore,
}

impl Wsl2Backend {
    pub fn new(config: Wsl2Config) -> Self {
        Self::with_host(config, SystemBackendHost::shared())
    }
    pub fn with_host(config: Wsl2Config, host: Arc<dyn BackendHost>) -> Self {
        let prefix = ["-d", config.distro.as_str(), "--"];
        let start = CommandSpec::new("wsl.exe").args(prefix).args([
            "ferrocrate",
            "daemon",
            "--docker-compat",
        ]);
        let exec = CommandSpec::new("wsl.exe").args(prefix);
        Self {
            core: BackendCore::new(
                "wsl2",
                Platform::Windows,
                start,
                exec,
                Transport::AuthenticatedLoopback {
                    addr: config.relay_addr,
                    bearer_token: config.relay_token,
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

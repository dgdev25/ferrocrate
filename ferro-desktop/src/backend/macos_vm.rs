use super::*;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ProvisionedVmState {
    config: ProvisionedVmRecord,
}

#[derive(Debug, Deserialize)]
struct ProvisionedVmRecord {
    #[serde(default)]
    ssh_port: Option<u16>,
    #[serde(default)]
    api_port: Option<u16>,
    #[serde(default)]
    guest_user: Option<String>,
    ssh_private_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct MacosVmConfig {
    pub launcher: PathBuf,
    pub vm_config: PathBuf,
    pub relay_addr: SocketAddr,
    pub ssh_port: u16,
    pub guest_user: String,
    pub ssh_key: PathBuf,
    /// Host path to a Linux x86_64 ferrocrate binary copied into the guest.
    pub guest_engine_path: PathBuf,
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
        let fallback = Self {
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
                .unwrap_or_else(|_| "ubuntu".into()),
            ssh_key: std::env::var_os("FERROCRATE_VM_SSH_KEY")
                .map(PathBuf::from)
                .unwrap_or_else(|| vm_root.join("desktop_vm_ed25519")),
            guest_engine_path: std::env::var_os("FERROCRATE_VM_GUEST_ENGINE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| vm_root.join("ferrocrate-guest-engine-x86_64")),
        };
        Self::from_vm_state(&fallback.vm_config).unwrap_or(fallback)
    }
}

impl MacosVmConfig {
    /// Loads connection settings from the state that VM provisioning wrote.
    /// The state record, rather than an independently-derived default, is the
    /// authority for the guest identity and its forwarded ports.
    pub fn from_vm_state(vm_config: &Path) -> Result<Self, BackendError> {
        let state: ProvisionedVmState = serde_json::from_slice(&std::fs::read(vm_config)?)
            .map_err(|error| {
                BackendError::Unavailable(format!(
                    "invalid provisioned VM state {}: {error}",
                    vm_config.display()
                ))
            })?;
        let record = state.config;
        let ssh_key = record.ssh_private_key_path.ok_or_else(|| {
            BackendError::Unavailable(format!(
                "provisioned VM state {} does not record ssh_private_key_path",
                vm_config.display()
            ))
        })?;
        Ok(Self {
            launcher: std::env::var_os("FERROCRATE_VM_LAUNCHER")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("ferro-desktop")),
            vm_config: vm_config.to_path_buf(),
            relay_addr: format!("127.0.0.1:{}", record.api_port.unwrap_or(4288))
                .parse()
                .expect("recorded VM API port is valid"),
            ssh_port: record.ssh_port.unwrap_or(2222),
            guest_user: record.guest_user.unwrap_or_else(|| "ubuntu".into()),
            ssh_key,
            guest_engine_path: std::env::var_os("FERROCRATE_VM_GUEST_ENGINE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    vm_config
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join("ferrocrate-guest-engine-x86_64")
                }),
        })
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
        let known_hosts = config
            .vm_config
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("known_hosts");
        let start = CommandSpec::new(config.launcher.clone()).args([
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
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            "IdentityAgent=none".into(),
            "-o".into(),
            format!("UserKnownHostsFile={}", known_hosts.display()),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            format!("{}@127.0.0.1", config.guest_user),
        ]);
        let tunnel = CommandSpec::new("ssh").args([
            "-i".to_string(),
            config.ssh_key.display().to_string(),
            "-p".into(),
            config.ssh_port.to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            "IdentityAgent=none".into(),
            "-o".into(),
            "ExitOnForwardFailure=yes".into(),
            "-o".into(),
            format!("UserKnownHostsFile={}", known_hosts.display()),
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
        let provisioner = guest_provisioner_command(&config, &known_hosts);
        Self {
            core: BackendCore::new(
                "macos-vm",
                Platform::Macos,
                start,
                exec,
                Transport::Loopback(config.relay_addr),
                host,
            )
            .with_auxiliary_start(provisioner)
            .with_auxiliary_start(tunnel)
            .with_readiness_timeout(Duration::from_secs(180)),
            stop_command,
            managed: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

fn guest_provisioner_command(
    config: &MacosVmConfig,
    known_hosts: &Path,
) -> CommandSpec {
    let identity = config.ssh_key.display().to_string();
    let port = config.ssh_port.to_string();
    let known_hosts = format!("UserKnownHostsFile={}", known_hosts.display());
    let target = format!("{}@127.0.0.1", config.guest_user);
    let guest_tmp = format!("{target}:/tmp/ferrocrate");
    let guest_runtime = format!("/home/{}/.local/state/ferrocrate", config.guest_user);
    let service = format!(
        "[Unit]\nDescription=Ferrocrate guest engine\nAfter=network-online.target\n\n[Service]\nType=simple\nUser={}\nExecStart=/usr/local/bin/ferrocrate daemon --socket {}/ferrocrate.sock --docker-compat\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n",
        config.guest_user, guest_runtime
    );
    let remote = format!(
        "sudo install -D -m 0755 /tmp/ferrocrate /usr/local/bin/ferrocrate && sudo install -d -o {user} -g {user} {runtime} && printf %s {service} | sudo tee /etc/systemd/system/ferrocrate.service >/dev/null && sudo systemctl daemon-reload && sudo systemctl enable --now ferrocrate.service",
        user = posix_shell_quote(&config.guest_user),
        runtime = posix_shell_quote(&guest_runtime),
        service = posix_shell_quote(&service),
    );
    let ssh_options = [
        "-i".to_string(),
        identity.clone(),
        "-p".to_string(),
        port.clone(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "IdentitiesOnly=yes".to_string(),
        "-o".to_string(),
        "IdentityAgent=none".to_string(),
        "-o".to_string(),
        known_hosts,
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
    ];
    let quote_words = |words: &[String]| {
        words
            .iter()
            .map(|word| posix_shell_quote(word))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let scp = format!(
        "scp {} {} {}",
        quote_words(&ssh_options),
        posix_shell_quote(&config.guest_engine_path.display().to_string()),
        posix_shell_quote(&guest_tmp),
    );
    let mut ssh_words = ssh_options.to_vec();
    ssh_words.push(target);
    ssh_words.push(remote);
    let ssh = format!("ssh {}", quote_words(&ssh_words));
    CommandSpec::new("sh").args(vec![
        "-lc".to_string(),
        format!(
            "until {scp}; do sleep 1; done; until {ssh}; do sleep 1; done; exec sleep 2147483647"
        ),
    ])
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
        self.core
            .host
            .exec(&self.core.exec_command, &remote_exec_request(request))
    }
    fn exec_stream(&self, request: ExecRequest) -> Result<Box<dyn ExecStream>, BackendError> {
        self.core
            .host
            .exec_stream(&self.core.exec_command, &remote_exec_request(request))
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

fn remote_exec_request(request: ExecRequest) -> ExecRequest {
    let mut command = String::from("exec env --");
    for (name, value) in &request.env {
        command.push(' ');
        command.push_str(&posix_shell_quote(&format!("{name}={value}")));
    }
    for value in std::iter::once(&request.program).chain(request.args.iter()) {
        command.push(' ');
        command.push_str(&posix_shell_quote(value));
    }
    ExecRequest::new(command).stdin(request.stdin)
}

fn posix_shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioned_vm_record_drives_ssh_identity_and_isolated_known_hosts() {
        let temp = tempfile::tempdir().expect("temp state directory");
        let state_file = temp.path().join("desktop-vm.json");
        std::fs::write(
            &state_file,
            r#"{
                "config": {
                    "ssh_port": 2207,
                    "api_port": 4299,
                    "guest_user": "ferro",
                    "ssh_private_key_path": "/state/vm_ssh_key"
                }
            }"#,
        )
        .expect("write provisioned state");

        let config = MacosVmConfig::from_vm_state(&state_file).expect("read provisioned state");
        let backend = MacosVmBackend::with_host(config, Arc::new(TestHost));
        let commands = &backend.core.start_commands;
        let known_hosts = format!(
            "UserKnownHostsFile={}",
            temp.path().join("known_hosts").display()
        );

        for command in commands
            .iter()
            .filter(|command| command.program == PathBuf::from("ssh"))
        {
            assert!(command
                .args
                .windows(2)
                .any(|pair| pair == ["-i", "/state/vm_ssh_key"]));
            assert!(command.args.windows(2).any(|pair| pair == ["-p", "2207"]));
            assert!(command
                .args
                .windows(2)
                .any(|pair| pair[0] == "-o" && pair[1] == known_hosts));
            assert!(command
                .args
                .windows(2)
                .any(|pair| pair == ["-o", "StrictHostKeyChecking=accept-new"]));
        }
    }

    struct TestHost;

    impl BackendHost for TestHost {
        fn start(&self, _: &CommandSpec) -> Result<(), BackendError> {
            Ok(())
        }
        fn stop(&self) -> Result<(), BackendError> {
            Ok(())
        }
        fn is_running(&self) -> Result<bool, BackendError> {
            Ok(false)
        }
        fn health(&self, _: &Transport) -> Result<bool, BackendError> {
            Ok(false)
        }
        fn request(
            &self,
            _: &Transport,
            _: &TransportRequest,
        ) -> Result<TransportResponse, BackendError> {
            unreachable!()
        }
        fn exec(&self, _: &CommandSpec, _: &ExecRequest) -> Result<ExecResponse, BackendError> {
            unreachable!()
        }
        fn exec_stream(
            &self,
            _: &CommandSpec,
            _: &ExecRequest,
        ) -> Result<Box<dyn ExecStream>, BackendError> {
            unreachable!()
        }
        fn open_terminal(
            &self,
            _: &Transport,
            _: &TerminalRequest,
        ) -> Result<TerminalSession, BackendError> {
            unreachable!()
        }
    }
}

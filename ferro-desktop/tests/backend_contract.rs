use ferro_desktop::backend::{
    select_backend_for, Backend, BackendCapabilities, BackendError, BackendHost, BackendState,
    CommandSpec, ExecRequest, ExecResponse, LinuxNativeBackend, LinuxNativeConfig, MacosVmBackend,
    MacosVmConfig, Platform, TerminalRequest, TerminalSession, Transport, TransportRequest,
    TransportResponse, Wsl2Backend, Wsl2Config,
};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

struct FakeDuplex(std::io::Cursor<Vec<u8>>);

impl Read for FakeDuplex {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buffer)
    }
}

impl Write for FakeDuplex {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.write(buffer)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ferro_desktop::backend::DuplexStream for FakeDuplex {
    fn try_clone_stream(
        &self,
    ) -> Result<Box<dyn ferro_desktop::backend::DuplexStream>, BackendError> {
        Ok(Box::new(Self(std::io::Cursor::new(Vec::new()))))
    }
    fn shutdown_write(&self) -> Result<(), BackendError> {
        Ok(())
    }
}

#[derive(Default)]
struct FakeHost {
    running: Mutex<bool>,
    healthy: Mutex<bool>,
    starts: Mutex<Vec<CommandSpec>>,
    stops: Mutex<usize>,
    requests: Mutex<Vec<(Transport, TransportRequest)>>,
    execs: Mutex<Vec<(CommandSpec, ExecRequest)>>,
    terminals: Mutex<Vec<(Transport, TerminalRequest)>>,
    controls: Mutex<Vec<CommandSpec>>,
    maintain_calls: Mutex<usize>,
    healthy_after_maintains: Option<usize>,
    becomes_healthy_on_start: bool,
    fail_program: Mutex<Option<String>>,
    exec_stdout: Mutex<Vec<u8>>,
}

impl FakeHost {
    fn healthy(value: bool) -> Arc<Self> {
        Arc::new(Self {
            healthy: Mutex::new(value),
            ..Self::default()
        })
    }

    fn ready_after_start() -> Arc<Self> {
        Arc::new(Self {
            becomes_healthy_on_start: true,
            ..Self::default()
        })
    }

    fn healthy_after_maintains(count: usize) -> Arc<Self> {
        Arc::new(Self {
            healthy_after_maintains: Some(count),
            ..Self::default()
        })
    }

    fn resolves_engine_to(path: &str) -> Arc<Self> {
        Arc::new(Self {
            becomes_healthy_on_start: true,
            exec_stdout: Mutex::new(format!("{path}\n").into_bytes()),
            ..Self::default()
        })
    }
}

impl BackendHost for FakeHost {
    fn start(&self, command: &CommandSpec) -> Result<(), BackendError> {
        if self.fail_program.lock().unwrap().as_deref() == command.program.to_str() {
            return Err(BackendError::Command("injected start failure".into()));
        }
        self.starts.lock().unwrap().push(command.clone());
        *self.running.lock().unwrap() = true;
        if self.becomes_healthy_on_start {
            *self.healthy.lock().unwrap() = true;
        }
        Ok(())
    }

    fn stop(&self) -> Result<(), BackendError> {
        *self.stops.lock().unwrap() += 1;
        *self.running.lock().unwrap() = false;
        Ok(())
    }

    fn is_running(&self) -> Result<bool, BackendError> {
        Ok(*self.running.lock().unwrap())
    }

    fn health(&self, _transport: &Transport) -> Result<bool, BackendError> {
        Ok(*self.healthy.lock().unwrap())
    }

    fn readiness_timeout(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }

    fn maintain(&self) -> Result<(), BackendError> {
        let mut calls = self.maintain_calls.lock().unwrap();
        *calls += 1;
        if self
            .healthy_after_maintains
            .is_some_and(|required| *calls >= required)
        {
            *self.healthy.lock().unwrap() = true;
        }
        Ok(())
    }

    fn control(&self, command: &CommandSpec) -> Result<(), BackendError> {
        self.controls.lock().unwrap().push(command.clone());
        Ok(())
    }

    fn request(
        &self,
        transport: &Transport,
        request: &TransportRequest,
    ) -> Result<TransportResponse, BackendError> {
        self.requests
            .lock()
            .unwrap()
            .push((transport.clone(), request.clone()));
        Ok(TransportResponse {
            status: 201,
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"id":"created"}"#.to_vec(),
        })
    }

    fn exec(
        &self,
        command: &CommandSpec,
        request: &ExecRequest,
    ) -> Result<ExecResponse, BackendError> {
        self.execs
            .lock()
            .unwrap()
            .push((command.clone(), request.clone()));
        Ok(ExecResponse {
            code: 0,
            stdout: self.exec_stdout.lock().unwrap().clone(),
            stderr: Vec::new(),
        })
    }

    fn exec_stream(
        &self,
        _command: &CommandSpec,
        _request: &ExecRequest,
    ) -> Result<Box<dyn ferro_desktop::backend::ExecStream>, BackendError> {
        Err(BackendError::Unavailable(
            "stream not used by this test".into(),
        ))
    }

    fn open_terminal(
        &self,
        transport: &Transport,
        request: &TerminalRequest,
    ) -> Result<TerminalSession, BackendError> {
        self.terminals
            .lock()
            .unwrap()
            .push((transport.clone(), request.clone()));
        Ok(TerminalSession {
            exec_id: "exec-123".into(),
            stream: Box::new(FakeDuplex(std::io::Cursor::new(Vec::new()))),
        })
    }
}

fn linux_config() -> LinuxNativeConfig {
    LinuxNativeConfig {
        socket_path: PathBuf::from("/run/user/1000/ferrocrate.sock"),
        ferrocrate_binary: PathBuf::from("/opt/ferrocrate/bin/ferrocrate"),
    }
}

fn wsl_config() -> Wsl2Config {
    Wsl2Config {
        relay_token: "bridge-secret".into(),
        ferrocrate_binary: PathBuf::from("/home/ferro/.local/bin/ferrocrate"),
        ..Wsl2Config::default()
    }
}

#[test]
fn trait_object_dispatches_to_selected_backend() {
    let host = FakeHost::healthy(true);
    let backend: Box<dyn Backend> = select_backend_for(
        Platform::Linux,
        host,
        linux_config(),
        wsl_config(),
        MacosVmConfig::default(),
    )
    .unwrap();

    assert_eq!(backend.name(), "linux-native");
    assert_eq!(backend.platform(), Platform::Linux);
    assert_eq!(backend.capabilities(), BackendCapabilities::native());
}

#[test]
fn platform_selection_uses_the_exact_backend_names() {
    for (platform, expected) in [
        (Platform::Linux, "linux-native"),
        (Platform::Windows, "wsl2"),
        (Platform::Macos, "macos-vm"),
    ] {
        let backend = select_backend_for(
            platform,
            FakeHost::healthy(true),
            linux_config(),
            wsl_config(),
            MacosVmConfig::default(),
        )
        .unwrap();
        assert_eq!(backend.name(), expected);
    }
    assert!(select_backend_for(
        Platform::Unsupported,
        FakeHost::healthy(true),
        linux_config(),
        wsl_config(),
        MacosVmConfig::default(),
    )
    .is_err());
}

#[test]
fn linux_native_owns_daemon_start_and_stop_transitions() {
    let host = FakeHost::ready_after_start();
    let backend = LinuxNativeBackend::with_host(linux_config(), host.clone());

    assert_eq!(backend.status().state, BackendState::Stopped);
    assert_eq!(backend.start().unwrap().state, BackendState::Running);
    assert_eq!(
        host.starts.lock().unwrap().as_slice(),
        &[CommandSpec::new("/opt/ferrocrate/bin/ferrocrate").args([
            "daemon",
            "--socket",
            "/run/user/1000/ferrocrate.sock",
            "--docker-compat",
        ])]
    );
    assert_eq!(backend.stop().unwrap().state, BackendState::Stopped);
    assert_eq!(*host.stops.lock().unwrap(), 1);
}

#[test]
fn linux_native_restarts_its_owned_daemon_after_an_unexpected_exit() {
    let host = FakeHost::ready_after_start();
    let backend = LinuxNativeBackend::with_host(linux_config(), host.clone());
    backend.start().unwrap();
    *host.running.lock().unwrap() = false;
    *host.healthy.lock().unwrap() = false;

    let status = backend.status();

    assert_eq!(status.state, BackendState::Running);
    assert!(status.healthy);
    assert_eq!(host.starts.lock().unwrap().len(), 2);
}

#[test]
fn wsl2_uses_a_real_subprocess_lifecycle() {
    let host = FakeHost::ready_after_start();
    let config = Wsl2Config {
        distro: "Ubuntu".into(),
        relay_addr: "127.0.0.1:4288".parse().unwrap(),
        relay_token: String::new(),
        ferrocrate_binary: PathBuf::from("/home/ferro/.local/bin/ferrocrate"),
    };
    let backend = Wsl2Backend::with_host(config, host.clone());

    assert_eq!(backend.start().unwrap().state, BackendState::Running);
    assert_eq!(
        host.starts.lock().unwrap().as_slice(),
        &[CommandSpec::new("wsl.exe").args([
            "-d",
            "Ubuntu",
            "--exec",
            "sh",
            "-lc",
            "exec '/home/ferro/.local/bin/ferrocrate' daemon --socket \"$HOME/$1\" --docker-compat",
            "ferrocrate-wsl",
            ".local/state/ferrocrate/ferrocrate.sock",
        ])]
    );
    assert_eq!(
        backend.status().endpoint,
        "wsl://Ubuntu/$HOME/.local/state/ferrocrate/ferrocrate.sock"
    );
    assert_eq!(
        backend.socket_path(),
        Some(PathBuf::from(".local/state/ferrocrate/ferrocrate.sock"))
    );
    assert_eq!(backend.stop().unwrap().state, BackendState::Stopped);
}

#[test]
fn wsl2_resolves_and_records_the_default_guest_engine_before_start() {
    let host = FakeHost::resolves_engine_to("/home/ferro/.local/bin/ferrocrate");
    let backend = Wsl2Backend::with_host(
        Wsl2Config {
            distro: "FerrocrateDesktop".into(),
            relay_addr: "127.0.0.1:4288".parse().unwrap(),
            relay_token: String::new(),
            ferrocrate_binary: PathBuf::new(),
        },
        host.clone(),
    );

    backend.start().unwrap();
    backend
        .exec(ExecRequest::new("ferrocrate").args(["doctor", "--json"]))
        .unwrap();

    assert_eq!(
        host.execs.lock().unwrap().as_slice(),
        &[
            (
                CommandSpec::new("wsl.exe").args(["-d", "FerrocrateDesktop", "--exec",]),
                ExecRequest::new("sh").args([
                    "-lc",
                    "PATH=\"$HOME/.local/bin:$PATH\"; command -v ferrocrate",
                ]),
            ),
            (
                CommandSpec::new("wsl.exe").args(["-d", "FerrocrateDesktop", "--exec",]),
                ExecRequest::new("env").args([
                    "/home/ferro/.local/bin/ferrocrate",
                    "doctor",
                    "--json",
                ]),
            ),
        ]
    );
    assert_eq!(
        host.starts.lock().unwrap().as_slice(),
        &[CommandSpec::new("wsl.exe").args([
            "-d",
            "FerrocrateDesktop",
            "--exec",
            "sh",
            "-lc",
            "exec '/home/ferro/.local/bin/ferrocrate' daemon --socket \"$HOME/$1\" --docker-compat",
            "ferrocrate-wsl",
            ".local/state/ferrocrate/ferrocrate.sock",
        ])]
    );
}

#[test]
fn wsl2_attaches_to_a_healthy_supervisor_owned_engine() {
    let host = FakeHost::healthy(true);
    let backend = Wsl2Backend::with_host(wsl_config(), host.clone());

    let status = backend.start().expect("attach to the running WSL engine");

    assert_eq!(status.state, BackendState::Running);
    assert!(status.healthy);
    assert!(host.starts.lock().unwrap().is_empty());
}

#[test]
fn macos_backend_starts_the_provisioned_vm_and_stops_owned_children() {
    let host = FakeHost::ready_after_start();
    let config = MacosVmConfig {
        launcher: PathBuf::from("/usr/local/bin/ferro-desktop"),
        vm_config: PathBuf::from("/Users/test/.ferrocrate/desktop-vm.json"),
        relay_addr: "127.0.0.1:4288".parse().unwrap(),
        ssh_port: 2222,
        guest_user: "ferro".into(),
        ssh_key: PathBuf::from("/Users/test/.ferrocrate/vm/desktop_vm_ed25519"),
        guest_engine_path: PathBuf::from("/Users/test/ferrocrate-guest-engine-x86_64"),
    };
    let backend = MacosVmBackend::with_host(config, host.clone());

    assert_eq!(backend.start().unwrap().state, BackendState::Running);
    let starts = host.starts.lock().unwrap();
    assert_eq!(starts.len(), 2);
    assert_eq!(
        starts[0],
        CommandSpec::new("/usr/local/bin/ferro-desktop").args([
            "vm",
            "--state-file",
            "/Users/test/.ferrocrate/desktop-vm.json",
            "start",
            "--foreground",
        ])
    );
    assert_eq!(
        backend.socket_path(),
        Some(PathBuf::from(".local/state/ferrocrate/ferrocrate.sock"))
    );
    assert_eq!(backend.stop().unwrap().state, BackendState::Stopped);
    assert_eq!(
        host.controls.lock().unwrap().as_slice(),
        &[CommandSpec::new("/usr/local/bin/ferro-desktop").args([
            "vm",
            "--state-file",
            "/Users/test/.ferrocrate/desktop-vm.json",
            "stop",
        ])]
    );
}

#[test]
fn macos_backend_uses_per_request_guest_relay_without_a_shared_host_port() {
    let host = FakeHost::ready_after_start();
    let config = MacosVmConfig {
        launcher: PathBuf::from("/usr/local/bin/ferro-desktop"),
        vm_config: PathBuf::from("/Users/test/.ferrocrate/desktop-vm.json"),
        relay_addr: "127.0.0.1:4288".parse().unwrap(),
        ssh_port: 2222,
        guest_user: "ferro".into(),
        ssh_key: PathBuf::from("/Users/test/.ferrocrate/vm/desktop_vm_ed25519"),
        guest_engine_path: PathBuf::from("/Users/test/ferrocrate-guest-engine-x86_64"),
    };
    let backend = MacosVmBackend::with_host(config, host.clone());

    backend.start().unwrap();
    backend
        .request(TransportRequest::new("GET", "/_ping"))
        .unwrap();

    assert_eq!(host.starts.lock().unwrap().len(), 2);
    assert!(host
        .starts
        .lock()
        .unwrap()
        .iter()
        .all(|command| command.program.as_path() != Path::new("ssh")));
    assert_eq!(
        host.requests.lock().unwrap()[0].0.to_string(),
        "ssh://ferro@127.0.0.1:2222/home/ferro/.local/state/ferrocrate/ferrocrate.sock"
    );
}

#[test]
fn macos_cold_start_gets_a_backend_specific_readiness_window() {
    let mac_host = FakeHost::healthy_after_maintains(2);
    let macos = MacosVmBackend::with_host(MacosVmConfig::default(), mac_host.clone());
    assert_eq!(macos.start().unwrap().state, BackendState::Running);
    assert_eq!(*mac_host.maintain_calls.lock().unwrap(), 2);

    let linux_host = FakeHost::healthy_after_maintains(2);
    let linux = LinuxNativeBackend::with_host(linux_config(), linux_host.clone());
    assert!(linux.start().is_err());
    assert_eq!(*linux_host.maintain_calls.lock().unwrap(), 1);
}

#[test]
fn macos_stop_terminates_a_vm_adopted_from_installer_state() {
    let host = FakeHost::healthy(true);
    let backend = MacosVmBackend::with_host(MacosVmConfig::default(), host.clone());

    assert_eq!(backend.start().unwrap().state, BackendState::Running);
    assert!(host.starts.lock().unwrap().is_empty());
    assert_eq!(backend.stop().unwrap().state, BackendState::Stopped);
    assert_eq!(host.controls.lock().unwrap().len(), 1);
    assert_eq!(
        host.controls.lock().unwrap()[0].args.last().unwrap(),
        "stop"
    );
}

#[test]
fn macos_vm_defaults_match_the_installer_layout() {
    let config = MacosVmConfig::default();
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let root = home.join(".ferrocrate");

    assert_eq!(config.launcher, PathBuf::from("ferro-desktop"));
    assert_eq!(config.vm_config, root.join("desktop-vm.json"));
    assert_eq!(config.guest_user, "ubuntu");
    // A provisioned VM record on this machine overrides the installer-layout key path.
    let recorded_key = std::fs::read_to_string(root.join("desktop-vm.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|record| {
            record["config"]["ssh_private_key_path"]
                .as_str()
                .map(PathBuf::from)
        });
    assert_eq!(
        config.ssh_key,
        recorded_key.unwrap_or_else(|| root.join("vm/desktop_vm_ed25519"))
    );
    assert_eq!(config.ssh_port, 2222);
    assert_eq!(config.relay_addr, "127.0.0.1:4288".parse().unwrap());
}

fn captured_macos_remote_command(request: ExecRequest) -> (CommandSpec, ExecRequest) {
    let host = FakeHost::healthy(true);
    let backend = MacosVmBackend::with_host(MacosVmConfig::default(), host.clone());

    backend.exec(request).unwrap();

    let captured = host.execs.lock().unwrap().pop().unwrap();
    captured
}

#[test]
fn macos_exec_quotes_semicolons_in_remote_programs() {
    let (ssh, request) =
        captured_macos_remote_command(ExecRequest::new("x; touch /home/ferro/pwned #"));

    assert_eq!(ssh.args.last().unwrap(), "ubuntu@127.0.0.1");
    assert_eq!(
        request.program,
        "exec env -- 'x; touch /home/ferro/pwned #'"
    );
    assert!(request.args.is_empty());
    assert!(request.env.is_empty());
}

#[test]
fn macos_exec_quotes_command_substitution_in_remote_arguments() {
    let (_, request) = captured_macos_remote_command(
        ExecRequest::new("printf").args(["$(touch /home/ferro/pwned)"]),
    );

    assert_eq!(
        request.program,
        "exec env -- 'printf' '$(touch /home/ferro/pwned)'"
    );
}

#[test]
fn macos_exec_preserves_spaces_in_one_remote_argument() {
    let (_, request) = captured_macos_remote_command(
        ExecRequest::new("printf").args(["one argument with spaces"]),
    );

    assert_eq!(
        request.program,
        "exec env -- 'printf' 'one argument with spaces'"
    );
}

#[test]
fn macos_exec_escapes_single_quotes_in_remote_arguments() {
    let (_, request) =
        captured_macos_remote_command(ExecRequest::new("printf").args(["it's literal"]));

    assert_eq!(request.program, "exec env -- 'printf' 'it'\"'\"'s literal'");
}

#[test]
fn macos_exec_quotes_hostile_remote_environment_values() {
    let (_, request) = captured_macos_remote_command(
        ExecRequest::new("printenv")
            .args(["PAYLOAD"])
            .env("PAYLOAD", "x; $(touch /home/ferro/pwned) 'quoted'"),
    );

    assert_eq!(
        request.program,
        "exec env -- 'PAYLOAD=x; $(touch /home/ferro/pwned) '\"'\"'quoted'\"'\"'' 'printenv' 'PAYLOAD'"
    );
    assert!(request.env.is_empty());
}

#[test]
fn start_does_not_report_running_before_the_health_check_passes() {
    let host = Arc::new(FakeHost::default());
    let backend = LinuxNativeBackend::with_host(linux_config(), host);
    assert!(backend.start().is_err());
    assert_eq!(backend.status().state, BackendState::Failed);
}

#[test]
fn linux_native_adopts_an_already_healthy_daemon_without_spawning() {
    let host = FakeHost::healthy(true);
    let backend = LinuxNativeBackend::with_host(linux_config(), host.clone());

    let status = backend.start().unwrap();

    assert_eq!(status.state, BackendState::Running);
    assert!(status.healthy);
    assert!(host.starts.lock().unwrap().is_empty());
}

#[test]
fn wsl2_selection_does_not_require_an_installer_impossible_relay_token() {
    let result = select_backend_for(
        Platform::Windows,
        FakeHost::healthy(true),
        linux_config(),
        Wsl2Config {
            relay_token: String::new(),
            ..Wsl2Config::default()
        },
        MacosVmConfig::default(),
    );

    assert!(result.is_ok());
}

#[test]
fn proxy_requests_route_through_the_selected_backend_transport() {
    let host = FakeHost::healthy(true);
    let backend = Wsl2Backend::with_host(
        Wsl2Config {
            distro: "FerrocrateDesktop".into(),
            relay_addr: "127.0.0.1:4288".parse().unwrap(),
            relay_token: "bridge-secret".into(),
            ferrocrate_binary: PathBuf::from("/home/tester/.local/bin/ferrocrate"),
        },
        host.clone(),
    );
    let request = TransportRequest::new("POST", "/volumes")
        .header("content-type", "application/json")
        .body(br#"{"name":"data"}"#.to_vec());

    let response = backend.request(request.clone()).unwrap();

    assert_eq!(response.status, 201);
    let requests = host.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].0.to_string(),
        "wsl://FerrocrateDesktop/$HOME/.local/state/ferrocrate/ferrocrate.sock"
    );
    assert_eq!(requests[0].1, request);
}

#[test]
fn exec_request_names_the_real_program_without_linux_argv_duplication() {
    let host = FakeHost::healthy(true);
    let backend = LinuxNativeBackend::with_host(linux_config(), host.clone());
    let request = ExecRequest::new("ferrocrate").args(["images", "--format", "json"]);

    let response = backend.exec(request.clone()).unwrap();

    assert_eq!(response.code, 0);
    assert_eq!(
        host.execs.lock().unwrap().as_slice(),
        &[(CommandSpec::launcher(), request)]
    );
}

#[test]
fn wsl_exec_forwards_environment_inside_the_guest() {
    let host = FakeHost::healthy(true);
    let backend = Wsl2Backend::with_host(
        Wsl2Config {
            distro: "FerrocrateDesktop".into(),
            ..wsl_config()
        },
        host.clone(),
    );
    let request = ExecRequest::new("sh")
        .args(["-c", "printf '%s' \"$NO_COLOR\""])
        .env("NO_COLOR", "1")
        .stdin(b"input".to_vec());

    backend.exec(request).unwrap();

    assert_eq!(
        host.execs.lock().unwrap().as_slice(),
        &[(
            CommandSpec::new("wsl.exe").args(["-d", "FerrocrateDesktop", "--exec"]),
            ExecRequest::new("env")
                .args(["NO_COLOR=1", "sh", "-c", "printf '%s' \"$NO_COLOR\"",])
                .stdin(b"input".to_vec()),
        )]
    );
}

#[test]
fn wsl_exec_uses_the_configured_guest_engine_path() {
    let host = FakeHost::healthy(true);
    let backend = Wsl2Backend::with_host(
        Wsl2Config {
            distro: "FerrocrateDesktop".into(),
            ferrocrate_binary: PathBuf::from("/home/ferro/.local/bin/ferrocrate"),
            ..wsl_config()
        },
        host.clone(),
    );

    backend
        .exec(ExecRequest::new("ferrocrate").args(["doctor"]))
        .unwrap();

    assert_eq!(
        host.execs.lock().unwrap().as_slice(),
        &[ (
            CommandSpec::new("wsl.exe").args(["-d", "FerrocrateDesktop", "--exec"]),
            ExecRequest::new("env").args([
                "/home/ferro/.local/bin/ferrocrate",
                "doctor",
            ]),
        )]
    );
}

#[test]
fn macos_backend_provisions_the_configured_guest_engine_before_relay_health() {
    let host = FakeHost::ready_after_start();
    let backend = MacosVmBackend::with_host(
        MacosVmConfig {
            launcher: PathBuf::from("/usr/local/bin/ferro-desktop"),
            vm_config: PathBuf::from("/Users/test/.ferrocrate/desktop-vm.json"),
            relay_addr: "127.0.0.1:4288".parse().unwrap(),
            ssh_port: 2222,
            guest_user: "ferro".into(),
            ssh_key: PathBuf::from("/Users/test/.ferrocrate/vm/desktop_vm_ed25519"),
            guest_engine_path: PathBuf::from("/Users/test/ferrocrate-guest-engine-x86_64"),
        },
        host.clone(),
    );

    backend.start().unwrap();

    let commands = host.starts.lock().unwrap();
    let provisioner = commands
        .iter()
        .find(|command| command.program.as_path() == Path::new("sh"))
        .expect("guest provisioning command");
    assert_eq!(provisioner.args[0], "-lc");
    assert!(provisioner.args[1].contains("scp"));
    assert!(provisioner.args[1].contains("'-P' '2222'"));
    assert!(provisioner.args[1].contains("/Users/test/ferrocrate-guest-engine-x86_64"));
    assert!(provisioner.args[1].contains("systemctl enable --now ferrocrate.service"));
    assert!(provisioner.args[1].contains("/home/ferro/.local/state/ferrocrate/ferrocrate.sock"));
}

#[test]
fn streaming_exec_keeps_stdin_open_for_interactive_round_trips() {
    let backend = LinuxNativeBackend::new(linux_config());
    let mut stream = backend
        .exec_stream(ExecRequest::new("sh").args(["-c", "cat"]))
        .unwrap();

    stream.write_all(b"interactive input\n").unwrap();
    stream.close_stdin().unwrap();
    let mut output = String::new();
    stream.read_to_string(&mut output).unwrap();

    assert_eq!(stream.wait().unwrap(), 0);
    assert_eq!(output, "interactive input\n");
}

#[test]
fn streaming_exec_exposes_stdout_and_stderr_as_separate_channels() {
    let backend = LinuxNativeBackend::new(linux_config());
    let mut stream = backend
        .exec_stream(ExecRequest::new("sh").args(["-c", "printf stdout; printf stderr >&2"]))
        .unwrap();
    stream.close_stdin().unwrap();
    let mut stdout = stream.take_stdout().unwrap();
    let mut stderr = stream.take_stderr().unwrap();
    let mut stdout_text = String::new();
    let mut stderr_text = String::new();

    stdout.read_to_string(&mut stdout_text).unwrap();
    stderr.read_to_string(&mut stderr_text).unwrap();

    assert_eq!(stream.wait().unwrap(), 0);
    assert_eq!(stdout_text, "stdout");
    assert_eq!(stderr_text, "stderr");
}

#[test]
fn terminal_open_and_resize_route_through_the_backend_transport() {
    let host = FakeHost::healthy(true);
    let backend = Wsl2Backend::with_host(wsl_config(), host.clone());
    let request = TerminalRequest {
        container: "web/api".into(),
        command: vec!["sh".into()],
        env: vec!["TERM=xterm".into()],
        user: Some("1000".into()),
        workdir: Some("/workspace".into()),
    };

    let session = backend.open_terminal(request.clone()).unwrap();
    backend.resize_terminal(&session.exec_id, 100, 40).unwrap();

    assert_eq!(session.exec_id, "exec-123");
    assert_eq!(host.terminals.lock().unwrap()[0].1, request);
    assert_eq!(
        host.requests.lock().unwrap().last().unwrap().1,
        TransportRequest::new("POST", "/exec/exec-123/resize?w=100&h=40")
    );
}

#[test]
fn partial_macos_provisioner_start_rolls_back_every_owned_child() {
    let host = FakeHost::ready_after_start();
    *host.fail_program.lock().unwrap() = Some("sh".into());
    let backend = MacosVmBackend::with_host(MacosVmConfig::default(), host.clone());

    assert!(backend.start().is_err());
    assert_eq!(*host.stops.lock().unwrap(), 1);
    assert!(!*host.running.lock().unwrap());
}

#[test]
fn dropping_an_owned_backend_stops_children_but_dropping_an_adopted_one_does_not() {
    let owned_host = FakeHost::ready_after_start();
    {
        let backend = LinuxNativeBackend::with_host(linux_config(), owned_host.clone());
        backend.start().unwrap();
    }
    assert_eq!(*owned_host.stops.lock().unwrap(), 1);

    let adopted_host = FakeHost::healthy(true);
    {
        let backend = LinuxNativeBackend::with_host(linux_config(), adopted_host.clone());
        backend.start().unwrap();
    }
    assert_eq!(*adopted_host.stops.lock().unwrap(), 0);
}

#[test]
fn system_host_reaps_stale_children_before_reporting_a_restart_running() {
    let host = ferro_desktop::backend::SystemBackendHost::default();
    host.start(&CommandSpec::new("sh").args(["-c", "sleep 1"]))
        .unwrap();
    let transient = CommandSpec::new("sh").args(["-c", "sleep 0.1"]);
    host.start(&transient).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while host.is_running().unwrap() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!host.is_running().unwrap());

    host.start(&transient).unwrap();

    assert!(host.is_running().unwrap());
    host.stop().unwrap();
}

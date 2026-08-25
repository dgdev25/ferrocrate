use ferro_desktop::backend::{
    select_backend_for, Backend, BackendCapabilities, BackendError, BackendHost, BackendState,
    CommandSpec, ExecRequest, ExecResponse, LinuxNativeBackend, LinuxNativeConfig, MacosVmBackend,
    MacosVmConfig, Platform, TerminalRequest, TerminalSession, Transport, TransportRequest,
    TransportResponse, Wsl2Backend, Wsl2Config,
};
use std::io::{Read, Write};
use std::path::PathBuf;
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
    becomes_healthy_on_start: bool,
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
}

impl BackendHost for FakeHost {
    fn start(&self, command: &CommandSpec) -> Result<(), BackendError> {
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
            stdout: b"ok".to_vec(),
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
        distro: "FerrocrateDesktop".into(),
        relay_addr: "127.0.0.1:4288".parse().unwrap(),
        relay_token: "bridge-secret".into(),
    };
    let backend = Wsl2Backend::with_host(config, host.clone());

    assert_eq!(backend.start().unwrap().state, BackendState::Running);
    assert_eq!(
        host.starts.lock().unwrap().as_slice(),
        &[
            CommandSpec::new("wsl.exe").args([
                "-d",
                "FerrocrateDesktop",
                "--",
                "ferrocrate",
                "daemon",
                "--docker-compat",
            ]),
            CommandSpec::new("wsl.exe")
                .args([
                    "-d",
                    "FerrocrateDesktop",
                    "--",
                    "ferrocrate-desktop-relay",
                    "--listen",
                    "127.0.0.1:4288",
                ])
                .env("FERROCRATE_WEB_BRIDGE_TOKEN", "bridge-secret"),
        ]
    );
    assert_eq!(backend.stop().unwrap().state, BackendState::Stopped);
}

#[test]
fn macos_vm_prefers_vfkit_and_stops_the_owned_vm() {
    let host = FakeHost::ready_after_start();
    let config = MacosVmConfig {
        launcher: PathBuf::from("/opt/homebrew/bin/vfkit"),
        vm_config: PathBuf::from("/Users/test/.ferrocrate/vm.json"),
        relay_addr: "127.0.0.1:4288".parse().unwrap(),
        ssh_port: 2222,
        guest_user: "ferrocrate".into(),
        ssh_key: PathBuf::from("/Users/test/.ferrocrate/id_ed25519"),
    };
    let backend = MacosVmBackend::with_host(config, host.clone());

    assert_eq!(backend.start().unwrap().state, BackendState::Running);
    assert_eq!(
        host.starts.lock().unwrap().as_slice(),
        &[
            CommandSpec::new("/opt/homebrew/bin/vfkit")
                .args(["--config", "/Users/test/.ferrocrate/vm.json",]),
            CommandSpec::new("ssh").args([
                "-i",
                "/Users/test/.ferrocrate/id_ed25519",
                "-p",
                "2222",
                "ferrocrate@127.0.0.1",
                "--",
                "ferrocrate-desktop-relay",
                "--listen",
                "127.0.0.1:4288",
            ]),
        ]
    );
    assert_eq!(backend.stop().unwrap().state, BackendState::Stopped);
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
fn wsl2_selection_rejects_an_empty_relay_token() {
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

    assert!(matches!(result, Err(BackendError::Unavailable(reason)) if reason.contains("token")));
}

#[test]
fn proxy_requests_route_through_the_selected_backend_transport() {
    let host = FakeHost::healthy(true);
    let backend = Wsl2Backend::with_host(
        Wsl2Config {
            distro: "FerrocrateDesktop".into(),
            relay_addr: "127.0.0.1:4288".parse().unwrap(),
            relay_token: "bridge-secret".into(),
        },
        host.clone(),
    );
    let request = TransportRequest::new("POST", "/volumes")
        .header("content-type", "application/json")
        .body(br#"{"name":"data"}"#.to_vec());

    let response = backend.request(request.clone()).unwrap();

    assert_eq!(response.status, 201);
    assert_eq!(
        host.requests.lock().unwrap().as_slice(),
        &[(
            Transport::AuthenticatedLoopback {
                addr: "127.0.0.1:4288".parse().unwrap(),
                bearer_token: "bridge-secret".into(),
            },
            request,
        )]
    );
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

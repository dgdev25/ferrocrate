use ferro_desktop::backend::{
    select_backend_for, Backend, BackendCapabilities, BackendError, BackendHost, BackendState,
    CommandSpec, ExecRequest, ExecResponse, LinuxNativeBackend, LinuxNativeConfig, MacosVmBackend,
    MacosVmConfig, Platform, Transport, TransportRequest, TransportResponse, Wsl2Backend,
    Wsl2Config,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct FakeHost {
    running: Mutex<bool>,
    healthy: Mutex<bool>,
    starts: Mutex<Vec<CommandSpec>>,
    stops: Mutex<usize>,
    requests: Mutex<Vec<(Transport, TransportRequest)>>,
}

impl FakeHost {
    fn healthy(value: bool) -> Arc<Self> {
        Arc::new(Self {
            healthy: Mutex::new(value),
            ..Self::default()
        })
    }
}

impl BackendHost for FakeHost {
    fn start(&self, command: &CommandSpec) -> Result<(), BackendError> {
        self.starts.lock().unwrap().push(command.clone());
        *self.running.lock().unwrap() = true;
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
        _command: &CommandSpec,
        _request: &ExecRequest,
    ) -> Result<ExecResponse, BackendError> {
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
}

fn linux_config() -> LinuxNativeConfig {
    LinuxNativeConfig {
        socket_path: PathBuf::from("/run/user/1000/ferrocrate.sock"),
        ferrocrate_binary: PathBuf::from("/opt/ferrocrate/bin/ferrocrate"),
    }
}

#[test]
fn trait_object_dispatches_to_selected_backend() {
    let host = FakeHost::healthy(true);
    let backend: Box<dyn Backend> = select_backend_for(
        Platform::Linux,
        host,
        linux_config(),
        Wsl2Config::default(),
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
            Wsl2Config::default(),
            MacosVmConfig::default(),
        )
        .unwrap();
        assert_eq!(backend.name(), expected);
    }
    assert!(select_backend_for(
        Platform::Unsupported,
        FakeHost::healthy(true),
        linux_config(),
        Wsl2Config::default(),
        MacosVmConfig::default(),
    )
    .is_err());
}

#[test]
fn linux_native_owns_daemon_start_and_stop_transitions() {
    let host = FakeHost::healthy(true);
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
    let host = FakeHost::healthy(true);
    let backend = LinuxNativeBackend::with_host(linux_config(), host.clone());
    backend.start().unwrap();
    *host.running.lock().unwrap() = false;

    let status = backend.status();

    assert_eq!(status.state, BackendState::Running);
    assert!(status.healthy);
    assert_eq!(host.starts.lock().unwrap().len(), 2);
}

#[test]
fn wsl2_uses_a_real_subprocess_lifecycle() {
    let host = FakeHost::healthy(true);
    let config = Wsl2Config {
        distro: "FerrocrateDesktop".into(),
        relay_addr: "127.0.0.1:4288".parse().unwrap(),
        relay_token: "bridge-secret".into(),
    };
    let backend = Wsl2Backend::with_host(config, host.clone());

    assert_eq!(backend.start().unwrap().state, BackendState::Running);
    assert_eq!(
        host.starts.lock().unwrap().as_slice(),
        &[CommandSpec::new("wsl.exe").args([
            "-d",
            "FerrocrateDesktop",
            "--",
            "ferrocrate",
            "daemon",
            "--docker-compat",
        ])]
    );
    assert_eq!(backend.stop().unwrap().state, BackendState::Stopped);
}

#[test]
fn macos_vm_prefers_vfkit_and_stops_the_owned_vm() {
    let host = FakeHost::healthy(true);
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
        &[CommandSpec::new("/opt/homebrew/bin/vfkit")
            .args(["--config", "/Users/test/.ferrocrate/vm.json",])]
    );
    assert_eq!(backend.stop().unwrap().state, BackendState::Stopped);
}

#[test]
fn status_never_reports_an_unhealthy_backend_as_healthy() {
    let host = FakeHost::healthy(false);
    let backend = LinuxNativeBackend::with_host(linux_config(), host);
    let status = backend.start().unwrap();

    assert_eq!(status.state, BackendState::Running);
    assert!(!status.healthy);
    assert_eq!(
        status.reason.as_deref(),
        Some("backend health check failed")
    );
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

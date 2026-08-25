use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ferro_desktop::backend::{select_backend, Backend, DuplexStream, TerminalRequest};
use ferro_web::{CommandDispatcher, CommandRequest, EventHub, Server, StaticAssets};
use rust_embed::RustEmbed;
use serde_json::{json, Value};

#[derive(RustEmbed)]
#[folder = "../apps/ferro-desktop-ui/dist"]
struct DashboardAssets;

impl StaticAssets for DashboardAssets {
    fn get(&self, path: &str) -> Option<(Vec<u8>, &'static str)> {
        let path = Path::new(path);
        if path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return None;
        }
        let path = path.to_str()?;
        let mut bytes = <Self as RustEmbed>::get(path)?.data.into_owned();
        if path == "index.html" {
            let html = String::from_utf8(bytes).ok()?;
            bytes = html
                .replace(
                    "</head>",
                    "<script>window.__FERROCRATE_DASHBOARD__=true</script></head>",
                )
                .into_bytes();
        }
        let mime = match mime_guess::from_path(path)
            .first_or_octet_stream()
            .essence_str()
        {
            "text/html" => "text/html; charset=utf-8",
            "text/css" => "text/css; charset=utf-8",
            "text/javascript" | "application/javascript" => "text/javascript; charset=utf-8",
            "image/svg+xml" => "image/svg+xml",
            "image/png" => "image/png",
            "font/woff2" => "font/woff2",
            _ => "application/octet-stream",
        };
        Some((bytes, mime))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub listen: SocketAddr,
    pub token_file: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub operator_gate: bool,
}

impl Options {
    fn validate(&self) -> Result<(), String> {
        if self.listen.ip().is_loopback() {
            return Ok(());
        }
        if self.tls_cert.is_none() || self.tls_key.is_none() || !self.operator_gate {
            return Err(format!(
                "refusing non-loopback dashboard bind {}; --tls-cert, --tls-key, and --operator-gate are all required",
                self.listen
            ));
        }
        for (label, path) in [
            ("TLS certificate", self.tls_cert.as_deref()),
            ("TLS private key", self.tls_key.as_deref()),
        ] {
            let path = path.expect("validated option");
            if !path.is_file() {
                return Err(format!("{label} does not exist: {}", path.display()));
            }
        }
        Ok(())
    }
}

struct OwnedDaemon {
    child: Option<Child>,
}

impl Drop for OwnedDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn runtime_socket() -> Option<PathBuf> {
    std::env::var_os("FERROCRATE_RUNTIME_DIR")
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR"))
        .map(PathBuf::from)
        .map(|path| path.join("ferrocrate.sock"))
}

fn sibling_binary(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(name)))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

fn ensure_daemon() -> Result<OwnedDaemon, String> {
    let socket = runtime_socket().ok_or_else(|| {
        "FERROCRATE_RUNTIME_DIR or XDG_RUNTIME_DIR is required for the dashboard".to_string()
    })?;
    if socket.exists() {
        return Ok(OwnedDaemon { child: None });
    }
    let mut child = Command::new(sibling_binary("ferro-cli"))
        .arg("daemon")
        .arg("--docker-compat")
        .arg("--socket")
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("failed to start desktop supervisor: {error}"))?;
    for _ in 0..100 {
        if runtime_socket().is_some_and(|path| path.exists()) {
            return Ok(OwnedDaemon { child: Some(child) });
        }
        if child
            .try_wait()
            .map_err(|error| format!("failed to inspect desktop supervisor: {error}"))?
            .is_some()
        {
            return Err("desktop supervisor exited before its socket became ready".to_string());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("desktop supervisor did not make its socket ready".to_string())
}

fn write_token(path: &Path, token: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("failed to create token file {}: {error}", path.display()))?;
    writeln!(file, "{token}")
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to persist token file {}: {error}", path.display()))
}

fn command_result(output: Output) -> Value {
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    json!({
        "ok": output.status.success(),
        "code": output.status.code().unwrap_or(1),
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": stderr,
        "message": stderr.lines().find(|line| !line.trim().is_empty()).unwrap_or("").trim(),
    })
}

fn desktop_command(args: &[String], stdin: Option<&[u8]>) -> Result<Output, String> {
    let mut command = Command::new(sibling_binary("ferro-cli"));
    command.args(args);
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to run desktop command: {error}"))?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| "desktop command stdin unavailable".to_string())?
            .write_all(input)
            .map_err(|error| format!("failed to write desktop command input: {error}"))?;
    }
    child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for desktop command: {error}"))
}

fn run_command_result(args: &[&str]) -> Result<Value, String> {
    let args = args
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    desktop_command(&args, None).map(command_result)
}

fn run_json(args: &[&str]) -> Result<Value, String> {
    let result = run_command_result(args)?;
    if !result["ok"].as_bool().unwrap_or(false) {
        return Err(result["message"]
            .as_str()
            .unwrap_or("dashboard command failed")
            .to_string());
    }
    serde_json::from_str(result["stdout"].as_str().unwrap_or(""))
        .map_err(|error| format!("dashboard command returned invalid JSON: {error}"))
}

struct TerminalState {
    stream: Box<dyn DuplexStream>,
    exec_id: String,
}

#[derive(Clone)]
struct ProcessDispatcher {
    log_process: Arc<Mutex<Option<Child>>>,
    terminal: Arc<Mutex<Option<TerminalState>>>,
    backend: Arc<dyn Backend>,
}

impl ProcessDispatcher {
    fn new() -> Result<Self, String> {
        Ok(Self {
            log_process: Arc::new(Mutex::new(None)),
            terminal: Arc::new(Mutex::new(None)),
            backend: Arc::from(select_backend().map_err(|error| error.to_string())?),
        })
    }

    fn snapshot(&self) -> Result<Value, String> {
        let socket = runtime_socket()
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let containers = run_command_result(&["containers", "--all", "--format", "json"])?;
        let images = run_command_result(&["images", "--format", "json"])?;
        Ok(json!({
            "daemon": {
                "state": "running", "healthy": true, "socket_path": socket,
                "reason": null, "platform": "linux-native", "custom_networks": false
            },
            "runtime": { "ok": true, "code": 0, "stdout": socket, "stderr": "", "message": "" },
            "containers": containers,
            "images": images
        }))
    }

    fn start_log_follow(&self, target: String, events: EventHub) -> Result<Value, String> {
        if target.trim().is_empty() {
            return Err("target container is required".to_string());
        }
        let mut slot = self
            .log_process
            .lock()
            .map_err(|_| "log follow state is unavailable".to_string())?;
        if slot.is_some() {
            return Err("a container log stream is already active".to_string());
        }
        let mut child = Command::new(sibling_binary("ferro-cli"))
            .arg("logs")
            .arg(target)
            .args(["--follow", "--format", "text"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("failed to start container log stream: {error}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "container log stream stdout unavailable".to_string())?;
        thread::spawn(move || {
            let mut text = String::new();
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                text.push_str(&line);
                text.push('\n');
                events.emit(
                    "container-log-batch",
                    json!({ "text": text, "truncated": false }),
                );
            }
            events.emit("container-log-ended", true);
        });
        *slot = Some(child);
        Ok(Value::Null)
    }

    fn stop_log_follow(&self) -> Result<Value, String> {
        if let Some(mut child) = self
            .log_process
            .lock()
            .map_err(|_| "log follow state is unavailable".to_string())?
            .take()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(Value::Null)
    }

    fn start_terminal(
        &self,
        args: ferro_web::TerminalArgs,
        events: EventHub,
    ) -> Result<Value, String> {
        if args.target.trim().is_empty() {
            return Err("target container is required".to_string());
        }
        if args.shell.trim().is_empty() {
            return Err("shell command is required".to_string());
        }
        let mut slot = self
            .terminal
            .lock()
            .map_err(|_| "terminal state is unavailable".to_string())?;
        if slot.is_some() {
            return Err("an exec terminal is already active".to_string());
        }
        let session = self
            .backend
            .open_terminal(TerminalRequest {
                container: args.target,
                command: vec![args.shell],
                env: args.env,
                user: args.user,
                workdir: args.workdir,
            })
            .map_err(|error| error.to_string())?;
        let mut output = session
            .stream
            .try_clone_stream()
            .map_err(|error| error.to_string())?;
        *slot = Some(TerminalState {
            stream: session.stream,
            exec_id: session.exec_id,
        });
        thread::spawn(move || {
            let mut buffer = [0_u8; 8192];
            loop {
                match output.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(bytes) => events.emit(
                        "terminal-output",
                        json!({ "data": &buffer[..bytes], "stderr": false }),
                    ),
                    Err(error) => {
                        events.emit("terminal-error", error.to_string());
                        break;
                    }
                }
            }
            events.emit("terminal-ended", true);
        });
        Ok(Value::Null)
    }

    fn write_terminal(&self, data: Vec<u8>) -> Result<Value, String> {
        if data.len() > 64 * 1024 {
            return Err("terminal input exceeds 64 KiB".to_string());
        }
        let mut slot = self
            .terminal
            .lock()
            .map_err(|_| "terminal state is unavailable".to_string())?;
        let terminal = slot
            .as_mut()
            .ok_or_else(|| "no exec terminal is active".to_string())?;
        terminal
            .stream
            .write_all(&data)
            .and_then(|()| terminal.stream.flush())
            .map_err(|error| format!("failed to write terminal input: {error}"))?;
        Ok(Value::Null)
    }

    fn resize_terminal(&self, columns: u16, rows: u16) -> Result<Value, String> {
        if columns == 0 || rows == 0 {
            return Err("terminal dimensions must be non-zero".to_string());
        }
        let exec_id = self
            .terminal
            .lock()
            .map_err(|_| "terminal state is unavailable".to_string())?
            .as_ref()
            .map(|terminal| terminal.exec_id.clone())
            .ok_or_else(|| "no exec terminal is active".to_string())?;
        self.backend
            .resize_terminal(&exec_id, columns, rows)
            .map_err(|error| error.to_string())?;
        Ok(Value::Null)
    }

    fn close_terminal(&self) -> Result<Value, String> {
        if let Some(terminal) = self
            .terminal
            .lock()
            .map_err(|_| "terminal state is unavailable".to_string())?
            .take()
        {
            terminal
                .stream
                .shutdown_write()
                .map_err(|error| error.to_string())?;
        }
        Ok(Value::Null)
    }
}

fn value_string(value: &Value) -> Result<&str, String> {
    value
        .as_str()
        .ok_or_else(|| "invalid command action".to_string())
}

impl CommandDispatcher for ProcessDispatcher {
    fn dispatch(&self, request: CommandRequest, events: EventHub) -> Result<Value, String> {
        match request {
            CommandRequest::GetDesktopSnapshot => self.snapshot(),
            CommandRequest::GetContainerStats(args) => {
                let mut samples = Vec::new();
                for id in args.ids {
                    let value = run_json(&["stats", &id, "--format", "json"]).ok();
                    samples.push(json!({
                        "id": id,
                        "available": value.is_some(),
                        "memory_usage": value.as_ref().and_then(|item| item.pointer("/memory_stats/usage")).and_then(Value::as_u64),
                        "memory_limit": value.as_ref().and_then(|item| item.pointer("/memory_stats/limit")).and_then(Value::as_u64),
                        "cpu_percent": null
                    }));
                }
                Ok(json!({ "samples": samples }))
            }
            CommandRequest::GetVolumes => run_json(&["volume", "ls", "--format", "json"]),
            CommandRequest::GetNetworks => run_json(&["network", "ls", "--format", "json"]),
            CommandRequest::GetContainerDetail(args) => {
                run_json(&["inspect", &args.target, "--format", "json"])
            }
            CommandRequest::GetComposeSnapshot(args) => {
                let config = run_command_result(&["compose", "-f", &args.file, "config"])?;
                Ok(json!({ "config": config["stdout"], "services": [] }))
            }
            CommandRequest::BuildImage(args) => {
                run_command_result(&["build", &args.context, "--tag", &args.tag])
            }
            CommandRequest::RunDesktopAction(args) => {
                let target = args.target.unwrap_or_default();
                let command = match value_string(&args.action)? {
                    "pull_image" => vec!["pull", &target],
                    "remove_image" => vec!["rmi", &target],
                    "start_container" => vec!["start", &target],
                    "stop_container" => vec!["stop", &target],
                    "remove_container" => vec!["rm", &target],
                    "container_prune" => vec!["container-prune"],
                    "image_prune" => vec!["image-prune"],
                    "vm_start" => {
                        return Ok(
                            json!({ "ok": true, "code": 0, "stdout": "", "stderr": "", "message": "" }),
                        )
                    }
                    "vm_stop" => {
                        return Err(
                            "the dashboard cannot stop the daemon that serves it".to_string()
                        )
                    }
                    action => return Err(format!("unsupported desktop action: {action}")),
                };
                run_command_result(&command)
            }
            CommandRequest::RunComposeAction(args) => {
                let action = value_string(&args.action)?;
                run_command_result(&["compose", "-f", &args.file, action])
            }
            CommandRequest::RunVolumeAction(args) => {
                let target = args.target.unwrap_or_default();
                let action = value_string(&args.action)?;
                let command = match action {
                    "create" => vec!["volume", "create", &target],
                    "remove" => vec!["volume", "rm", &target],
                    "prune" => vec!["volume", "prune"],
                    _ => return Err(format!("unsupported volume action: {action}")),
                };
                run_command_result(&command)
            }
            CommandRequest::RunNetworkAction(args) => {
                let target = args.target.unwrap_or_default();
                let action = value_string(&args.action)?;
                let public_action = if action == "remove" { "rm" } else { action };
                let mut values = vec!["network", public_action, &target];
                let subnet = args.subnet.unwrap_or_default();
                if action == "create" && !subnet.is_empty() {
                    values.extend(["--subnet", &subnet]);
                }
                run_command_result(&values)
            }
            CommandRequest::UpdateContainerResources(args) => {
                let mut values = vec!["update".to_string(), args.target];
                for (flag, value) in [
                    ("--memory", args.memory),
                    ("--cpu-quota", args.cpu_quota),
                    ("--cpu-period", args.cpu_period),
                ] {
                    if let Some(value) = value {
                        values.extend([flag.to_string(), value.to_string()]);
                    }
                }
                desktop_command(&values, None).map(command_result)
            }
            CommandRequest::RunNewContainer(args) => {
                let mut values = vec!["run".to_string(), "--detach".to_string()];
                if let Some(name) = args.name {
                    values.extend(["--name".to_string(), name]);
                }
                for port in args.ports {
                    values.extend(["--publish".to_string(), port]);
                }
                for volume in args.volumes {
                    values.extend(["--volume".to_string(), volume]);
                }
                for env in args.environment {
                    values.extend(["--env".to_string(), env]);
                }
                if let Some(memory) = args.memory {
                    values.extend(["--memory-max".to_string(), memory.to_string()]);
                }
                if let Some(quota) = args.cpu_quota {
                    values.extend(["--cpu-quota".to_string(), quota.to_string()]);
                }
                if let Some(period) = args.cpu_period {
                    values.extend(["--cpu-period".to_string(), period.to_string()]);
                }
                values.push(args.image);
                values.extend(args.command);
                desktop_command(&values, None).map(command_result)
            }
            CommandRequest::GetRegistryAuthStatus(args) => {
                Ok(json!({ "registry": args.registry, "logged_in": false, "username": null }))
            }
            CommandRequest::LoginRegistry(args) => {
                let values = vec![
                    "login".to_string(),
                    args.registry,
                    "--username".to_string(),
                    args.username,
                    "--password-stdin".to_string(),
                ];
                desktop_command(&values, Some(args.password.as_bytes())).map(command_result)
            }
            CommandRequest::LogoutRegistry(args) => run_command_result(&["logout", &args.registry]),
            CommandRequest::StartLogFollow { target } => self.start_log_follow(target, events),
            CommandRequest::StopLogFollow => self.stop_log_follow(),
            CommandRequest::StartTerminal(args) => self.start_terminal(args, events),
            CommandRequest::WriteTerminal(args) => self.write_terminal(args.data),
            CommandRequest::ResizeTerminal(args) => self.resize_terminal(args.columns, args.rows),
            CommandRequest::CloseTerminal => self.close_terminal(),
            CommandRequest::GetPaidAuthState => Ok(
                json!({ "config": null, "session": { "token_present": false, "subject": null, "plan": null, "expires_at": null, "expired": null }, "entitlement": null }),
            ),
            CommandRequest::SavePaidBackendConfig(_)
            | CommandRequest::SetPaidSessionToken(_)
            | CommandRequest::AcquirePaidSession(_)
            | CommandRequest::ClearPaidSession
            | CommandRequest::RunPaidFullStackInstall(_) => {
                Err("paid account settings are managed by the native desktop".to_string())
            }
            CommandRequest::RunDoctorAction(args) => {
                let mut values = vec!["doctor".to_string(), "--json".to_string()];
                if args.fix {
                    values.push("--fix".to_string());
                }
                if args.bootstrap {
                    values.push("--bootstrap".to_string());
                }
                if args.dry_run {
                    values.push("--dry-run".to_string());
                }
                if args.confirm {
                    values.push("--confirm".to_string());
                }
                let output = desktop_command(&values, None)?;
                let ok = output.status.success();
                let mut raw: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(
                    |error| json!({ "healthy": false, "checks": [], "error": error.to_string() }),
                );
                if let Some(object) = raw.as_object_mut() {
                    object.insert("surface".to_string(), json!("dashboard"));
                    object.entry("checks".to_string()).or_insert_with(|| json!([])).as_array_mut().map(|checks| checks.push(json!({ "id": "dashboard_surface", "ok": true, "message": "dashboard browser surface is active", "hint": "Bearer-authenticated loopback session", "remediated": false, "action": null })));
                }
                Ok(json!({ "ok": ok && raw["healthy"].as_bool().unwrap_or(false), "raw": raw }))
            }
        }
    }
}

pub(crate) fn run(options: Options) -> Result<(), String> {
    options.validate()?;
    let _daemon = ensure_daemon()?;
    let token = ferro_web::generate_session_token()?;
    if let Some(path) = options.token_file.as_deref() {
        write_token(path, &token)?;
    }
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("failed to create dashboard runtime: {error}"))?;
    runtime.block_on(async move {
        let assets = Arc::new(DashboardAssets);
        let dispatcher = Arc::new(ProcessDispatcher::new()?);
        if options.listen.ip().is_loopback() {
            let server =
                Server::spawn_loopback(options.listen, token.clone(), assets, dispatcher).await?;
            println!("dashboard ready at http://{}/#token={token}", server.addr());
            server.wait().await
        } else {
            let cert = options.tls_cert.as_deref().expect("validated TLS cert");
            let key = options.tls_key.as_deref().expect("validated TLS key");
            println!(
                "dashboard ready at https://{}/#token={token}",
                options.listen
            );
            ferro_web::serve_tls(options.listen, token, cert, key, assets, dispatcher).await
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_loopback_requires_tls_and_operator_gate() {
        let options = Options {
            listen: "0.0.0.0:4190".parse().unwrap(),
            token_file: None,
            tls_cert: None,
            tls_key: None,
            operator_gate: false,
        };
        let error = options.validate().expect_err("unsafe bind rejected");
        assert!(error.contains("--tls-cert"));
        assert!(error.contains("--operator-gate"));
    }

    #[test]
    fn embedded_dashboard_contains_the_forge_shell() {
        let (_, mime) = DashboardAssets.get("index.html").expect("embedded index");
        assert!(mime.starts_with("text/html"));
        assert!(<DashboardAssets as RustEmbed>::iter()
            .any(|path| path.starts_with("assets/index-") && path.ends_with(".js")));
    }
}

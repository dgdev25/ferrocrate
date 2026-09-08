#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use clap::{Args, Parser, Subcommand};
use ferro_core::entitlements::{self, Feature};
use ferro_desktop::backend::{
    select_backend, Backend, ExecRequest as BackendExecRequest, LinuxNativeBackend,
    LinuxNativeConfig, Platform, TerminalRequest, TransportRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use thiserror::Error;

const MAX_REQUEST_BYTES: usize = 64 * 1024;

fn desktop_addr_default_from(value: Option<std::ffi::OsString>) -> String {
    value
        .and_then(|address| address.into_string().ok())
        .filter(|address| !address.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1:4288".to_string())
}

fn desktop_addr_default() -> String {
    desktop_addr_default_from(std::env::var_os("FERROCRATE_DESKTOP_ADDR"))
}

#[derive(Debug, Parser)]
#[command(
    name = "ferro-desktop",
    version,
    about = "FerroCrate desktop daemon/proxy"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Probe TCP ports on this runtime host; suggestions are not reservations.
    PortProbe {
        #[arg(long, value_delimiter = ',')]
        ports: Vec<u16>,
        #[arg(long, value_delimiter = ',')]
        exclude: Vec<u16>,
    },
    Daemon {
        #[arg(long, default_value_t = desktop_addr_default())]
        addr: String,
        #[arg(long)]
        pipe_name: Option<String>,
        #[arg(long)]
        wsl_distro: Option<String>,
        #[arg(long, default_value_t = false)]
        allow_remote: bool,
    },
    Exec {
        #[arg(long, default_value_t = desktop_addr_default())]
        addr: String,
        #[arg(long)]
        pipe_name: Option<String>,
        #[arg(long)]
        wsl: bool,
        #[arg(long)]
        wsl_distro: Option<String>,
        #[arg(long, default_value_t = false)]
        follow: bool,
        /// Relay stdin and streamed output for an interactive container exec.
        #[arg(long, default_value_t = false)]
        interactive: bool,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    #[command(hide = true)]
    TerminalProxy {
        #[arg(long)]
        socket: Option<String>,
        #[arg(long)]
        container: String,
        #[arg(long = "env")]
        env: Vec<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        workdir: Option<String>,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    #[command(hide = true)]
    TerminalResize {
        #[arg(long)]
        socket: Option<String>,
        #[arg(long)]
        exec_id: String,
        #[arg(long)]
        columns: u16,
        #[arg(long)]
        rows: u16,
    },
    #[command(hide = true)]
    VolumeProxy {
        #[arg(long)]
        socket: Option<String>,
        #[command(subcommand)]
        command: VolumeProxyCommands,
    },
    #[command(hide = true)]
    NetworkProxy {
        #[arg(long)]
        socket: Option<String>,
        #[command(subcommand)]
        command: NetworkProxyCommands,
    },
    #[command(hide = true)]
    ContainerProxy {
        #[arg(long)]
        socket: Option<String>,
        #[command(subcommand)]
        command: ContainerProxyCommands,
    },
    #[command(hide = true)]
    RegistryProxy {
        #[arg(long)]
        socket: Option<String>,
        #[command(subcommand)]
        command: RegistryProxyCommands,
    },
    Doctor {
        #[arg(long)]
        wsl_distro: Option<String>,
    },
    /// Exercise the selected desktop backend's lifecycle and API transport.
    BackendSmoke {
        /// Start the selected backend before checking its status and transport.
        #[arg(long, default_value_t = false)]
        start: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Phase0Check {
        #[arg(long)]
        wsl_distro: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Forward {
        #[arg(long)]
        state_file: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
        #[command(subcommand)]
        command: ForwardCommands,
    },
    Vm {
        #[arg(long)]
        state_file: Option<String>,
        #[command(subcommand)]
        command: Box<VmCommands>,
    },
    Autostart {
        #[command(subcommand)]
        command: AutostartCommands,
    },
}

#[derive(Debug, Subcommand)]
enum VolumeProxyCommands {
    List,
    Create { name: String },
    Remove { name: String },
    Prune,
}

#[derive(Debug, Subcommand)]
enum NetworkProxyCommands {
    List,
    Inspect {
        name: String,
    },
    Create {
        name: String,
        #[arg(long)]
        subnet: Option<String>,
    },
    Remove {
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum ContainerProxyCommands {
    Inspect {
        container: String,
    },
    Update {
        container: String,
        #[arg(long)]
        memory: Option<u64>,
        #[arg(long)]
        cpu_quota: Option<u64>,
        #[arg(long)]
        cpu_period: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
enum RegistryProxyCommands {
    Login {
        #[arg(long)]
        registry: String,
        #[arg(long)]
        username: String,
    },
}

#[derive(Debug, Subcommand)]
enum ForwardCommands {
    Add {
        #[arg(long, default_value = "127.0.0.1")]
        bind_addr: String,
        #[arg(long)]
        listen_port: u16,
        #[arg(long, default_value = "127.0.0.1")]
        target_host: String,
        #[arg(long)]
        target_port: u16,
    },
    Remove {
        #[arg(long, default_value = "127.0.0.1")]
        bind_addr: String,
        #[arg(long)]
        listen_port: u16,
    },
    List,
    Run,
}

fn default_vm_backend() -> String {
    if cfg!(target_arch = "aarch64") {
        "qemu-hvf".to_string()
    } else {
        "qemu-x86_64".to_string()
    }
}

fn default_fs_backend() -> String {
    if Command::new("virtiofsd").arg("--version").output().is_ok() {
        "virtiofs".to_string()
    } else {
        "9p".to_string()
    }
}

#[derive(Debug, Args)]
struct VmInitArgs {
    #[arg(long, default_value_t = default_vm_backend())]
    backend: String,
    #[arg(long, default_value = "FerroCrateDesktopVM")]
    vm_name: String,
    #[arg(long, default_value_t = 2)]
    cpus: u8,
    #[arg(long, default_value_t = 4096)]
    memory_mb: u32,
    #[arg(long)]
    disk_path: Option<String>,
    #[arg(long)]
    host_share_path: Option<String>,
    #[arg(long, default_value_t = default_fs_backend())]
    fs_backend: String,
    #[arg(long)]
    virtiofs_socket_path: Option<String>,
    #[arg(long)]
    hyperv_switch: Option<String>,
    #[arg(long, default_value_t = 2222)]
    ssh_port: u16,
    #[arg(long, default_value_t = 4288)]
    api_port: u16,
    #[arg(long)]
    guest_user: Option<String>,
    #[arg(long)]
    ssh_private_key_path: Option<String>,
    #[arg(long)]
    cloud_init_image_path: Option<String>,
    #[arg(long)]
    vfkit_kernel_path: Option<String>,
    #[arg(long)]
    vfkit_initrd_path: Option<String>,
    #[arg(long, default_value = "5a:94:ef:e4:0c:ee")]
    vfkit_mac: String,
}

#[derive(Debug, Subcommand)]
enum VmCommands {
    Init(Box<VmInitArgs>),
    Start {
        #[arg(long, default_value_t = false)]
        foreground: bool,
        #[arg(long)]
        forward_state_file: Option<String>,
    },
    Stop,
    Status {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    BridgeApi {
        #[arg(long, default_value = "127.0.0.1")]
        bind_addr: String,
        #[arg(long, default_value_t = 4288)]
        listen_port: u16,
        #[arg(long)]
        forward_state_file: Option<String>,
    },
    UpdateCheck {
        #[arg(long)]
        manifest_path: String,
        #[arg(long, default_value = "stable")]
        channel: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    ApplyChannelUpdate {
        #[arg(long)]
        manifest_path: String,
        #[arg(long, default_value = "stable")]
        channel: String,
        #[arg(long, default_value_t = false)]
        no_backup: bool,
    },
    RollbackImage,
    UpdateImage {
        #[arg(long)]
        image_path: String,
        #[arg(long, default_value_t = false)]
        no_backup: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AutostartCommands {
    InstallMacos {
        #[arg(long)]
        output_path: Option<String>,
        #[arg(long, default_value = "127.0.0.1:4288")]
        addr: String,
    },
    InstallWindows {
        #[arg(long)]
        output_path: Option<String>,
        #[arg(long, default_value = "127.0.0.1:4288")]
        addr: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecRequest {
    cmd: Vec<String>,
    use_wsl: bool,
    wsl_distro: Option<String>,
    #[serde(default)]
    follow: bool,
    #[serde(default)]
    interactive: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecResponse {
    status: i32,
    stdout: String,
    stderr: String,
}

fn percent_encode_terminal_path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
fn terminal_exec_create_path(container: &str) -> String {
    format!(
        "/containers/{}/exec",
        percent_encode_terminal_path_component(container)
    )
}

#[cfg(test)]
fn terminal_resize_path(exec_id: &str, columns: u16, rows: u16) -> String {
    format!(
        "/exec/{}/resize?w={columns}&h={rows}",
        percent_encode_terminal_path_component(exec_id)
    )
}

#[cfg(test)]
fn terminal_exec_create_payload(
    cmd: &[String],
    env: &[String],
    user: Option<&str>,
    workdir: Option<&str>,
) -> Result<Vec<u8>, DesktopError> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "Cmd": cmd,
        "AttachStdin": true,
        "AttachStdout": true,
        "AttachStderr": true,
        "Tty": true,
        "Env": env,
        "User": user,
        "WorkingDir": workdir,
    }))?)
}

#[cfg(all(test, target_os = "linux"))]
fn terminal_http_request(
    socket: &Path,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), DesktopError> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket)?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: ferrocrate-desktop\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| DesktopError::Invalid("daemon returned malformed HTTP".to_string()))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| DesktopError::Invalid("daemon returned non-UTF-8 headers".to_string()))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| DesktopError::Invalid("daemon returned invalid HTTP status".to_string()))?;
    Ok((status, response[header_end + 4..].to_vec()))
}

fn terminal_daemon_error(status: u16, body: &[u8]) -> DesktopError {
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("message")?.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_string());
    DesktopError::Invalid(format!("daemon returned HTTP {status}: {message}"))
}

#[cfg(all(test, target_os = "linux"))]
fn create_terminal_exec(
    socket: &Path,
    container: &str,
    cmd: &[String],
    env: &[String],
    user: Option<&str>,
    workdir: Option<&str>,
) -> Result<String, DesktopError> {
    if container.trim().is_empty() {
        return Err(DesktopError::Invalid(
            "terminal container is required".to_string(),
        ));
    }
    if cmd.is_empty() {
        return Err(DesktopError::Invalid(
            "terminal command is required".to_string(),
        ));
    }
    let body = terminal_exec_create_payload(cmd, env, user, workdir)?;
    let (status, response) =
        terminal_http_request(socket, "POST", &terminal_exec_create_path(container), &body)?;
    if !(200..300).contains(&status) {
        return Err(terminal_daemon_error(status, &response));
    }
    let response: serde_json::Value = serde_json::from_slice(&response)?;
    response
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| DesktopError::Invalid("daemon exec create omitted Id".to_string()))
}

#[cfg(all(test, target_os = "linux"))]
fn read_terminal_http_headers(
    stream: &mut std::os::unix::net::UnixStream,
) -> Result<(u16, Vec<u8>), DesktopError> {
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        headers.push(byte[0]);
        if headers.len() > MAX_REQUEST_BYTES {
            return Err(DesktopError::Invalid(
                "daemon response headers are too large".to_string(),
            ));
        }
    }
    let text = std::str::from_utf8(&headers)
        .map_err(|_| DesktopError::Invalid("daemon returned non-UTF-8 headers".to_string()))?;
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| DesktopError::Invalid("daemon returned invalid HTTP status".to_string()))?;
    Ok((status, headers))
}

#[cfg(all(test, target_os = "linux"))]
fn open_terminal_exec(
    socket: &Path,
    exec_id: &str,
) -> Result<std::os::unix::net::UnixStream, DesktopError> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket)?;
    let body = serde_json::to_vec(&serde_json::json!({"Detach": false, "Tty": true}))?;
    let path = format!(
        "/exec/{}/start",
        percent_encode_terminal_path_component(exec_id)
    );
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: ferrocrate-desktop\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(&body)?;
    let (status, _) = read_terminal_http_headers(&mut stream)?;
    if status != 101 {
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        return Err(terminal_daemon_error(status, &response));
    }
    Ok(stream)
}

#[cfg(all(test, target_os = "linux"))]
fn resize_terminal_exec(
    socket: &Path,
    exec_id: &str,
    columns: u16,
    rows: u16,
) -> Result<(), DesktopError> {
    let (status, response) = terminal_http_request(
        socket,
        "POST",
        &terminal_resize_path(exec_id, columns, rows),
        &[],
    )?;
    if !(200..300).contains(&status) {
        return Err(terminal_daemon_error(status, &response));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
fn ferrocrate_socket_candidates(
    explicit: Option<&str>,
    rootless_socket: Option<&str>,
    runtime_dir: Option<PathBuf>,
    xdg_runtime_dir: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = explicit {
        candidates.push(PathBuf::from(path));
    } else {
        if let Some(path) = rootless_socket {
            candidates.push(PathBuf::from(path));
        }
        if let Some(runtime) = runtime_dir {
            candidates.push(runtime.join("ferrocrate.sock"));
        }
        if let Some(runtime) = xdg_runtime_dir {
            candidates.push(runtime.join("ferrocrate.sock"));
        }
    }
    candidates.dedup();
    candidates
}

#[cfg(all(test, target_os = "linux"))]
fn select_terminal_socket(explicit: Option<&str>) -> Result<PathBuf, DesktopError> {
    use std::os::unix::fs::FileTypeExt;

    let candidates = ferrocrate_socket_candidates(
        explicit,
        std::env::var("FERROCRATE_ROOTLESS_SOCKET").ok().as_deref(),
        std::env::var_os("FERROCRATE_RUNTIME_DIR").map(PathBuf::from),
        std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
    );

    let mut rejected = Vec::new();
    for path in candidates {
        if !path.is_absolute() {
            rejected.push(format!("{} (not absolute)", path.display()));
            continue;
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_socket() => return Ok(path),
            Ok(_) => rejected.push(format!("{} (not a Unix socket)", path.display())),
            Err(_) => rejected.push(format!("{} (missing)", path.display())),
        }
    }
    Err(DesktopError::Invalid(format!(
        "Ferrocrate daemon socket not found; probed {}",
        if rejected.is_empty() {
            "no configured rootless runtime directory".to_string()
        } else {
            rejected.join(", ")
        }
    )))
}

#[cfg(test)]
fn ferrocrate_daemon_command(socket: &Path) -> Vec<String> {
    vec![
        "daemon".to_string(),
        "--socket".to_string(),
        socket.display().to_string(),
        "--docker-compat".to_string(),
    ]
}

#[cfg(test)]
fn daemon_health_response_ok(response: &str) -> bool {
    let Some((headers, body)) = response.split_once("\r\n\r\n") else {
        return false;
    };
    headers.starts_with("HTTP/1.1 200") && body.trim() == "OK"
}

fn run_terminal_proxy(
    socket: Option<&str>,
    container: &str,
    cmd: &[String],
    env: &[String],
    user: Option<&str>,
    workdir: Option<&str>,
) -> Result<(), DesktopError> {
    let backend = selected_proxy_backend(socket)?;
    let mut session = backend
        .open_terminal(TerminalRequest {
            container: container.to_string(),
            command: cmd.to_vec(),
            env: env.to_vec(),
            user: user.map(str::to_owned),
            workdir: workdir.map(str::to_owned),
        })
        .map_err(|error| DesktopError::Invalid(error.to_string()))?;
    eprintln!("FERROCRATE_EXEC_ID={}", session.exec_id);
    std::io::stderr().flush()?;

    let mut input_stream = session
        .stream
        .try_clone_stream()
        .map_err(|error| DesktopError::Invalid(error.to_string()))?;
    thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        let _ = std::io::copy(&mut input, &mut input_stream);
        let _ = input_stream.shutdown_write();
    });
    let mut output = std::io::stdout().lock();
    std::io::copy(&mut session.stream, &mut output)?;
    output.flush()?;
    Ok(())
}

fn run_terminal_resize(
    socket: Option<&str>,
    exec_id: &str,
    columns: u16,
    rows: u16,
) -> Result<(), DesktopError> {
    if columns == 0 || rows == 0 {
        return Err(DesktopError::Invalid(
            "terminal dimensions must be non-zero".to_string(),
        ));
    }
    selected_proxy_backend(socket)?
        .resize_terminal(exec_id, columns, rows)
        .map_err(|error| DesktopError::Invalid(error.to_string()))
}

fn volume_proxy_request(
    command: &VolumeProxyCommands,
) -> Result<(&'static str, String, Vec<u8>), DesktopError> {
    match command {
        VolumeProxyCommands::List => Ok(("GET", "/volumes".to_string(), Vec::new())),
        VolumeProxyCommands::Create { name } => {
            if name.trim().is_empty() {
                return Err(DesktopError::Invalid("volume name is required".to_string()));
            }
            let body = serde_json::to_vec(&serde_json::json!({
                "Name": name,
                "Driver": "local",
            }))?;
            Ok(("POST", "/volumes/create".to_string(), body))
        }
        VolumeProxyCommands::Remove { name } => {
            if name.trim().is_empty() {
                return Err(DesktopError::Invalid("volume name is required".to_string()));
            }
            Ok((
                "DELETE",
                format!("/volumes/{}", percent_encode_terminal_path_component(name)),
                Vec::new(),
            ))
        }
        VolumeProxyCommands::Prune => Ok(("POST", "/volumes/prune".to_string(), Vec::new())),
    }
}

fn run_volume_proxy(
    socket: Option<&str>,
    command: VolumeProxyCommands,
) -> Result<(), DesktopError> {
    let (method, path, body) = volume_proxy_request(&command)?;
    run_backend_request(socket, method, path, body)
}

fn required_network_name(name: &str) -> Result<&str, DesktopError> {
    if name.trim().is_empty() {
        Err(DesktopError::Invalid(
            "network name is required".to_string(),
        ))
    } else {
        Ok(name.trim())
    }
}

fn network_proxy_request(
    command: &NetworkProxyCommands,
) -> Result<(&'static str, String, Vec<u8>), DesktopError> {
    match command {
        NetworkProxyCommands::List => Ok(("GET", "/networks".to_string(), Vec::new())),
        NetworkProxyCommands::Inspect { name } => Ok((
            "GET",
            format!(
                "/networks/{}",
                percent_encode_terminal_path_component(required_network_name(name)?)
            ),
            Vec::new(),
        )),
        NetworkProxyCommands::Create { name, subnet } => {
            let name = required_network_name(name)?;
            let mut payload = serde_json::json!({"Name": name, "Driver": "bridge"});
            if let Some(subnet) = subnet
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                payload["IPAM"] = serde_json::json!({"Config": [{"Subnet": subnet}]});
            }
            Ok((
                "POST",
                "/networks/create".to_string(),
                serde_json::to_vec(&payload)?,
            ))
        }
        NetworkProxyCommands::Remove { name } => Ok((
            "DELETE",
            format!(
                "/networks/{}",
                percent_encode_terminal_path_component(required_network_name(name)?)
            ),
            Vec::new(),
        )),
    }
}

fn run_network_proxy(
    socket: Option<&str>,
    command: NetworkProxyCommands,
) -> Result<(), DesktopError> {
    let (method, path, body) = network_proxy_request(&command)?;
    run_backend_request(socket, method, path, body)
}

fn container_proxy_request(
    command: &ContainerProxyCommands,
) -> Result<(&'static str, String, Vec<u8>), DesktopError> {
    match command {
        ContainerProxyCommands::Inspect { container } => {
            let container = required_network_name(container)
                .map_err(|_| DesktopError::Invalid("container is required".to_string()))?;
            Ok((
                "GET",
                format!(
                    "/containers/{}/json",
                    percent_encode_terminal_path_component(container)
                ),
                Vec::new(),
            ))
        }
        ContainerProxyCommands::Update {
            container,
            memory,
            cpu_quota,
            cpu_period,
        } => {
            let container = required_network_name(container)
                .map_err(|_| DesktopError::Invalid("container is required".to_string()))?;
            if memory.is_none() && cpu_quota.is_none() && cpu_period.is_none() {
                return Err(DesktopError::Invalid(
                    "at least one resource limit is required".to_string(),
                ));
            }
            let mut payload = serde_json::Map::new();
            if let Some(value) = memory {
                payload.insert("Memory".to_string(), serde_json::json!(value));
            }
            if let Some(value) = cpu_quota {
                payload.insert("CpuQuota".to_string(), serde_json::json!(value));
            }
            if let Some(value) = cpu_period {
                payload.insert("CpuPeriod".to_string(), serde_json::json!(value));
            }
            Ok((
                "POST",
                format!(
                    "/containers/{}/update",
                    percent_encode_terminal_path_component(container)
                ),
                serde_json::to_vec(&payload)?,
            ))
        }
    }
}

fn run_container_proxy(
    socket: Option<&str>,
    command: ContainerProxyCommands,
) -> Result<(), DesktopError> {
    let (method, path, body) = container_proxy_request(&command)?;
    run_backend_request(socket, method, path, body)
}

fn registry_login_request(
    registry: &str,
    username: &str,
    password: &str,
) -> Result<(&'static str, String, Vec<u8>), DesktopError> {
    let registry = registry.trim();
    let username = username.trim();
    if registry.is_empty() {
        return Err(DesktopError::Invalid("registry is required".to_string()));
    }
    if username.is_empty() || password.is_empty() {
        return Err(DesktopError::Invalid(
            "registry username and password are required".to_string(),
        ));
    }
    Ok((
        "POST",
        "/auth".to_string(),
        serde_json::to_vec(&serde_json::json!({
            "serveraddress": registry,
            "username": username,
            "password": password,
        }))?,
    ))
}

fn run_registry_proxy(
    socket: Option<&str>,
    command: RegistryProxyCommands,
) -> Result<(), DesktopError> {
    let RegistryProxyCommands::Login { registry, username } = command;
    let mut password = String::new();
    std::io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_string(&mut password)?;
    if password.len() > MAX_REQUEST_BYTES {
        return Err(DesktopError::Invalid(
            "registry password input is too large".to_string(),
        ));
    }
    let password = password.trim_end_matches(['\r', '\n']);
    let (method, path, body) = registry_login_request(&registry, &username, password)?;
    run_backend_request(socket, method, path, body)
}

fn selected_proxy_backend(socket: Option<&str>) -> Result<Box<dyn Backend>, DesktopError> {
    if Platform::current() == Platform::Linux {
        if let Some(socket) = socket {
            let config = LinuxNativeConfig {
                socket_path: PathBuf::from(socket),
                ..LinuxNativeConfig::default()
            };
            return Ok(Box::new(LinuxNativeBackend::new(config)));
        }
    }
    select_backend().map_err(|error| DesktopError::Invalid(error.to_string()))
}

fn run_backend_request(
    socket: Option<&str>,
    method: &str,
    path: String,
    body: Vec<u8>,
) -> Result<(), DesktopError> {
    let backend = selected_proxy_backend(socket)?;
    let mut request = TransportRequest::new(method, path).body(body);
    if !request.body.is_empty() {
        request = request.header("content-type", "application/json");
    }
    let response = backend
        .request(request)
        .map_err(|error| DesktopError::Invalid(error.to_string()))?;
    if !(200..300).contains(&response.status) {
        return Err(terminal_daemon_error(response.status, &response.body));
    }
    std::io::stdout().write_all(&response.body)?;
    if !response.body.is_empty() && !response.body.ends_with(b"\n") {
        println!();
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FollowChannel {
    Stdout,
    Stderr,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FollowFrame {
    Data {
        channel: FollowChannel,
        data: Vec<u8>,
    },
    Terminal {
        status: i32,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Phase0CheckResult {
    host_os: String,
    wsl_detected: bool,
    wsl_list_status: Option<i32>,
    wsl_distros: Vec<String>,
    requested_distro: Option<String>,
    requested_available: Option<bool>,
    selected_distro: Option<String>,
    ferrocrate_present_in_guest: Option<bool>,
    guest_kernel: Option<String>,
    notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ForwardEntry {
    bind_addr: String,
    listen_port: u16,
    target_host: String,
    target_port: u16,
    enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VmConfig {
    backend: String,
    #[serde(default = "default_vm_name")]
    vm_name: String,
    cpus: u8,
    memory_mb: u32,
    disk_path: String,
    host_share_path: String,
    fs_backend: String,
    #[serde(default)]
    virtiofs_socket_path: Option<String>,
    #[serde(default)]
    hyperv_switch: Option<String>,
    ssh_port: u16,
    api_port: u16,
    #[serde(default)]
    guest_user: Option<String>,
    #[serde(default)]
    ssh_private_key_path: Option<String>,
    #[serde(default)]
    cloud_init_image_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VmState {
    config: VmConfig,
    pid: Option<u32>,
    #[serde(default)]
    auxiliary_pids: Vec<u32>,
    status: String,
    #[serde(default)]
    current_version: Option<String>,
    last_error: Option<String>,
}

fn default_vm_name() -> String {
    "FerroCrateDesktopVM".to_string()
}

fn command_exists(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        // Some required tools (notably macOS ssh-keygen and hdiutil) do not
        // implement `--version`; being executable is the availability test.
        .map(|_| true)
        .unwrap_or(false)
}

fn require_command(bin: &str) -> Result<(), DesktopError> {
    if command_exists(bin) {
        Ok(())
    } else {
        Err(DesktopError::Invalid(format!(
            "missing required command: {bin}"
        )))
    }
}

fn vm_arch_tag() -> Result<&'static str, DesktopError> {
    match std::env::consts::ARCH {
        "aarch64" => Ok("arm64"),
        "x86_64" => Ok("amd64"),
        other => Err(DesktopError::Invalid(format!(
            "unsupported architecture: {other}"
        ))),
    }
}

fn base_cloud_image_url() -> Result<String, DesktopError> {
    let arch = vm_arch_tag()?;
    Ok(std::env::var("FERROCRATE_VM_BASE_IMAGE_URL").unwrap_or_else(|_| {
        format!(
            "https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-{arch}.img"
        )
    }))
}

fn ensure_base_image(cache_dir: &Path) -> Result<PathBuf, DesktopError> {
    require_command("curl")?;
    let base = cache_dir.join("base-cloudimg.qcow2");
    if base.exists() {
        return Ok(base);
    }
    fs::create_dir_all(cache_dir)?;
    let url = base_cloud_image_url()?;
    let status = Command::new("curl")
        .arg("-fL")
        .arg(&url)
        .arg("-o")
        .arg(&base)
        .status()?;
    if !status.success() {
        return Err(DesktopError::Invalid(format!(
            "failed to download base image from {url}"
        )));
    }
    Ok(base)
}

fn ensure_vm_disk(disk_path: &Path, vm_dir: &Path) -> Result<(), DesktopError> {
    if disk_path.exists() {
        return Ok(());
    }
    require_command("qemu-img")?;
    let cache_dir = vm_dir.join("vm-cache");
    let base = ensure_base_image(&cache_dir)?;
    let size_gb = std::env::var("FERROCRATE_VM_SIZE_GB")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(20);
    let status = Command::new("qemu-img")
        .args([
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            base.to_string_lossy().as_ref(),
            disk_path.to_string_lossy().as_ref(),
            &format!("{size_gb}G"),
        ])
        .status()?;
    if !status.success() {
        return Err(DesktopError::Invalid(format!(
            "failed to create vm disk at {}",
            disk_path.display()
        )));
    }
    Ok(())
}

fn ensure_ssh_key(vm_dir: &Path) -> Result<(PathBuf, PathBuf), DesktopError> {
    require_command("ssh-keygen")?;
    let key_path = vm_dir.join("vm_ssh_key");
    let pub_path = vm_dir.join("vm_ssh_key.pub");
    if key_path.exists() && pub_path.exists() {
        restrict_ssh_private_key(&key_path)?;
        return Ok((key_path, pub_path));
    }
    let status = Command::new("ssh-keygen")
        .args(ssh_keygen_generate_args(&key_path))
        .status()?;
    if !status.success() {
        return Err(DesktopError::Invalid(
            "failed to generate vm ssh key".to_string(),
        ));
    }
    restrict_ssh_private_key(&key_path)?;
    Ok((key_path, pub_path))
}

fn reset_vm_known_hosts(vm_dir: &Path) -> Result<(), DesktopError> {
    let path = vm_dir.join("known_hosts");
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn ssh_keygen_generate_args(key_path: &Path) -> Vec<String> {
    vec![
        "-t".to_string(),
        "ed25519".to_string(),
        "-N".to_string(),
        String::new(),
        "-f".to_string(),
        key_path.display().to_string(),
    ]
}

#[cfg(unix)]
fn restrict_ssh_private_key(key_path: &Path) -> Result<(), DesktopError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_ssh_private_key(_key_path: &Path) -> Result<(), DesktopError> {
    Ok(())
}

fn ensure_cloud_init_iso(vm_dir: &Path, ssh_pubkey: &str) -> Result<PathBuf, DesktopError> {
    require_command("hdiutil")?;
    let seed_path = vm_dir.join("cloud-init.iso");
    if seed_path.exists() {
        fs::remove_file(&seed_path)?;
    }
    let tmp_dir = tempfile::tempdir()?;
    let user_data = tmp_dir.path().join("user-data");
    let meta_data = tmp_dir.path().join("meta-data");
    fs::write(
        &user_data,
        format!(
            "#cloud-config\noutput:\n  all: \"| tee -a /var/log/cloud-init-output.log > /dev/ttyS0\"\nusers:\n  - name: ubuntu\n    lock_passwd: false\n    plain_text_passwd: ferrocrate\n    ssh_authorized_keys:\n      - {ssh_pubkey}\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\nssh_pwauth: true\npackage_update: true\npackages:\n  - openssh-server\nwrite_files:\n  - path: /etc/systemd/system/ferro-cloud-debug.service\n    permissions: \"0644\"\n    owner: root:root\n    content: |\n      [Unit]\n      Description=Ferrocrate cloud-init debug capture\n      After=cloud-init.service\n\n      [Service]\n      Type=oneshot\n      ExecStart=/bin/bash -c 'echo ferro-cloud-debug $(date -Is) >> /var/log/ferro-cloud-debug.log; cloud-init status --long >> /var/log/ferro-cloud-debug.log 2>&1 || true; tail -200 /var/log/cloud-init.log >> /var/log/ferro-cloud-debug.log 2>&1 || true; tail -200 /var/log/cloud-init-output.log >> /var/log/ferro-cloud-debug.log 2>&1 || true; cat /run/cloud-init/ds-identify.log >> /var/log/ferro-cloud-debug.log 2>&1 || true'\n\n      [Install]\n      WantedBy=multi-user.target\nbootcmd:\n  - ['sh', '-c', 'echo cloud-init-bootcmd-start > /dev/ttyS0']\n  - rm -f /etc/systemd/system/ssh.service.d/* || true\n  - rm -f /etc/systemd/system/sshd.service.d/* || true\nruncmd:\n  - ['sh', '-c', 'echo cloud-init-runcmd-start > /dev/ttyS0']\n  - systemctl daemon-reload\n  - systemctl enable ferro-cloud-debug.service || true\n  - modprobe 9pnet_virtio || true\n  - modprobe 9p || true\n  - mkdir -p /mnt/host\n  - mount -t 9p -o trans=virtio,version=9p2000.L,cache=mmap ferrohost /mnt/host || true\n  - mkdir -p /mnt/host/.ferrocrate\n  - ssh-keygen -A\n  - sed -i 's/^#\\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config\n  - sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config\n  - systemctl disable --now ssh.socket || true\n  - systemctl enable ssh.service\n  - systemctl restart ssh.service\n  - ['sh', '-c', 'sleep 1 && ss -ltnp']\n  - ss -ltnp > /mnt/host/.ferrocrate/guest-ssh-debug.log || true\n  - cp -f /var/log/ferro-cloud-debug.log /mnt/host/.ferrocrate/ferro-cloud-debug.log 2>/dev/null || true\n  - cp -f /var/log/cloud-init.log /mnt/host/.ferrocrate/cloud-init.log 2>/dev/null || true\n  - cp -f /var/log/cloud-init-output.log /mnt/host/.ferrocrate/cloud-init-output.log 2>/dev/null || true\n",
        ),
    )?;
    let instance_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    fs::write(
        &meta_data,
        format!("instance-id: ferrocrate-vm-{instance_ts}\nlocal-hostname: ferrocrate\n"),
    )?;

    let status = Command::new("hdiutil")
        .args([
            "makehybrid",
            "-iso",
            "-joliet",
            "-o",
            seed_path.to_string_lossy().as_ref(),
            "-default-volume-name",
            "cidata",
        ])
        .arg(tmp_dir.path())
        .status()?;
    if !status.success() {
        return Err(DesktopError::Invalid(
            "failed to create cloud-init seed iso".to_string(),
        ));
    }
    Ok(seed_path)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ChannelManifest {
    channels: std::collections::BTreeMap<String, ChannelRelease>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ChannelRelease {
    version: String,
    image_path: String,
    sha256: Option<String>,
}

#[derive(Debug, Error)]
enum DesktopError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid request: {0}")]
    Invalid(String),
}

fn main() {
    let cli = Cli::parse();
    if command_requires_desktop_entitlement(&cli.command) {
        if let Err(err) = entitlements::require_feature(Feature::Desktop) {
            eprintln!(
                "error: entitlement check failed: {err}. set FERROCRATE_ENTITLEMENT_FILE and FERROCRATE_ENTITLEMENT_PUBKEY"
            );
            std::process::exit(1);
        }
    }
    let result = match cli.command {
        Commands::PortProbe { ports, exclude } => ferro_desktop::ports::probe_ports(&ports, &exclude)
            .map_err(DesktopError::Invalid)
            .and_then(|probes| {
                let payload: Vec<_> = probes.into_iter().map(|probe| serde_json::json!({ "port": probe.port, "available": probe.available, "suggested": probe.suggested })).collect();
                println!("{}", serde_json::to_string(&payload)?);
                Ok(())
            }),
        Commands::Daemon {
            addr,
            pipe_name,
            wsl_distro,
            allow_remote,
        } => run_daemon(&addr, pipe_name.as_deref(), wsl_distro, allow_remote),
        Commands::Exec {
            addr,
            pipe_name,
            wsl,
            wsl_distro,
            follow,
            interactive,
            cmd,
        } => run_client_exec(
            &addr,
            pipe_name.as_deref(),
            cmd,
            wsl,
            wsl_distro,
            follow,
            interactive,
        ),
        Commands::TerminalProxy {
            socket,
            container,
            env,
            user,
            workdir,
            cmd,
        } => run_terminal_proxy(
            socket.as_deref(),
            &container,
            &cmd,
            &env,
            user.as_deref(),
            workdir.as_deref(),
        ),
        Commands::TerminalResize {
            socket,
            exec_id,
            columns,
            rows,
        } => run_terminal_resize(socket.as_deref(), &exec_id, columns, rows),
        Commands::VolumeProxy { socket, command } => run_volume_proxy(socket.as_deref(), command),
        Commands::NetworkProxy { socket, command } => run_network_proxy(socket.as_deref(), command),
        Commands::ContainerProxy { socket, command } => {
            run_container_proxy(socket.as_deref(), command)
        }
        Commands::RegistryProxy { socket, command } => {
            run_registry_proxy(socket.as_deref(), command)
        }
        Commands::Doctor { wsl_distro } => run_doctor(wsl_distro),
        Commands::BackendSmoke { start, json } => run_backend_smoke(start, json),
        Commands::Phase0Check { wsl_distro, json } => run_phase0_check(wsl_distro, json),
        Commands::Forward {
            state_file,
            json,
            command,
        } => run_forward_command(state_file.as_deref(), json, command),
        Commands::Vm {
            state_file,
            command,
        } => run_vm_command(state_file.as_deref(), *command),
        Commands::Autostart { command } => run_autostart_command(command),
    };
    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn command_requires_desktop_entitlement(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Daemon { .. }
            | Commands::PortProbe { .. }
            | Commands::Exec { .. }
            | Commands::TerminalProxy { .. }
            | Commands::TerminalResize { .. }
            | Commands::VolumeProxy { .. }
            | Commands::NetworkProxy { .. }
            | Commands::BackendSmoke { .. }
            | Commands::ContainerProxy { .. }
            | Commands::RegistryProxy { .. }
            | Commands::Forward { .. }
            | Commands::Vm { .. }
            | Commands::Autostart { .. }
    )
}

fn run_daemon(
    addr: &str,
    pipe_name: Option<&str>,
    default_wsl_distro: Option<String>,
    allow_remote: bool,
) -> Result<(), DesktopError> {
    if let Some(pipe_name) = pipe_name {
        return run_daemon_pipe(pipe_name, default_wsl_distro);
    }
    validate_daemon_addr(addr, allow_remote)?;
    let runtime_backend =
        select_backend().map_err(|error| DesktopError::Invalid(error.to_string()))?;
    runtime_backend
        .start()
        .map_err(|error| DesktopError::Invalid(error.to_string()))?;
    let listener = TcpListener::bind(addr)?;
    loop {
        let (mut stream, _) = listener.accept()?;
        let default_wsl_distro = default_wsl_distro.clone();
        thread::spawn(move || {
            let _ = handle_client(&mut stream, default_wsl_distro.as_deref());
        });
    }
}

fn validate_daemon_addr(addr: &str, allow_remote: bool) -> Result<(), DesktopError> {
    if addr == "127.0.0.1:4190" || addr == "localhost:4190" || addr == "[::1]:4190" {
        return Err(DesktopError::Invalid(
            "127.0.0.1:4190 is reserved for the web bridge; run the desktop daemon on its API port (default 127.0.0.1:4288)".to_string(),
        ));
    }
    if allow_remote {
        return Ok(());
    }
    if addr.starts_with("127.0.0.1:")
        || addr.starts_with("localhost:")
        || addr.starts_with("[::1]:")
    {
        return Ok(());
    }
    Err(DesktopError::Invalid(
        "daemon bind address must be loopback unless --allow-remote is set".to_string(),
    ))
}

fn handle_client(
    stream: &mut TcpStream,
    default_wsl_distro: Option<&str>,
) -> Result<(), DesktopError> {
    let request = read_exec_request(stream)?;
    if request.interactive {
        return proxy_interactive_request(stream, request, default_wsl_distro);
    }
    if request.follow {
        return proxy_follow_request(stream, request, default_wsl_distro);
    }
    let response = process_exec_request(request, default_wsl_distro)?;
    let payload = serde_json::to_string(&response)? + "\n";
    stream.write_all(payload.as_bytes())?;
    Ok(())
}

fn write_follow_frame<W: Write>(writer: &mut W, frame: &FollowFrame) -> Result<(), DesktopError> {
    serde_json::to_writer(&mut *writer, frame)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn replay_follow_frames<R: BufRead, O: Write, E: Write>(
    mut reader: R,
    stdout: &mut O,
    stderr: &mut E,
) -> Result<(), DesktopError> {
    let mut raw = String::new();
    loop {
        raw.clear();
        if reader.read_line(&mut raw)? == 0 {
            return Err(DesktopError::Invalid(
                "follow stream ended without terminal status".to_string(),
            ));
        }
        let frame: FollowFrame = serde_json::from_str(raw.trim_end())?;
        match frame {
            FollowFrame::Data {
                channel: FollowChannel::Stdout,
                data,
            } => {
                stdout.write_all(&data)?;
                stdout.flush()?;
            }
            FollowFrame::Data {
                channel: FollowChannel::Stderr,
                data,
            } => {
                stderr.write_all(&data)?;
                stderr.flush()?;
            }
            FollowFrame::Terminal { status: 0 } => return Ok(()),
            FollowFrame::Terminal { status } => {
                return Err(DesktopError::Invalid(format!(
                    "remote command exited with status {status}"
                )));
            }
        }
    }
}

fn copy_interactive_input<R: Read, W: Write>(mut reader: R, mut writer: W) -> std::io::Result<()> {
    std::io::copy(&mut reader, &mut writer)?;
    writer.flush()
}

fn proxy_interactive_request(
    stream: &mut TcpStream,
    mut request: ExecRequest,
    default_wsl_distro: Option<&str>,
) -> Result<(), DesktopError> {
    if !is_interactive_exec_command(&request.cmd) {
        write_follow_frame(
            stream,
            &FollowFrame::Data {
                channel: FollowChannel::Stderr,
                data: b"interactive requests must invoke ferrocrate exec with stdin and TTY\n"
                    .to_vec(),
            },
        )?;
        write_follow_frame(stream, &FollowFrame::Terminal { status: 2 })?;
        return Ok(());
    }
    if request.wsl_distro.is_none() {
        request.wsl_distro = default_wsl_distro.map(ToOwned::to_owned);
    }

    let mut process = match run_follow_request(&request) {
        Ok(process) => process,
        Err(err) => {
            write_follow_frame(
                stream,
                &FollowFrame::Data {
                    channel: FollowChannel::Stderr,
                    data: format!("{err}\n").into_bytes(),
                },
            )?;
            write_follow_frame(stream, &FollowFrame::Terminal { status: 1 })?;
            return Ok(());
        }
    };
    let stdin = process
        .take_stdin()
        .map_err(|error| DesktopError::Invalid(error.to_string()))?;
    let input_stream = stream.try_clone()?;
    thread::spawn(move || copy_interactive_input(input_stream, stdin));
    forward_backend_channels(stream, process)?;
    Ok(())
}

fn proxy_follow_request(
    stream: &mut TcpStream,
    mut request: ExecRequest,
    default_wsl_distro: Option<&str>,
) -> Result<(), DesktopError> {
    if !is_log_follow_command(&request.cmd) {
        write_follow_frame(
            stream,
            &FollowFrame::Data {
                channel: FollowChannel::Stderr,
                data: b"follow requests must invoke ferrocrate logs --follow\n".to_vec(),
            },
        )?;
        write_follow_frame(stream, &FollowFrame::Terminal { status: 2 })?;
        return Ok(());
    }
    if request.wsl_distro.is_none() {
        request.wsl_distro = default_wsl_distro.map(ToOwned::to_owned);
    }

    let process = match run_follow_request(&request) {
        Ok(process) => process,
        Err(err) => {
            write_follow_frame(
                stream,
                &FollowFrame::Data {
                    channel: FollowChannel::Stderr,
                    data: format!("{err}\n").into_bytes(),
                },
            )?;
            write_follow_frame(stream, &FollowFrame::Terminal { status: 1 })?;
            return Ok(());
        }
    };
    forward_backend_channels(stream, process)?;
    Ok(())
}

fn forward_backend_channels(
    stream: &mut TcpStream,
    mut process: Box<dyn ferro_desktop::backend::ExecStream>,
) -> Result<(), DesktopError> {
    let stdout = process
        .take_stdout()
        .map_err(|error| DesktopError::Invalid(error.to_string()))?;
    let stderr = process
        .take_stderr()
        .map_err(|error| DesktopError::Invalid(error.to_string()))?;
    let output = Arc::new(Mutex::new(stream.try_clone()?));
    let stdout_worker = spawn_frame_reader(stdout, FollowChannel::Stdout, output.clone());
    let stderr_worker = spawn_frame_reader(stderr, FollowChannel::Stderr, output.clone());
    let status = process
        .wait()
        .map_err(|error| DesktopError::Invalid(error.to_string()))?;
    let _ = stdout_worker.join();
    let _ = stderr_worker.join();
    let mut output = output
        .lock()
        .map_err(|_| DesktopError::Invalid("follow output state is unavailable".into()))?;
    write_follow_frame(&mut *output, &FollowFrame::Terminal { status })
}

fn spawn_frame_reader(
    mut reader: Box<dyn Read + Send>,
    channel: FollowChannel,
    stream: Arc<Mutex<TcpStream>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        loop {
            let Ok(read) = reader.read(&mut buffer) else {
                return;
            };
            if read == 0 {
                return;
            }
            let Ok(mut stream) = stream.lock() else {
                return;
            };
            if write_follow_frame(
                &mut *stream,
                &FollowFrame::Data {
                    channel: channel.clone(),
                    data: buffer[..read].to_vec(),
                },
            )
            .is_err()
            {
                return;
            }
        }
    })
}

fn process_exec_request(
    mut request: ExecRequest,
    default_wsl_distro: Option<&str>,
) -> Result<ExecResponse, DesktopError> {
    if request.cmd.is_empty() {
        return Err(DesktopError::Invalid("command is required".to_string()));
    }
    if let Some(distro) = default_wsl_distro {
        request.use_wsl = true;
        request.wsl_distro = Some(distro.to_owned());
        let output = run_direct_wsl_request(&request, distro)?;
        return Ok(ExecResponse {
            status: output.code,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let output = run_request(&request)?;
    Ok(ExecResponse {
        status: output.code,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

#[cfg(windows)]
fn run_direct_wsl_request(
    request: &ExecRequest,
    distro: &str,
) -> Result<ferro_desktop::backend::ExecResponse, DesktopError> {
    let mut command = Command::new("wsl.exe");
    command.args([
        "-d",
        distro,
        "--",
        "env",
        "FERROCRATE_DESKTOP_FORWARD=0",
        "RUST_LOG=error",
        "FERROCRATE_LOG=error",
        "NO_COLOR=1",
    ]);
    command.args(&request.cmd);
    let output = command.output()?;
    Ok(ferro_desktop::backend::ExecResponse {
        code: output.status.code().unwrap_or(1),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

#[cfg(not(windows))]
fn run_direct_wsl_request(
    _request: &ExecRequest,
    _distro: &str,
) -> Result<ferro_desktop::backend::ExecResponse, DesktopError> {
    Err(DesktopError::Invalid(
        "WSL execution is only available on Windows hosts".to_string(),
    ))
}

fn read_exec_request<R: Read>(stream: &mut R) -> Result<ExecRequest, DesktopError> {
    let mut buf = Vec::new();
    let mut byte = [0_u8; 1];
    while buf.len() <= MAX_REQUEST_BYTES {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    if buf.len() > MAX_REQUEST_BYTES {
        return Err(DesktopError::Invalid("request too large".to_string()));
    }
    if buf.is_empty() {
        return Err(DesktopError::Invalid("empty request".to_string()));
    }
    let request: ExecRequest = serde_json::from_slice(&buf)?;
    Ok(request)
}

fn run_client_exec(
    addr: &str,
    pipe_name: Option<&str>,
    cmd: Vec<String>,
    wsl: bool,
    wsl_distro: Option<String>,
    follow: bool,
    interactive: bool,
) -> Result<(), DesktopError> {
    if cmd.is_empty() {
        return Err(DesktopError::Invalid("command is required".to_string()));
    }
    if follow && interactive {
        return Err(DesktopError::Invalid(
            "--follow and --interactive are mutually exclusive".to_string(),
        ));
    }
    let request = ExecRequest {
        cmd,
        use_wsl: wsl,
        wsl_distro,
        follow,
        interactive,
    };
    if let Some(pipe_name) = pipe_name {
        if follow || interactive {
            return Err(DesktopError::Invalid(
                "streamed execution is unsupported with --pipe-name".to_string(),
            ));
        }
        return run_client_exec_pipe(pipe_name, request);
    }
    let mut stream = TcpStream::connect(addr)?;
    let payload = serde_json::to_string(&request)? + "\n";
    stream.write_all(payload.as_bytes())?;

    if interactive {
        let input_stream = stream.try_clone()?;
        thread::spawn(move || {
            let stdin = std::io::stdin();
            let _ = copy_interactive_input(stdin.lock(), input_stream);
        });
        let mut stdout = std::io::stdout();
        let mut stderr = std::io::stderr();
        return replay_follow_frames(BufReader::new(stream), &mut stdout, &mut stderr);
    }
    if follow {
        let mut stdout = std::io::stdout();
        let mut stderr = std::io::stderr();
        return replay_follow_frames(BufReader::new(stream), &mut stdout, &mut stderr);
    }

    let mut response_raw = String::new();
    stream.read_to_string(&mut response_raw)?;
    let response: ExecResponse = serde_json::from_str(response_raw.trim())?;

    if !response.stdout.is_empty() {
        print!("{}", response.stdout);
    }
    if !response.stderr.is_empty() {
        eprint!("{}", response.stderr);
    }
    if response.status != 0 {
        return Err(DesktopError::Invalid(format!(
            "remote command exited with status {}",
            response.status
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn run_daemon_pipe(
    pipe_name: &str,
    default_wsl_distro: Option<String>,
) -> Result<(), DesktopError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;

    let full_name = normalize_pipe_name(pipe_name);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(DesktopError::Io)?;
    runtime.block_on(async move {
        loop {
            let server = ServerOptions::new().create(&full_name)?;
            server.connect().await?;
            let mut reader = BufReader::new(server);
            let mut request_raw = String::new();
            reader.read_line(&mut request_raw).await?;
            if request_raw.len() > MAX_REQUEST_BYTES {
                return Err(DesktopError::Invalid(
                    "request exceeds size limit".to_string(),
                ));
            }
            let request = serde_json::from_str(request_raw.trim())?;
            let response = process_exec_request(request, default_wsl_distro.as_deref())?;
            let payload = serde_json::to_string(&response)? + "\n";
            let mut server = reader.into_inner();
            server.write_all(payload.as_bytes()).await?;
            server.flush().await?;
            server.disconnect()?;
        }
    })
}

#[cfg(not(windows))]
fn run_daemon_pipe(
    _pipe_name: &str,
    _default_wsl_distro: Option<String>,
) -> Result<(), DesktopError> {
    Err(DesktopError::Invalid(
        "--pipe-name is supported only on Windows hosts".to_string(),
    ))
}

#[cfg(windows)]
fn run_client_exec_pipe(pipe_name: &str, request: ExecRequest) -> Result<(), DesktopError> {
    use std::fs::OpenOptions;

    let full_name = normalize_pipe_name(pipe_name);
    let mut file = OpenOptions::new().read(true).write(true).open(full_name)?;
    let payload = serde_json::to_string(&request)? + "\n";
    file.write_all(payload.as_bytes())?;
    file.flush()?;
    let mut response_raw = String::new();
    file.read_to_string(&mut response_raw)?;
    let response: ExecResponse = serde_json::from_str(response_raw.trim())?;
    if !response.stdout.is_empty() {
        print!("{}", response.stdout);
    }
    if !response.stderr.is_empty() {
        eprint!("{}", response.stderr);
    }
    if response.status != 0 {
        return Err(DesktopError::Invalid(format!(
            "remote command exited with status {}",
            response.status
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn run_client_exec_pipe(_pipe_name: &str, _request: ExecRequest) -> Result<(), DesktopError> {
    Err(DesktopError::Invalid(
        "--pipe-name is supported only on Windows hosts".to_string(),
    ))
}

#[cfg(windows)]
fn normalize_pipe_name(pipe_name: &str) -> String {
    if pipe_name.starts_with(r"\\.\pipe\") {
        pipe_name.to_string()
    } else {
        format!(r"\\.\pipe\{}", pipe_name)
    }
}

#[cfg(unix)]
fn stop_vm_process(pid: u32) -> Result<(), DesktopError> {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(DesktopError::Invalid(format!(
            "failed to stop vm pid={pid}"
        )))
    }
}

#[cfg(not(unix))]
fn stop_vm_process(_pid: u32) -> Result<(), DesktopError> {
    Err(DesktopError::Invalid(
        "vm stop is supported on unix-like hosts only".to_string(),
    ))
}

fn run_doctor(wsl_distro: Option<String>) -> Result<(), DesktopError> {
    let check = gather_phase0_check(wsl_distro)?;
    println!("wsl_detected={}", check.wsl_detected);
    if let Some(status) = check.wsl_list_status {
        println!("wsl_list_status={status}");
    }
    println!("wsl_distros={}", check.wsl_distros.join(","));
    if let Some(distro) = check.requested_distro {
        println!("wsl_distro_requested={distro}");
    }
    if let Some(available) = check.requested_available {
        println!("wsl_distro_available={available}");
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct BackendSmokeReport {
    backend: ferro_desktop::backend::BackendStatus,
    request_status: u16,
    request_path: &'static str,
}

fn run_backend_smoke(start: bool, json: bool) -> Result<(), DesktopError> {
    let backend = select_backend().map_err(|error| DesktopError::Invalid(error.to_string()))?;
    if start {
        backend
            .start()
            .map_err(|error| DesktopError::Invalid(error.to_string()))?;
    }
    let status = backend.status();
    if !status.healthy {
        return Err(DesktopError::Invalid(format!(
            "selected backend {} is not healthy (state={}, reason={})",
            status.backend,
            serde_json::to_value(status.state)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| "unknown".to_string()),
            status.reason.as_deref().unwrap_or("not reported"),
        )));
    }

    const REQUEST_PATH: &str = "/containers/json?all=1";
    let response = backend
        .request(TransportRequest::new("GET", REQUEST_PATH))
        .map_err(|error| DesktopError::Invalid(error.to_string()))?;
    if !(200..300).contains(&response.status) {
        return Err(DesktopError::Invalid(format!(
            "selected backend {} proxy request {REQUEST_PATH} returned HTTP {}",
            status.backend, response.status
        )));
    }
    let report = BackendSmokeReport {
        backend: status,
        request_status: response.status,
        request_path: REQUEST_PATH,
    };
    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!(
            "backend={} state={:?} healthy={} request={} status={}",
            report.backend.backend,
            report.backend.state,
            report.backend.healthy,
            report.request_path,
            report.request_status,
        );
    }
    Ok(())
}

fn run_phase0_check(wsl_distro: Option<String>, json: bool) -> Result<(), DesktopError> {
    let check = gather_phase0_check(wsl_distro)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&check)?);
        return Ok(());
    }

    println!("host_os={}", check.host_os);
    println!("wsl_detected={}", check.wsl_detected);
    if let Some(status) = check.wsl_list_status {
        println!("wsl_list_status={status}");
    }
    println!("wsl_distros={}", check.wsl_distros.join(","));
    if let Some(requested) = check.requested_distro {
        println!("requested_distro={requested}");
    }
    if let Some(ok) = check.requested_available {
        println!("requested_available={ok}");
    }
    if let Some(selected) = check.selected_distro {
        println!("selected_distro={selected}");
    }
    if let Some(found) = check.ferrocrate_present_in_guest {
        println!("ferrocrate_present_in_guest={found}");
    }
    if let Some(kernel) = check.guest_kernel {
        println!("guest_kernel={kernel}");
    }
    for note in check.notes {
        println!("note={note}");
    }
    Ok(())
}

fn run_forward_command(
    state_file: Option<&str>,
    json: bool,
    command: ForwardCommands,
) -> Result<(), DesktopError> {
    let state_path = state_file
        .map(PathBuf::from)
        .unwrap_or_else(default_forward_state_path);
    let mut entries = load_forward_entries(&state_path)?;

    match command {
        ForwardCommands::Add {
            bind_addr,
            listen_port,
            target_host,
            target_port,
        } => {
            upsert_forward_entry(
                &mut entries,
                ForwardEntry {
                    bind_addr,
                    listen_port,
                    target_host,
                    target_port,
                    enabled: true,
                },
            );
            save_forward_entries(&state_path, &entries)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                println!(
                    "forward: added {} entries={}",
                    state_path.display(),
                    entries.len()
                );
            }
        }
        ForwardCommands::Remove {
            bind_addr,
            listen_port,
        } => {
            let before = entries.len();
            entries.retain(|entry| {
                !(entry.bind_addr == bind_addr && entry.listen_port == listen_port)
            });
            save_forward_entries(&state_path, &entries)?;
            let removed = before.saturating_sub(entries.len());
            if json {
                let payload = serde_json::json!({
                    "removed": removed,
                    "entries": entries,
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                println!("forward: removed={removed} entries={}", entries.len());
            }
        }
        ForwardCommands::List => {
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if entries.is_empty() {
                println!("forward: no entries");
            } else {
                for entry in entries {
                    println!(
                        "forward: {}:{} -> {}:{} enabled={}",
                        entry.bind_addr,
                        entry.listen_port,
                        entry.target_host,
                        entry.target_port,
                        entry.enabled
                    );
                }
            }
        }
        ForwardCommands::Run => {
            let enabled = entries
                .into_iter()
                .filter(|entry| entry.enabled)
                .collect::<Vec<_>>();
            if enabled.is_empty() {
                return Err(DesktopError::Invalid(
                    "forward: no enabled entries configured".to_string(),
                ));
            }
            start_forwarders(enabled)?;
        }
    }
    Ok(())
}

fn default_forward_state_path() -> PathBuf {
    if let Ok(path) = std::env::var("FERROCRATE_DESKTOP_FORWARD_STATE") {
        return PathBuf::from(path);
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("ferrocrate")
            .join("desktop-forwards.json");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".ferrocrate")
            .join("desktop-forwards.json");
    }
    PathBuf::from(".ferrocrate").join("desktop-forwards.json")
}

fn load_forward_entries(path: &Path) -> Result<Vec<ForwardEntry>, DesktopError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice::<Vec<ForwardEntry>>(&bytes)?)
}

fn save_forward_entries(path: &Path, entries: &[ForwardEntry]) -> Result<(), DesktopError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_vec_pretty(entries)?;
    fs::write(path, payload)?;
    Ok(())
}

fn upsert_forward_entry(entries: &mut Vec<ForwardEntry>, entry: ForwardEntry) {
    if let Some(existing) = entries.iter_mut().find(|existing| {
        existing.bind_addr == entry.bind_addr && existing.listen_port == entry.listen_port
    }) {
        *existing = entry;
        return;
    }
    entries.push(entry);
}

fn start_forwarders(entries: Vec<ForwardEntry>) -> Result<(), DesktopError> {
    for entry in entries {
        thread::spawn(move || {
            let _ = run_single_forwarder(entry);
        });
    }
    loop {
        thread::park();
    }
}

fn run_single_forwarder(entry: ForwardEntry) -> Result<(), DesktopError> {
    let listen = format!("{}:{}", entry.bind_addr, entry.listen_port);
    let target = format!("{}:{}", entry.target_host, entry.target_port);
    let listener = TcpListener::bind(&listen)?;
    for incoming in listener.incoming() {
        let target = target.clone();
        if let Ok(mut source) = incoming {
            thread::spawn(move || {
                if let Ok(mut destination) = TcpStream::connect(&target) {
                    let _ = pipe_bidirectional(&mut source, &mut destination);
                }
            });
        }
    }
    Ok(())
}

fn pipe_bidirectional(a: &mut TcpStream, b: &mut TcpStream) -> Result<(), DesktopError> {
    let mut a_read = a.try_clone()?;
    let mut a_write = a.try_clone()?;
    let mut b_read = b.try_clone()?;
    let mut b_write = b.try_clone()?;

    let t1 = thread::spawn(move || std::io::copy(&mut a_read, &mut b_write));
    let t2 = thread::spawn(move || std::io::copy(&mut b_read, &mut a_write));
    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

fn run_vm_command(state_file: Option<&str>, command: VmCommands) -> Result<(), DesktopError> {
    let state_path = state_file
        .map(PathBuf::from)
        .unwrap_or_else(default_vm_state_path);
    match command {
        VmCommands::Init(args) => {
            let VmInitArgs {
                backend,
                vm_name,
                cpus,
                memory_mb,
                disk_path,
                host_share_path,
                fs_backend,
                virtiofs_socket_path,
                hyperv_switch,
                ssh_port,
                api_port,
                guest_user,
                ssh_private_key_path,
                cloud_init_image_path,
                vfkit_kernel_path,
                vfkit_initrd_path,
                vfkit_mac,
            } = *args;
            let disk_path = disk_path.unwrap_or_else(|| {
                state_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("ferrocrate-desktop.qcow2")
                    .display()
                    .to_string()
            });
            let host_share_path = host_share_path.unwrap_or_else(|| {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .display()
                    .to_string()
            });
            let vm_dir = state_path.parent().unwrap_or_else(|| Path::new("."));
            reset_vm_known_hosts(vm_dir)?;
            let fs_backend = fs_backend.to_ascii_lowercase();
            if fs_backend != "virtiofs" && fs_backend != "9p" {
                return Err(DesktopError::Invalid(format!(
                    "unsupported fs backend: {} (expected virtiofs or 9p)",
                    fs_backend
                )));
            }
            let virtiofs_socket_path = virtiofs_socket_path.or_else(|| {
                state_path
                    .parent()
                    .map(|p| p.join("virtiofsd.sock").display().to_string())
            });
            let guest_user = guest_user.unwrap_or_else(|| "ubuntu".to_string());
            let mut ssh_private_key_path = ssh_private_key_path;
            let mut cloud_init_image_path = cloud_init_image_path;
            if backend.starts_with("qemu") {
                ensure_vm_disk(Path::new(&disk_path), vm_dir)?;
                if ssh_private_key_path.is_none() {
                    let (priv_key, pub_key) = ensure_ssh_key(vm_dir)?;
                    ssh_private_key_path = Some(priv_key.display().to_string());
                    let ssh_pub = fs::read_to_string(&pub_key)?;
                    let seed = ensure_cloud_init_iso(vm_dir, ssh_pub.trim())?;
                    cloud_init_image_path = Some(seed.display().to_string());
                } else if cloud_init_image_path.is_none() {
                    let pub_path = PathBuf::from(
                        ssh_private_key_path
                            .as_ref()
                            .map(|p| format!("{p}.pub"))
                            .unwrap_or_default(),
                    );
                    if pub_path.exists() {
                        let ssh_pub = fs::read_to_string(&pub_path)?;
                        let seed = ensure_cloud_init_iso(vm_dir, ssh_pub.trim())?;
                        cloud_init_image_path = Some(seed.display().to_string());
                    }
                }
            } else if backend == "vfkit" {
                let artifact_dir = Path::new(&disk_path)
                    .parent()
                    .unwrap_or_else(|| Path::new("."));
                fs::create_dir_all(artifact_dir)?;
                let kernel = vfkit_kernel_path.ok_or_else(|| {
                    DesktopError::Invalid("vfkit requires --vfkit-kernel-path".to_string())
                })?;
                let initrd = vfkit_initrd_path.ok_or_else(|| {
                    DesktopError::Invalid("vfkit requires --vfkit-initrd-path".to_string())
                })?;
                let canonical_kernel = artifact_dir.join("vfkit-kernel");
                let canonical_initrd = artifact_dir.join("vfkit-initrd");
                if Path::new(&kernel) != canonical_kernel {
                    fs::copy(&kernel, &canonical_kernel)?;
                }
                if Path::new(&initrd) != canonical_initrd {
                    fs::copy(&initrd, &canonical_initrd)?;
                }
                fs::write(artifact_dir.join("vfkit-mac"), vfkit_mac)?;
            }
            let state = VmState {
                config: VmConfig {
                    backend,
                    vm_name,
                    cpus,
                    memory_mb,
                    disk_path,
                    host_share_path,
                    fs_backend,
                    virtiofs_socket_path,
                    hyperv_switch,
                    ssh_port,
                    api_port,
                    guest_user: Some(guest_user),
                    ssh_private_key_path,
                    cloud_init_image_path,
                },
                pid: None,
                auxiliary_pids: Vec::new(),
                status: "initialized".to_string(),
                current_version: None,
                last_error: None,
            };
            save_vm_state(&state_path, &state)?;
            println!("vm: initialized {}", state_path.display());
            Ok(())
        }
        VmCommands::Start {
            foreground,
            forward_state_file,
        } => {
            let mut state = load_vm_state(&state_path)?;
            if let Some(pid) = state.pid {
                if pid_alive(pid) {
                    if foreground {
                        while pid_alive(pid) {
                            std::thread::sleep(Duration::from_millis(250));
                        }
                    }
                    println!("vm: already running pid={pid}");
                    return Ok(());
                }
            }
            let forward_state_path = forward_state_file
                .map(PathBuf::from)
                .unwrap_or_else(default_forward_state_path);
            let forwards = load_forward_entries(&forward_state_path)
                .unwrap_or_default()
                .into_iter()
                .filter(|entry| entry.enabled)
                .collect::<Vec<_>>();

            match state.config.backend.as_str() {
                "qemu-hvf" | "qemu-x86_64" | "qemu-tcg-aarch64" | "qemu-tcg-x86_64" => {
                    if !cfg!(target_os = "macos") {
                        return Err(DesktopError::Invalid(
                            "qemu vm backend is currently supported on macOS hosts only"
                                .to_string(),
                        ));
                    }
                    state.auxiliary_pids.clear();
                    if state.config.fs_backend == "virtiofs" {
                        state
                            .auxiliary_pids
                            .push(start_virtiofs_daemon(&state.config)?);
                    }
                    let mut command = build_vm_command(&state.config, &forwards)?;
                    if foreground {
                        command.arg("-serial").arg("mon:stdio");
                        let mut child = command.spawn()?;
                        state.pid = Some(child.id());
                        state.status = "running".to_string();
                        state.last_error = None;
                        save_vm_state(&state_path, &state)?;
                        let status = child.wait()?;
                        if !status.success() {
                            return Err(DesktopError::Invalid(format!(
                                "vm process exited with status {status}"
                            )));
                        }
                        return Ok(());
                    }
                    let log_path = state_path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join("ferro-desktop-vm.log");
                    command
                        .arg("-serial")
                        .arg(format!("file:{}", log_path.display()));
                    let log_file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&log_path)?;
                    let log_file_err = log_file.try_clone()?;
                    command.stdin(Stdio::null());
                    command.stdout(Stdio::from(log_file));
                    command.stderr(Stdio::from(log_file_err));
                    let pid = if cfg!(target_os = "macos") {
                        let pidfile = state_path
                            .parent()
                            .unwrap_or_else(|| Path::new("."))
                            .join("ferro-desktop-vm.pid");
                        command.arg("-daemonize").arg("-pidfile").arg(&pidfile);
                        let status = command.status()?;
                        if !status.success() {
                            return Err(DesktopError::Invalid(format!(
                                "vm process exited with status {status}"
                            )));
                        }
                        let pid = fs::read_to_string(&pidfile)
                            .ok()
                            .and_then(|text| text.trim().parse::<u32>().ok());
                        pid.ok_or_else(|| {
                            DesktopError::Invalid(format!(
                                "vm pidfile missing or invalid: {}",
                                pidfile.display()
                            ))
                        })?
                    } else {
                        let child = command.spawn()?;
                        child.id()
                    };
                    state.pid = Some(pid);
                    state.status = "running".to_string();
                    state.last_error = None;
                    save_vm_state(&state_path, &state)?;
                    println!("vm: started pid={pid}");
                    std::thread::sleep(Duration::from_millis(500));
                    if !pid_alive(pid) {
                        state.pid = None;
                        state.status = "stopped".to_string();
                        state.last_error =
                            Some(format!("vm exited early; see {}", log_path.display()));
                        save_vm_state(&state_path, &state)?;
                    }
                    Ok(())
                }
                "vfkit" => {
                    if !cfg!(target_os = "macos") {
                        return Err(DesktopError::Invalid(
                            "vfkit is supported on macOS hosts only".to_string(),
                        ));
                    }
                    let mut command = build_vfkit_command(&state.config)?;
                    let log_path = state_path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join("vfkit.log");
                    let log_file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&log_path)?;
                    let log_file_err = log_file.try_clone()?;
                    command
                        .stdin(Stdio::null())
                        .stdout(Stdio::from(log_file))
                        .stderr(Stdio::from(log_file_err));
                    let mut child = command.spawn()?;
                    state.pid = Some(child.id());
                    state.auxiliary_pids.clear();
                    state.status = "starting".to_string();
                    state.last_error = None;
                    save_vm_state(&state_path, &state)?;
                    let guest_address = wait_for_vfkit_guest_address(&state.config, 120)?;
                    let forward_pid = start_vfkit_ssh_forward(&state.config, &guest_address)?;
                    state.auxiliary_pids.push(forward_pid);
                    state.status = "running".to_string();
                    save_vm_state(&state_path, &state)?;
                    println!("vm: started pid={} backend=vfkit", child.id());
                    if foreground {
                        let status = child.wait()?;
                        if !status.success() {
                            return Err(DesktopError::Invalid(format!(
                                "vfkit exited with status {status}"
                            )));
                        }
                    }
                    Ok(())
                }
                "hyperv" => {
                    start_hyperv_vm(&state.config)?;
                    state.pid = None;
                    state.status = "running".to_string();
                    state.last_error = None;
                    save_vm_state(&state_path, &state)?;
                    println!("vm: started backend=hyperv name={}", state.config.vm_name);
                    Ok(())
                }
                other => Err(DesktopError::Invalid(format!(
                    "unsupported vm backend: {other}"
                ))),
            }
        }
        VmCommands::Stop => {
            let mut state = load_vm_state(&state_path)?;
            if state.config.backend == "hyperv" {
                stop_hyperv_vm(&state.config)?;
                state.pid = None;
                state.status = "stopped".to_string();
                save_vm_state(&state_path, &state)?;
                println!("vm: stopped backend=hyperv name={}", state.config.vm_name);
                return Ok(());
            }
            for auxiliary_pid in state.auxiliary_pids.drain(..) {
                if pid_alive(auxiliary_pid) {
                    stop_vm_process(auxiliary_pid)?;
                }
            }
            let Some(pid) = state.pid else {
                state.status = "stopped".to_string();
                save_vm_state(&state_path, &state)?;
                println!("vm: already stopped");
                return Ok(());
            };
            if !pid_alive(pid) {
                state.pid = None;
                state.status = "stopped".to_string();
                save_vm_state(&state_path, &state)?;
                println!("vm: already stopped");
                return Ok(());
            }
            stop_vm_process(pid)?;
            state.pid = None;
            state.status = "stopped".to_string();
            save_vm_state(&state_path, &state)?;
            println!("vm: stopped");
            Ok(())
        }
        VmCommands::Status { json } => {
            let mut state = load_vm_state(&state_path)?;
            if state.config.backend == "hyperv" {
                let running = hyperv_vm_running(&state.config).unwrap_or(false);
                state.status = if running {
                    "running".to_string()
                } else {
                    "stopped".to_string()
                };
                if !running {
                    state.pid = None;
                }
                save_vm_state(&state_path, &state)?;
            } else if let Some(pid) = state.pid {
                if !pid_alive(pid) {
                    state.pid = None;
                    state.status = "stopped".to_string();
                    save_vm_state(&state_path, &state)?;
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&state)?);
            } else {
                println!("vm: status={}", state.status);
                if let Some(pid) = state.pid {
                    println!("vm: pid={pid}");
                }
                if let Some(version) = state.current_version.as_deref() {
                    println!("vm: version={version}");
                }
                println!(
                    "vm: name={} backend={} cpus={} memory_mb={} api_port={} ssh_port={} disk={} host_share={} fs_backend={} virtiofs_socket={} hyperv_switch={} guest_user={} ssh_key={} cloud_init={}",
                    state.config.vm_name,
                    state.config.backend,
                    state.config.cpus,
                    state.config.memory_mb,
                    state.config.api_port,
                    state.config.ssh_port,
                    state.config.disk_path,
                    state.config.host_share_path,
                    state.config.fs_backend,
                    state
                        .config
                        .virtiofs_socket_path
                        .as_deref()
                        .unwrap_or("-"),
                    state.config.hyperv_switch.as_deref().unwrap_or("-"),
                    state.config.guest_user.as_deref().unwrap_or("-"),
                    state.config.ssh_private_key_path.as_deref().unwrap_or("-"),
                    state.config.cloud_init_image_path.as_deref().unwrap_or("-")
                );
            }
            Ok(())
        }
        VmCommands::BridgeApi {
            bind_addr,
            listen_port,
            forward_state_file,
        } => {
            let state = load_vm_state(&state_path)?;
            let forward_state_path = forward_state_file
                .map(PathBuf::from)
                .unwrap_or_else(default_forward_state_path);
            let mut entries = load_forward_entries(&forward_state_path)?;
            upsert_forward_entry(
                &mut entries,
                ForwardEntry {
                    bind_addr: bind_addr.clone(),
                    listen_port,
                    target_host: "127.0.0.1".to_string(),
                    target_port: state.config.api_port,
                    enabled: true,
                },
            );
            save_forward_entries(&forward_state_path, &entries)?;
            println!(
                "vm: api bridge configured {}:{} -> 127.0.0.1:{} (state={})",
                bind_addr,
                listen_port,
                state.config.api_port,
                forward_state_path.display()
            );
            Ok(())
        }
        VmCommands::UpdateCheck {
            manifest_path,
            channel,
            json,
        } => {
            let state = load_vm_state(&state_path)?;
            let manifest = load_channel_manifest(Path::new(&manifest_path))?;
            let release = manifest.channels.get(&channel).ok_or_else(|| {
                DesktopError::Invalid(format!("channel not found in manifest: {channel}"))
            })?;
            let needs_update = state
                .current_version
                .as_ref()
                .map(|v| v != &release.version)
                .unwrap_or(true);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "channel": channel,
                        "current_version": state.current_version,
                        "latest_version": release.version,
                        "image_path": release.image_path,
                        "sha256": release.sha256,
                        "needs_update": needs_update
                    }))?
                );
            } else {
                println!(
                    "vm: channel={} current={} latest={} needs_update={}",
                    channel,
                    state.current_version.as_deref().unwrap_or("unknown"),
                    release.version,
                    needs_update
                );
            }
            Ok(())
        }
        VmCommands::ApplyChannelUpdate {
            manifest_path,
            channel,
            no_backup,
        } => {
            let manifest = load_channel_manifest(Path::new(&manifest_path))?;
            let release = manifest.channels.get(&channel).ok_or_else(|| {
                DesktopError::Invalid(format!("channel not found in manifest: {channel}"))
            })?;
            apply_vm_image_update(
                &state_path,
                Path::new(&release.image_path),
                release.sha256.as_deref(),
                no_backup,
                Some(release.version.clone()),
            )
        }
        VmCommands::RollbackImage => rollback_vm_image_update(&state_path),
        VmCommands::UpdateImage {
            image_path,
            no_backup,
        } => apply_vm_image_update(&state_path, Path::new(&image_path), None, no_backup, None),
    }
}

fn run_autostart_command(command: AutostartCommands) -> Result<(), DesktopError> {
    match command {
        AutostartCommands::InstallMacos { output_path, addr } => {
            let output = output_path
                .map(PathBuf::from)
                .unwrap_or_else(default_macos_launch_agent_path);
            let exe_path = std::env::current_exe()?;
            let content = render_macos_launch_agent_plist(
                "io.ferrocrate.desktop",
                exe_path.to_string_lossy().as_ref(),
                &addr,
            );
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, content)?;
            println!(
                "autostart: wrote macOS launch agent plist at {}",
                output.display()
            );
            Ok(())
        }
        AutostartCommands::InstallWindows { output_path, addr } => {
            let output = output_path
                .map(PathBuf::from)
                .unwrap_or_else(default_windows_service_script_path);
            let exe_path = std::env::current_exe()?;
            let content = render_windows_service_script(
                "FerroDesktop",
                exe_path.to_string_lossy().as_ref(),
                &addr,
            );
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, content)?;
            println!(
                "autostart: wrote Windows service install script at {}",
                output.display()
            );
            Ok(())
        }
    }
}

fn default_macos_launch_agent_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join("Library")
            .join("LaunchAgents")
            .join("io.ferrocrate.desktop.plist");
    }
    PathBuf::from("io.ferrocrate.desktop.plist")
}

fn default_windows_service_script_path() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("ferrocrate")
            .join("install-ferro-desktop-service.ps1");
    }
    PathBuf::from("install-ferro-desktop-service.ps1")
}

fn render_macos_launch_agent_plist(label: &str, ferro_desktop_bin: &str, addr: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
      <string>{ferro_desktop_bin}</string>
      <string>daemon</string>
      <string>--addr</string>
      <string>{addr}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>
"#
    )
}

fn render_windows_service_script(
    service_name: &str,
    ferro_desktop_bin: &str,
    addr: &str,
) -> String {
    format!(
        r#"$ErrorActionPreference = "Stop"
$serviceName = "{service_name}"
$binPath = '"{ferro_desktop_bin}" daemon --addr {addr}'

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {{
  Write-Host "Service already exists: $serviceName"
  exit 0
}}

sc.exe create $serviceName binPath= $binPath start= auto
sc.exe description $serviceName "FerroCrate desktop daemon"
sc.exe start $serviceName
Write-Host "Installed and started service: $serviceName"
"#
    )
}

fn default_vm_state_path() -> PathBuf {
    if let Ok(path) = std::env::var("FERROCRATE_DESKTOP_VM_STATE") {
        return PathBuf::from(path);
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("ferrocrate")
            .join("desktop-vm.json");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".ferrocrate")
            .join("desktop-vm.json");
    }
    PathBuf::from(".ferrocrate").join("desktop-vm.json")
}

fn load_vm_state(path: &Path) -> Result<VmState, DesktopError> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Err(DesktopError::Invalid(format!(
            "vm state file is empty: {}",
            path.display()
        )));
    }
    Ok(serde_json::from_slice::<VmState>(&bytes)?)
}

fn save_vm_state(path: &Path, state: &VmState) -> Result<(), DesktopError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_vec_pretty(state)?;
    fs::write(path, payload)?;
    Ok(())
}

fn load_channel_manifest(path: &Path) -> Result<ChannelManifest, DesktopError> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Err(DesktopError::Invalid(format!(
            "channel manifest is empty: {}",
            path.display()
        )));
    }
    Ok(serde_json::from_slice::<ChannelManifest>(&bytes)?)
}

fn sha256_file(path: &Path) -> Result<String, DesktopError> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn apply_vm_image_update(
    state_path: &Path,
    new_image: &Path,
    expected_sha256: Option<&str>,
    no_backup: bool,
    new_version: Option<String>,
) -> Result<(), DesktopError> {
    let mut state = load_vm_state(state_path)?;
    if !new_image.exists() {
        return Err(DesktopError::Invalid(format!(
            "image path does not exist: {}",
            new_image.display()
        )));
    }
    if state.config.backend == "hyperv" {
        let running = hyperv_vm_running(&state.config).unwrap_or(false);
        if running {
            return Err(DesktopError::Invalid(
                "refusing VM image update while hyperv vm is running; stop vm first".to_string(),
            ));
        }
    } else if let Some(pid) = state.pid {
        if pid_alive(pid) {
            return Err(DesktopError::Invalid(
                "refusing VM image update while vm is running; stop vm first".to_string(),
            ));
        }
    }
    let current_disk = PathBuf::from(&state.config.disk_path);
    if !current_disk.exists() {
        return Err(DesktopError::Invalid(format!(
            "current vm disk path does not exist: {}",
            current_disk.display()
        )));
    }

    if let Some(expected) = expected_sha256 {
        let actual = sha256_file(new_image)?;
        if actual != expected.to_ascii_lowercase() {
            return Err(DesktopError::Invalid(format!(
                "image checksum mismatch: expected={expected} actual={actual}"
            )));
        }
    }

    if !no_backup {
        let backup_path = backup_path_for_disk(&current_disk);
        fs::copy(&current_disk, &backup_path)?;
    }
    fs::copy(new_image, &current_disk)?;
    state.status = "initialized".to_string();
    if let Some(version) = new_version {
        state.current_version = Some(version);
    }
    state.last_error = None;
    save_vm_state(state_path, &state)?;
    println!(
        "vm: image updated from {} to {}",
        new_image.display(),
        current_disk.display()
    );
    Ok(())
}

fn rollback_vm_image_update(state_path: &Path) -> Result<(), DesktopError> {
    let mut state = load_vm_state(state_path)?;
    let current_disk = PathBuf::from(&state.config.disk_path);
    let backup_path = backup_path_for_disk(&current_disk);
    if !backup_path.exists() {
        return Err(DesktopError::Invalid(format!(
            "backup image not found: {}",
            backup_path.display()
        )));
    }
    if state.config.backend == "hyperv" {
        if hyperv_vm_running(&state.config).unwrap_or(false) {
            return Err(DesktopError::Invalid(
                "refusing rollback while hyperv vm is running; stop vm first".to_string(),
            ));
        }
    } else if let Some(pid) = state.pid {
        if pid_alive(pid) {
            return Err(DesktopError::Invalid(
                "refusing rollback while vm is running; stop vm first".to_string(),
            ));
        }
    }
    fs::copy(&backup_path, &current_disk)?;
    state.status = "initialized".to_string();
    state.last_error = None;
    save_vm_state(state_path, &state)?;
    println!(
        "vm: rollback applied from {} to {}",
        backup_path.display(),
        current_disk.display()
    );
    Ok(())
}

fn backup_path_for_disk(disk: &Path) -> PathBuf {
    let mut s = disk.as_os_str().to_string_lossy().to_string();
    s.push_str(".bak");
    PathBuf::from(s)
}

fn start_virtiofs_daemon(config: &VmConfig) -> Result<u32, DesktopError> {
    let socket_path = config.virtiofs_socket_path.as_deref().ok_or_else(|| {
        DesktopError::Invalid("virtiofs backend requires virtiofs_socket_path".to_string())
    })?;
    if fs::metadata(socket_path).is_ok() {
        let _ = fs::remove_file(socket_path);
    }
    let child = Command::new("virtiofsd")
        .arg("--socket-path")
        .arg(socket_path)
        .arg("--shared-dir")
        .arg(&config.host_share_path)
        .arg("--cache")
        .arg("auto")
        .spawn();
    match child {
        Ok(child) => Ok(child.id()),
        Err(err) => Err(DesktopError::Invalid(format!(
            "failed to start virtiofsd: {err}"
        ))),
    }
}

fn wait_for_vfkit_guest_address(
    config: &VmConfig,
    timeout_seconds: u64,
) -> Result<String, DesktopError> {
    let artifact_dir = Path::new(&config.disk_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let mac = fs::read_to_string(artifact_dir.join("vfkit-mac"))
        .unwrap_or_else(|_| "5a:94:ef:e4:0c:ee".to_string());
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_seconds);
    loop {
        if let Ok(leases) = fs::read_to_string("/var/db/dhcpd_leases") {
            if let Some(address) = vfkit_address_from_leases(&leases, mac.trim()) {
                return Ok(address);
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(DesktopError::Invalid(format!(
                "vfkit guest address was not discovered within {timeout_seconds}s"
            )));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn vfkit_address_from_leases(leases: &str, mac: &str) -> Option<String> {
    let mac = mac.to_ascii_lowercase();
    leases.split('}').find_map(|lease| {
        if !lease.to_ascii_lowercase().contains(&mac) {
            return None;
        }
        lease.lines().find_map(|line| {
            line.trim()
                .strip_prefix("ip_address=")
                .map(str::trim)
                .filter(|address| !address.is_empty())
                .map(str::to_string)
        })
    })
}

fn start_vfkit_ssh_forward(config: &VmConfig, guest_address: &str) -> Result<u32, DesktopError> {
    let child = Command::new("socat")
        .arg(format!(
            "TCP-LISTEN:{},bind=127.0.0.1,reuseaddr,fork",
            config.ssh_port
        ))
        .arg(format!("TCP:{guest_address}:22"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child.id())
}

fn start_hyperv_vm(config: &VmConfig) -> Result<(), DesktopError> {
    #[cfg(windows)]
    {
        if hyperv_vm_running(config)? {
            return Ok(());
        }
        // The script text is fixed. Values travel through environment
        // variables so a config field can never be parsed as PowerShell code.
        const SCRIPT: &str = "$name = $env:FERROCRATE_VM_NAME; if (-not (Get-VM -Name $name -ErrorAction SilentlyContinue)) { $mem = [string]$env:FERROCRATE_VM_MEMORY_MB + 'MB'; $cpus = [int]$env:FERROCRATE_VM_CPUS; $vhd = $env:FERROCRATE_VM_VHD; $switch = $env:FERROCRATE_VM_SWITCH; if ([string]::IsNullOrEmpty($switch)) { New-VM -Name $name -Generation 2 -MemoryStartupBytes $mem -VHDPath $vhd | Out-Null } else { New-VM -Name $name -Generation 2 -MemoryStartupBytes $mem -VHDPath $vhd -SwitchName $switch | Out-Null }; Set-VMProcessor -VMName $name -Count $cpus; }; Start-VM -Name $name | Out-Null";
        let status = Command::new("powershell.exe")
            .env("FERROCRATE_VM_NAME", &config.vm_name)
            .env("FERROCRATE_VM_MEMORY_MB", config.memory_mb.to_string())
            .env("FERROCRATE_VM_CPUS", config.cpus.to_string())
            .env("FERROCRATE_VM_VHD", &config.disk_path)
            .env(
                "FERROCRATE_VM_SWITCH",
                config.hyperv_switch.as_deref().unwrap_or(""),
            )
            .args(["-NoProfile", "-Command", SCRIPT])
            .status()?;
        if !status.success() {
            return Err(DesktopError::Invalid(format!(
                "failed to start Hyper-V vm {}",
                config.vm_name
            )));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        Err(DesktopError::Invalid(
            "hyperv backend is only supported on Windows hosts".to_string(),
        ))
    }
}

fn hyperv_vm_running(config: &VmConfig) -> Result<bool, DesktopError> {
    #[cfg(windows)]
    {
        // Fixed script text; the VM name travels through an environment
        // variable and is never parsed as PowerShell code.
        const SCRIPT: &str = "$name = $env:FERROCRATE_VM_NAME; $vm = Get-VM -Name $name -ErrorAction SilentlyContinue; if ($null -eq $vm) { exit 2 }; if ($vm.State -eq 'Running') { exit 0 } else { exit 1 }";
        let status = Command::new("powershell.exe")
            .env("FERROCRATE_VM_NAME", &config.vm_name)
            .args(["-NoProfile", "-Command", SCRIPT])
            .status()?;
        let code = status.code().unwrap_or(1);
        if code == 0 {
            return Ok(true);
        }
        if code == 1 || code == 2 {
            return Ok(false);
        }
        Err(DesktopError::Invalid(format!(
            "failed to query Hyper-V vm state {}",
            config.vm_name
        )))
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        Ok(false)
    }
}

fn stop_hyperv_vm(config: &VmConfig) -> Result<(), DesktopError> {
    #[cfg(windows)]
    {
        // Fixed script text; the VM name travels through an environment
        // variable and is never parsed as PowerShell code.
        const SCRIPT: &str = "$name = $env:FERROCRATE_VM_NAME; if (Get-VM -Name $name -ErrorAction SilentlyContinue) { Stop-VM -Name $name -TurnOff -Force -ErrorAction SilentlyContinue | Out-Null; }";
        let status = Command::new("powershell.exe")
            .env("FERROCRATE_VM_NAME", &config.vm_name)
            .args(["-NoProfile", "-Command", SCRIPT])
            .status()?;
        if !status.success() {
            return Err(DesktopError::Invalid(format!(
                "failed to stop Hyper-V vm {}",
                config.vm_name
            )));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        Err(DesktopError::Invalid(
            "hyperv backend is only supported on Windows hosts".to_string(),
        ))
    }
}

/// Escape a value embedded in a QEMU option string. QEMU parses `,` as an
/// option separator inside a single argv element, so a literal comma must be
/// doubled to remain part of the value. Without this, an operator-configured
/// path containing a comma could alter adjacent drive/chardev/netdev options.
fn qemu_escape_option_value(value: &str) -> String {
    value.replace(',', ",,")
}

fn build_vm_command(config: &VmConfig, forwards: &[ForwardEntry]) -> Result<Command, DesktopError> {
    if config.backend == "vfkit" {
        return build_vfkit_command(config);
    }
    let qemu_bin = match config.backend.as_str() {
        "qemu-hvf" | "qemu-tcg-aarch64" => "qemu-system-aarch64",
        "qemu-x86_64" | "qemu-tcg-x86_64" => "qemu-system-x86_64",
        other => {
            return Err(DesktopError::Invalid(format!(
                "unsupported vm backend: {other}"
            )))
        }
    };
    let mut cmd = Command::new(qemu_bin);
    let software_emulation = config.backend.starts_with("qemu-tcg-");
    if software_emulation {
        cmd.arg("-accel").arg("tcg");
    } else if cfg!(target_os = "macos") {
        cmd.arg("-accel").arg("hvf");
    }
    if cfg!(target_os = "macos") {
        cmd.arg("-display").arg("none");
    }
    let x86_64 = matches!(config.backend.as_str(), "qemu-x86_64" | "qemu-tcg-x86_64");
    let machine = if x86_64 { "q35" } else { "virt" };
    if let Some((code, vars)) = find_uefi_firmware(config.backend.as_str()) {
        if let Some(vars_path) = vars {
            cmd.arg("-drive")
                .arg(format!(
                    "if=pflash,format=raw,readonly=on,file={}",
                    qemu_escape_option_value(&code.display().to_string())
                ))
                .arg("-drive")
                .arg(format!(
                    "if=pflash,format=raw,file={}",
                    qemu_escape_option_value(&vars_path.display().to_string())
                ));
        } else if !x86_64 {
            cmd.arg("-bios").arg(code);
        }
    }
    let mut host_forward_specs = vec![format!("hostfwd=tcp:127.0.0.1:{}-:22", config.ssh_port)];
    let mut used_bind_ports = HashSet::new();
    used_bind_ports.insert(("127.0.0.1".to_string(), config.ssh_port));
    for entry in forwards {
        if !is_loopback_host(&entry.target_host) {
            continue;
        }
        let bind_addr = if entry.bind_addr.trim().is_empty() {
            "127.0.0.1".to_string()
        } else {
            qemu_escape_option_value(entry.bind_addr.trim())
        };
        if used_bind_ports.contains(&(bind_addr.clone(), entry.listen_port)) {
            continue;
        }
        host_forward_specs.push(format!(
            "hostfwd=tcp:{}:{}-:{}",
            bind_addr, entry.listen_port, entry.target_port
        ));
        used_bind_ports.insert((bind_addr, entry.listen_port));
    }
    let netdev = format!("user,id=net0,{}", host_forward_specs.join(","));
    cmd.arg("-machine")
        .arg(machine)
        .arg("-cpu")
        .arg(if software_emulation { "max" } else { "host" })
        .arg("-smp")
        .arg(config.cpus.to_string())
        .arg("-m")
        .arg(config.memory_mb.to_string())
        .arg("-drive")
        .arg(format!(
            "file={},if=virtio,format=qcow2",
            qemu_escape_option_value(&config.disk_path)
        ))
        .arg("-netdev")
        .arg(netdev)
        .arg("-device")
        .arg("virtio-net-pci,netdev=net0");
    if let Some(cloud_init) = config.cloud_init_image_path.as_deref() {
        cmd.arg("-drive").arg(format!(
            "file={},if=virtio,media=cdrom,readonly=on,format=raw",
            qemu_escape_option_value(cloud_init)
        ));
    }
    match config.fs_backend.as_str() {
        "virtiofs" => {
            let socket_path = config.virtiofs_socket_path.as_deref().ok_or_else(|| {
                DesktopError::Invalid(
                    "virtiofs backend requires virtiofs_socket_path in vm config".to_string(),
                )
            })?;
            cmd.arg("-chardev")
                .arg(format!(
                    "socket,id=vfs0,path={}",
                    qemu_escape_option_value(socket_path)
                ))
                .arg("-device")
                .arg("vhost-user-fs-pci,chardev=vfs0,tag=ferrohost");
        }
        "9p" => {
            cmd.arg("-virtfs").arg(format!(
                "local,path={},mount_tag=ferrohost,security_model=none",
                qemu_escape_option_value(&config.host_share_path)
            ));
        }
        other => {
            return Err(DesktopError::Invalid(format!(
                "unsupported fs backend: {other}"
            )))
        }
    }
    Ok(cmd)
}

fn build_vfkit_command(config: &VmConfig) -> Result<Command, DesktopError> {
    if config.fs_backend != "virtiofs" {
        return Err(DesktopError::Invalid(
            "vfkit requires the virtiofs filesystem backend".to_string(),
        ));
    }
    let artifact_dir = Path::new(&config.disk_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let kernel = artifact_dir.join("vfkit-kernel");
    let initrd = artifact_dir.join("vfkit-initrd");
    let mac = fs::read_to_string(artifact_dir.join("vfkit-mac"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "5a:94:ef:e4:0c:ee".to_string());
    let mut command = Command::new("vfkit");
    command
        .arg("--cpus")
        .arg(config.cpus.to_string())
        .arg("--memory")
        .arg(config.memory_mb.to_string())
        .arg("--bootloader")
        .arg(format!(
            "linux,kernel={},initrd={},cmdline=console=hvc0 root=/dev/vda1",
            kernel.display(),
            initrd.display()
        ))
        .arg("--device")
        .arg(format!("virtio-blk,path={}", config.disk_path))
        .arg("--device")
        .arg(format!(
            "virtio-fs,sharedDir={},mountTag=ferrohost",
            config.host_share_path
        ))
        .arg("--device")
        .arg(format!("virtio-net,nat,mac={mac}"));
    if let Some(cloud_init) = config.cloud_init_image_path.as_deref() {
        command
            .arg("--device")
            .arg(format!("virtio-blk,path={cloud_init}"));
    }
    Ok(command)
}

fn find_uefi_firmware(backend: &str) -> Option<(PathBuf, Option<PathBuf>)> {
    let candidates = if matches!(backend, "qemu-x86_64" | "qemu-tcg-x86_64") {
        vec![
            ("OVMF_CODE.fd", Some("OVMF_VARS.fd")),
            ("edk2-x86_64-code.fd", Some("edk2-x86_64-vars.fd")),
        ]
    } else {
        vec![
            ("edk2-aarch64-code.fd", Some("edk2-aarch64-vars.fd")),
            ("edk2-aarch64-code.fd", None),
        ]
    };
    let roots = ["/usr/local/share/qemu", "/opt/homebrew/share/qemu"];
    for (code_name, vars_name) in candidates {
        for root in roots {
            let code = Path::new(root).join(code_name);
            if !code.exists() {
                continue;
            }
            let vars = vars_name.and_then(|name| {
                let vars_path = Path::new(root).join(name);
                vars_path.exists().then_some(vars_path)
            });
            return Some((code, vars));
        }
    }
    None
}

fn is_loopback_host(value: &str) -> bool {
    let lowered = value.trim().to_ascii_lowercase();
    lowered == "127.0.0.1" || lowered == "localhost" || lowered == "::1"
}

fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[cfg(any(windows, test))]
fn decode_wsl_output(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.contains(&0) {
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
        return String::from_utf16_lossy(&units.collect::<Vec<_>>())
            .trim_start_matches('\u{feff}')
            .to_string();
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn gather_phase0_check(wsl_distro: Option<String>) -> Result<Phase0CheckResult, DesktopError> {
    #[cfg(windows)]
    {
        let output = Command::new("wsl.exe").args(["-l", "-q"]).output()?;
        let status = output.status.code();
        let distros = decode_wsl_output(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        let requested_available = wsl_distro
            .as_ref()
            .map(|name| distros.iter().any(|d| d == name));

        let selected = match (&wsl_distro, requested_available) {
            (Some(name), Some(true)) => Some(name.clone()),
            (Some(_), Some(false)) => distros.first().cloned(),
            (None, _) => distros.first().cloned(),
            _ => None,
        };

        let mut check = Phase0CheckResult {
            host_os: std::env::consts::OS.to_string(),
            wsl_detected: true,
            wsl_list_status: status,
            wsl_distros: distros,
            requested_distro: wsl_distro,
            requested_available,
            selected_distro: selected.clone(),
            ferrocrate_present_in_guest: None,
            guest_kernel: None,
            notes: Vec::new(),
        };

        if let Some(distro) = selected {
            let probe = Command::new("wsl.exe")
                .args([
                    "--distribution",
                    &distro,
                    "--",
                    "sh",
                    "-lc",
                    "uname -r; command -v ferrocrate >/dev/null && echo FC_PRESENT=1 || echo FC_PRESENT=0",
                ])
                .output()?;
            let text = decode_wsl_output(&probe.stdout);
            let mut lines = text.lines();
            check.guest_kernel = lines.next().map(ToOwned::to_owned);
            let found = lines.any(|line| line.trim() == "FC_PRESENT=1");
            check.ferrocrate_present_in_guest = Some(found);
            if !found {
                check
                    .notes
                    .push("ferrocrate binary not found in selected WSL distro".to_string());
            }
        } else {
            check
                .notes
                .push("no WSL distro available; install/import distro first".to_string());
        }

        Ok(check)
    }

    #[cfg(not(windows))]
    {
        Ok(Phase0CheckResult {
            host_os: std::env::consts::OS.to_string(),
            wsl_detected: false,
            wsl_list_status: None,
            wsl_distros: Vec::new(),
            requested_distro: wsl_distro,
            requested_available: None,
            selected_distro: None,
            ferrocrate_present_in_guest: None,
            guest_kernel: None,
            notes: vec!["WSL checks are available only on Windows hosts".to_string()],
        })
    }
}

fn backend_exec_request(cmd: &[String]) -> Result<BackendExecRequest, DesktopError> {
    let (program, args) = cmd
        .split_first()
        .ok_or_else(|| DesktopError::Invalid("command is required".to_string()))?;
    Ok(BackendExecRequest::new(program.clone())
        .args(args.iter().cloned())
        .env("FERROCRATE_DESKTOP_FORWARD", "0")
        .env("RUST_LOG", "error")
        .env("FERROCRATE_LOG", "error")
        .env("NO_COLOR", "1"))
}

fn select_exec_backend(_cmd: &[String]) -> Result<Box<dyn Backend>, DesktopError> {
    #[cfg(target_os = "macos")]
    if !should_route_to_macos_guest(_cmd, exec_mode_from_env()) {
        return Ok(Box::new(LinuxNativeBackend::new(
            LinuxNativeConfig::default(),
        )));
    }

    #[cfg(windows)]
    {
        Ok(Box::new(LinuxNativeBackend::new(
            LinuxNativeConfig::default(),
        )))
    }

    #[cfg(not(windows))]
    {
        select_backend().map_err(|error| DesktopError::Invalid(error.to_string()))
    }
}

fn run_request(
    request: &ExecRequest,
) -> Result<ferro_desktop::backend::ExecResponse, DesktopError> {
    let backend = select_exec_backend(&request.cmd)?;
    backend
        .exec(backend_exec_request(&request.cmd)?)
        .map_err(|error| DesktopError::Invalid(error.to_string()))
}

fn run_follow_request(
    request: &ExecRequest,
) -> Result<Box<dyn ferro_desktop::backend::ExecStream>, DesktopError> {
    let backend = select_exec_backend(&request.cmd)?;
    backend
        .exec_stream(backend_exec_request(&request.cmd)?)
        .map_err(|error| DesktopError::Invalid(error.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum ExecMode {
    Auto,
    Host,
    Guest,
}

#[allow(dead_code)]
fn exec_mode_from_env() -> ExecMode {
    let value = std::env::var("FERROCRATE_DESKTOP_EXEC_MODE").ok();
    parse_exec_mode(value.as_deref())
}

#[allow(dead_code)]
fn parse_exec_mode(value: Option<&str>) -> ExecMode {
    match value.unwrap_or("auto").to_ascii_lowercase().as_str() {
        "host" | "local" => ExecMode::Host,
        "guest" | "vm" => ExecMode::Guest,
        _ => ExecMode::Auto,
    }
}

#[allow(dead_code)]
fn should_route_to_macos_guest(cmd: &[String], mode: ExecMode) -> bool {
    match mode {
        ExecMode::Host => false,
        ExecMode::Guest => true,
        ExecMode::Auto => command_targets_ferrocrate(cmd),
    }
}

#[allow(dead_code)]
fn command_targets_ferrocrate(cmd: &[String]) -> bool {
    let Some(program) = cmd.first() else {
        return false;
    };
    let basename = Path::new(program)
        .components()
        .next_back()
        .map(|component| match component {
            Component::Normal(value) => value.to_string_lossy().to_string(),
            _ => program.clone(),
        })
        .unwrap_or_else(|| program.clone())
        .to_ascii_lowercase();
    matches!(
        basename.as_str(),
        "ferrocrate" | "ferro-cli" | "ferro-cli.exe" | "ferrocrate.exe"
    )
}

fn is_log_follow_command(cmd: &[String]) -> bool {
    command_targets_ferrocrate(cmd)
        && cmd.get(1).is_some_and(|subcommand| subcommand == "logs")
        && cmd[2..]
            .iter()
            .any(|argument| argument == "--follow" || argument == "-f")
}

fn is_interactive_exec_command(cmd: &[String]) -> bool {
    if !command_targets_ferrocrate(cmd) || cmd.get(1).is_none_or(|subcommand| subcommand != "exec")
    {
        return false;
    }
    let arguments = &cmd[2..];
    let interactive = arguments.iter().any(|argument| {
        argument == "--interactive"
            || argument == "-i"
            || (argument.starts_with('-') && !argument.starts_with("--") && argument.contains('i'))
    });
    let tty = arguments.iter().any(|argument| {
        argument == "--tty"
            || argument == "-t"
            || (argument.starts_with('-') && !argument.starts_with("--") && argument.contains('t'))
    });
    interactive && tty
}

#[allow(dead_code)]
fn vm_state_running(state: &VmState) -> bool {
    if state.status.eq_ignore_ascii_case("running") {
        return true;
    }
    state.pid.map(pid_alive).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::ensure_ssh_key;
    #[cfg(windows)]
    use super::select_exec_backend;
    use super::{
        backend_exec_request, backup_path_for_disk, build_vm_command, command_exists,
        command_requires_desktop_entitlement, command_targets_ferrocrate, container_proxy_request,
        copy_interactive_input, decode_wsl_output, desktop_addr_default_from, exec_mode_from_env,
        gather_phase0_check, is_interactive_exec_command, is_log_follow_command,
        load_channel_manifest, load_forward_entries, load_vm_state, network_proxy_request,
        parse_exec_mode, process_exec_request, read_exec_request, registry_login_request,
        render_macos_launch_agent_plist, render_windows_service_script, replay_follow_frames,
        run_request, save_forward_entries, save_vm_state, should_route_to_macos_guest,
        ssh_keygen_generate_args, terminal_exec_create_path, terminal_exec_create_payload,
        terminal_resize_path, upsert_forward_entry, validate_daemon_addr, vm_state_running,
        volume_proxy_request, write_follow_frame, Cli, Commands, ExecMode, ExecRequest,
        FollowChannel, FollowFrame, ForwardCommands, ForwardEntry, VmCommands, VmConfig, VmState,
    };
    #[cfg(target_os = "linux")]
    use super::{
        create_terminal_exec, daemon_health_response_ok, ferrocrate_daemon_command,
        ferrocrate_socket_candidates, open_terminal_exec, resize_terminal_exec,
        select_terminal_socket,
    };
    use clap::Parser;
    use std::io::{BufRead, BufReader, Cursor, Read, Write};
    use std::path::Path;

    #[test]
    fn cli_exec_consumer_builds_one_backend_program_request() {
        let request = backend_exec_request(&[
            "ferrocrate".into(),
            "images".into(),
            "--format".into(),
            "json".into(),
        ])
        .unwrap();
        assert_eq!(request.program, "ferrocrate");
        assert_eq!(request.args, ["images", "--format", "json"]);
    }
    use std::path::PathBuf;

    #[cfg(target_os = "linux")]
    fn read_test_http_request(stream: &mut std::os::unix::net::UnixStream) -> (String, Vec<u8>) {
        let mut reader = BufReader::new(stream);
        let mut headers = String::new();
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("request header");
            if line == "\r\n" {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                if key.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().expect("content length");
                }
            }
            headers.push_str(&line);
        }
        let mut body = vec![0_u8; content_length];
        reader.read_exact(&mut body).expect("request body");
        (headers, body)
    }

    #[test]
    fn parses_typed_terminal_proxy_commands() {
        assert!(Cli::try_parse_from([
            "ferro-desktop",
            "terminal-proxy",
            "--socket",
            "/tmp/ferrocrate.sock",
            "--container",
            "web",
            "--env",
            "TERM=xterm-256color",
            "--user",
            "1000:1000",
            "--workdir",
            "/workspace",
            "--",
            "sh",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "ferro-desktop",
            "terminal-resize",
            "--socket",
            "/tmp/ferrocrate.sock",
            "--exec-id",
            "exec-1",
            "--columns",
            "100",
            "--rows",
            "40",
        ])
        .is_ok());
    }

    #[test]
    fn volume_proxy_builds_bounded_daemon_requests() {
        assert_eq!(
            volume_proxy_request(&super::VolumeProxyCommands::List).expect("list request"),
            ("GET", "/volumes".to_string(), Vec::new())
        );
        assert_eq!(
            volume_proxy_request(&super::VolumeProxyCommands::Create {
                name: "data/blue".to_string()
            })
            .expect("create request"),
            (
                "POST",
                "/volumes/create".to_string(),
                br#"{"Driver":"local","Name":"data/blue"}"#.to_vec()
            )
        );
        assert_eq!(
            volume_proxy_request(&super::VolumeProxyCommands::Remove {
                name: "data/blue".to_string()
            })
            .expect("remove request"),
            ("DELETE", "/volumes/data%2Fblue".to_string(), Vec::new())
        );
        assert_eq!(
            volume_proxy_request(&super::VolumeProxyCommands::Prune).expect("prune request"),
            ("POST", "/volumes/prune".to_string(), Vec::new())
        );
    }

    #[test]
    fn network_proxy_builds_bounded_daemon_requests() {
        assert_eq!(
            network_proxy_request(&super::NetworkProxyCommands::List).expect("list request"),
            ("GET", "/networks".to_string(), Vec::new())
        );
        assert_eq!(
            network_proxy_request(&super::NetworkProxyCommands::Inspect {
                name: "team/net".to_string(),
            })
            .expect("inspect request"),
            ("GET", "/networks/team%2Fnet".to_string(), Vec::new())
        );
        assert_eq!(
            network_proxy_request(&super::NetworkProxyCommands::Create {
                name: "frontend".to_string(),
                subnet: Some("172.30.0.0/16".to_string()),
            })
            .expect("create request"),
            (
                "POST",
                "/networks/create".to_string(),
                br#"{"Driver":"bridge","IPAM":{"Config":[{"Subnet":"172.30.0.0/16"}]},"Name":"frontend"}"#.to_vec(),
            )
        );
        assert_eq!(
            network_proxy_request(&super::NetworkProxyCommands::Remove {
                name: "frontend".to_string(),
            })
            .expect("remove request"),
            ("DELETE", "/networks/frontend".to_string(), Vec::new())
        );
        assert!(network_proxy_request(&super::NetworkProxyCommands::Create {
            name: " ".to_string(),
            subnet: None,
        })
        .is_err());
    }

    #[test]
    fn container_proxy_builds_inspect_and_resource_update_requests() {
        assert_eq!(
            container_proxy_request(&super::ContainerProxyCommands::Inspect {
                container: "web/api".to_string(),
            })
            .expect("inspect request"),
            ("GET", "/containers/web%2Fapi/json".to_string(), Vec::new())
        );
        assert_eq!(
            container_proxy_request(&super::ContainerProxyCommands::Update {
                container: "web".to_string(),
                memory: Some(134_217_728),
                cpu_quota: Some(50_000),
                cpu_period: Some(100_000),
            })
            .expect("update request"),
            (
                "POST",
                "/containers/web/update".to_string(),
                br#"{"CpuPeriod":100000,"CpuQuota":50000,"Memory":134217728}"#.to_vec(),
            )
        );
        assert!(
            container_proxy_request(&super::ContainerProxyCommands::Update {
                container: " ".to_string(),
                memory: None,
                cpu_quota: None,
                cpu_period: None,
            })
            .is_err()
        );
    }

    #[test]
    fn registry_login_proxy_builds_daemon_auth_request_without_argv_password() {
        assert_eq!(
            registry_login_request("registry.example.com", "alice", "secret")
                .expect("auth request"),
            (
                "POST",
                "/auth".to_string(),
                br#"{"password":"secret","serveraddress":"registry.example.com","username":"alice"}"#.to_vec(),
            )
        );
        assert!(registry_login_request("registry.example.com", " ", "secret").is_err());
        assert!(registry_login_request("registry.example.com", "alice", "").is_err());
    }

    #[test]
    fn terminal_proxy_builds_typed_exec_create_payload() {
        let payload = terminal_exec_create_payload(
            &["sh".to_string()],
            &["TERM=xterm-256color".to_string()],
            Some("1000:1000"),
            Some("/workspace"),
        )
        .expect("exec payload");
        let payload: serde_json::Value = serde_json::from_slice(&payload).expect("payload JSON");

        assert_eq!(payload["Cmd"], serde_json::json!(["sh"]));
        assert_eq!(payload["AttachStdin"], true);
        assert_eq!(payload["AttachStdout"], true);
        assert_eq!(payload["AttachStderr"], true);
        assert_eq!(payload["Tty"], true);
        assert_eq!(payload["Env"], serde_json::json!(["TERM=xterm-256color"]));
        assert_eq!(payload["User"], "1000:1000");
        assert_eq!(payload["WorkingDir"], "/workspace");
    }

    #[test]
    fn terminal_proxy_percent_encodes_daemon_resource_paths() {
        assert_eq!(
            terminal_exec_create_path("web/name"),
            "/containers/web%2Fname/exec"
        );
        assert_eq!(
            terminal_resize_path("exec/id", 100, 40),
            "/exec/exec%2Fid/resize?w=100&h=40"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_proxy_creates_exec_through_daemon_socket() {
        let temp = tempfile::tempdir().expect("tempdir");
        let socket = temp.path().join("ferrocrate.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept create");
            let (headers, body) = read_test_http_request(&mut stream);
            assert!(headers.starts_with("POST /containers/web%2Fblue/exec HTTP/1.1\r\n"));
            let payload: serde_json::Value = serde_json::from_slice(&body).expect("create JSON");
            assert_eq!(payload["Cmd"], serde_json::json!(["sh"]));
            assert_eq!(payload["Env"], serde_json::json!(["TERM=xterm-256color"]));
            stream
                .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 15\r\n\r\n{\"Id\":\"exec-1\"}")
                .expect("create response");
        });

        let exec_id = create_terminal_exec(
            &socket,
            "web/blue",
            &["sh".to_string()],
            &["TERM=xterm-256color".to_string()],
            None,
            None,
        )
        .expect("create terminal exec");

        assert_eq!(exec_id, "exec-1");
        server.join().expect("server");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_proxy_opens_hijack_and_resizes_exec() {
        let temp = tempfile::tempdir().expect("tempdir");
        let socket = temp.path().join("ferrocrate.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
        let server = std::thread::spawn(move || {
            let (mut start, _) = listener.accept().expect("accept start");
            let (headers, body) = read_test_http_request(&mut start);
            assert!(headers.starts_with("POST /exec/exec%2F1/start HTTP/1.1\r\n"));
            assert!(headers.contains("Connection: Upgrade\r\n"));
            assert_eq!(body, br#"{"Detach":false,"Tty":true}"#);
            start
                .write_all(
                    b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\nready",
                )
                .expect("hijack response");

            let (mut resize, _) = listener.accept().expect("accept resize");
            let (headers, body) = read_test_http_request(&mut resize);
            assert!(headers.starts_with("POST /exec/exec%2F1/resize?w=100&h=40 HTTP/1.1\r\n"));
            assert!(body.is_empty());
            resize
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .expect("resize response");
        });

        let mut hijack = open_terminal_exec(&socket, "exec/1").expect("open terminal exec");
        let mut ready = [0_u8; 5];
        hijack
            .read_exact(&mut ready)
            .expect("initial terminal output");
        assert_eq!(&ready, b"ready");
        resize_terminal_exec(&socket, "exec/1", 100, 40).expect("resize terminal exec");
        server.join().expect("server");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_proxy_requires_an_actual_daemon_socket() {
        let temp = tempfile::tempdir().expect("tempdir");
        let regular = temp.path().join("regular");
        std::fs::write(&regular, b"not a socket").expect("regular file");
        let error = select_terminal_socket(Some(regular.to_str().expect("path")))
            .expect_err("regular file must be rejected");
        assert!(error.to_string().contains("not a Unix socket"));

        let socket = temp.path().join("ferrocrate.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
        assert_eq!(
            select_terminal_socket(Some(socket.to_str().expect("path"))).expect("daemon socket"),
            socket
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn desktop_socket_candidates_never_include_docker_engine_paths() {
        let candidates = ferrocrate_socket_candidates(
            None,
            Some("/tmp/explicit-ferrocrate.sock"),
            Some(PathBuf::from("/tmp/ferro-runtime")),
            Some(PathBuf::from("/run/user/1000")),
        );
        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/tmp/explicit-ferrocrate.sock"),
                PathBuf::from("/tmp/ferro-runtime/ferrocrate.sock"),
                PathBuf::from("/run/user/1000/ferrocrate.sock"),
            ]
        );
        assert!(candidates.iter().all(|path| !path.ends_with("docker.sock")));
        assert!(!candidates
            .iter()
            .any(|path| path == std::path::Path::new("/var/run/docker.sock")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn desktop_daemon_starts_real_rootless_api_daemon() {
        assert_eq!(
            ferrocrate_daemon_command(std::path::Path::new("/run/user/1000/ferrocrate.sock")),
            vec![
                "daemon".to_string(),
                "--socket".to_string(),
                "/run/user/1000/ferrocrate.sock".to_string(),
                "--docker-compat".to_string(),
            ]
        );
        assert!(daemon_health_response_ok(
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK\n"
        ));
        assert!(!daemon_health_response_ok(
            "HTTP/1.1 500 Internal Server Error\r\n\r\nOK\n"
        ));
    }

    #[test]
    fn command_exists_treats_binary_name_as_literal_argv() {
        assert!(command_exists("rustc"));
        assert!(command_exists("sh"));
        assert!(command_exists("ssh-keygen"));
        assert!(!command_exists("rustc; printf injected"));
    }

    #[test]
    fn decodes_wsl_utf16_output_without_embedded_nuls() {
        let encoded = "Ubuntu\r\nDebian\r\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();

        assert_eq!(decode_wsl_output(&encoded), "Ubuntu\r\nDebian\r\n");
        assert_eq!(decode_wsl_output(b"Ubuntu\n"), "Ubuntu\n");
    }

    #[test]
    fn executes_local_command() {
        #[cfg(windows)]
        let cmd = vec![
            "cmd.exe".to_string(),
            "/C".to_string(),
            "echo ok".to_string(),
        ];
        #[cfg(not(windows))]
        let cmd = vec!["sh".to_string(), "-c".to_string(), "echo ok".to_string()];
        let req = ExecRequest {
            cmd,
            use_wsl: false,
            wsl_distro: None,
            follow: false,
            interactive: false,
        };
        let out = run_request(&req).expect("run command");
        assert_eq!(out.code, 0);
        assert!(String::from_utf8_lossy(&out.stdout).contains("ok"));

        #[cfg(windows)]
        {
            let failed = ExecRequest {
                cmd: vec![
                    "cmd.exe".to_string(),
                    "/C".to_string(),
                    "exit 23".to_string(),
                ],
                ..req
            };
            assert_eq!(run_request(&failed).expect("run command").code, 23);
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn a_default_wsl_distro_forces_direct_guest_execution() {
        let request = ExecRequest {
            cmd: vec!["printf".to_string(), "must-not-run-on-host".to_string()],
            use_wsl: false,
            wsl_distro: None,
            follow: false,
            interactive: false,
        };

        let error = process_exec_request(request, Some("Ubuntu"))
            .expect_err("a named-pipe request must route directly to WSL");

        assert!(error
            .to_string()
            .contains("WSL execution is only available on Windows hosts"));
    }

    #[test]
    fn proxied_commands_disable_color_and_warning_noise() {
        #[cfg(windows)]
        let cmd = vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "Write-Output ($env:RUST_LOG + '|' + $env:FERROCRATE_LOG + '|' + $env:NO_COLOR)"
                .to_string(),
        ];
        #[cfg(not(windows))]
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf '%s|%s|%s' \"$RUST_LOG\" \"$FERROCRATE_LOG\" \"$NO_COLOR\"".to_string(),
        ];
        let req = ExecRequest {
            cmd,
            use_wsl: false,
            wsl_distro: None,
            follow: false,
            interactive: false,
        };
        let out = run_request(&req).expect("run command");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "error|error|1");
    }

    #[cfg(windows)]
    #[test]
    fn local_windows_commands_bypass_the_wsl_backend() {
        assert_eq!(
            select_exec_backend(&["cmd.exe".to_string()])
                .expect("local backend")
                .name(),
            "linux-native"
        );
    }

    #[test]
    fn rejects_empty_local_command() {
        let req = ExecRequest {
            cmd: vec![],
            use_wsl: false,
            wsl_distro: None,
            follow: false,
            interactive: false,
        };
        let err = run_request(&req).expect_err("should fail");
        assert!(err.to_string().contains("command is required"));
    }

    #[test]
    fn follow_proxy_only_accepts_ferrocrate_logs_with_follow_flag() {
        assert!(is_log_follow_command(&[
            "ferrocrate".to_string(),
            "logs".to_string(),
            "--follow".to_string(),
            "web".to_string(),
        ]));
        assert!(!is_log_follow_command(&[
            "ferrocrate".to_string(),
            "logs".to_string(),
            "web".to_string(),
        ]));
        assert!(!is_log_follow_command(&[
            "ferrocrate".to_string(),
            "ps".to_string(),
            "--follow".to_string(),
        ]));
    }

    #[test]
    fn interactive_proxy_only_accepts_ferrocrate_exec_with_stdin_and_tty() {
        assert!(is_interactive_exec_command(&[
            "ferrocrate".to_string(),
            "exec".to_string(),
            "-i".to_string(),
            "-t".to_string(),
            "web".to_string(),
            "sh".to_string(),
        ]));
        assert!(is_interactive_exec_command(&[
            "ferrocrate".to_string(),
            "exec".to_string(),
            "-it".to_string(),
            "web".to_string(),
            "sh".to_string(),
        ]));
        assert!(!is_interactive_exec_command(&[
            "ferrocrate".to_string(),
            "exec".to_string(),
            "web".to_string(),
            "sh".to_string(),
        ]));
        assert!(!is_interactive_exec_command(&[
            "sh".to_string(),
            "-i".to_string(),
        ]));
    }

    #[test]
    fn interactive_proxy_forwards_terminal_input_without_text_decoding() {
        let input = Cursor::new(vec![b'e', b'c', b'h', b'o', b' ', 0xff, b'\n']);
        let mut output = Vec::new();

        copy_interactive_input(input, &mut output).expect("forward input");

        assert_eq!(output, vec![b'e', b'c', b'h', b'o', b' ', 0xff, b'\n']);
    }

    #[test]
    fn interactive_request_reader_preserves_input_sent_after_header() {
        let mut wire = Cursor::new(
            b"{\"cmd\":[\"ferrocrate\",\"exec\",\"-it\",\"web\",\"sh\"],\"use_wsl\":false,\"wsl_distro\":null,\"interactive\":true}\necho ready\n"
                .to_vec(),
        );

        let request = read_exec_request(&mut wire).expect("request header");
        let mut input = Vec::new();
        wire.read_to_end(&mut input).expect("remaining input");

        assert!(request.interactive);
        assert_eq!(input, b"echo ready\n");
    }

    #[test]
    fn framed_follow_replays_channels_and_fails_nonzero_terminal_status() {
        let mut wire = Vec::new();
        write_follow_frame(
            &mut wire,
            &FollowFrame::Data {
                channel: FollowChannel::Stdout,
                data: b"ready\n".to_vec(),
            },
        )
        .expect("stdout frame");
        write_follow_frame(
            &mut wire,
            &FollowFrame::Data {
                channel: FollowChannel::Stderr,
                data: b"warning\n".to_vec(),
            },
        )
        .expect("stderr frame");
        write_follow_frame(&mut wire, &FollowFrame::Terminal { status: 17 })
            .expect("terminal frame");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err = replay_follow_frames(BufReader::new(Cursor::new(wire)), &mut stdout, &mut stderr)
            .expect_err("nonzero terminal status must fail the client");

        assert_eq!(stdout, b"ready\n");
        assert_eq!(stderr, b"warning\n");
        assert!(err.to_string().contains("status 17"));
    }

    #[test]
    fn follow_frames_preserve_multibyte_utf8_split_across_reads() {
        let mut wire = Vec::new();
        write_follow_frame(
            &mut wire,
            &FollowFrame::Data {
                channel: FollowChannel::Stdout,
                data: b"cost: \xe2".to_vec(),
            },
        )
        .expect("first byte frame");
        write_follow_frame(
            &mut wire,
            &FollowFrame::Data {
                channel: FollowChannel::Stdout,
                data: b"\x82\xac\n".to_vec(),
            },
        )
        .expect("second byte frame");
        write_follow_frame(&mut wire, &FollowFrame::Terminal { status: 0 })
            .expect("terminal frame");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        replay_follow_frames(BufReader::new(Cursor::new(wire)), &mut stdout, &mut stderr)
            .expect("successful terminal status");

        assert_eq!(stdout, b"cost: \xe2\x82\xac\n");
        assert!(stderr.is_empty());
    }

    #[test]
    fn daemon_addr_is_loopback_by_default() {
        assert!(validate_daemon_addr("127.0.0.1:4288", false).is_ok());
        assert!(validate_daemon_addr("localhost:4288", false).is_ok());
        assert!(validate_daemon_addr("[::1]:4288", false).is_ok());
        assert!(validate_daemon_addr("0.0.0.0:4288", false).is_err());
        assert!(validate_daemon_addr("192.168.1.10:4288", false).is_err());
    }

    #[test]
    fn desktop_addr_default_accepts_an_isolated_proxy_override() {
        assert_eq!(
            desktop_addr_default_from(Some("127.0.0.1:4399".into())),
            "127.0.0.1:4399"
        );
        assert_eq!(desktop_addr_default_from(None), "127.0.0.1:4288");
    }

    #[test]
    fn daemon_addr_remote_allowed_with_flag() {
        assert!(validate_daemon_addr("0.0.0.0:4288", true).is_ok());
    }

    #[test]
    fn desktop_entitlement_gate_applies_to_runtime_commands() {
        assert!(command_requires_desktop_entitlement(&Commands::Daemon {
            addr: "127.0.0.1:4288".to_string(),
            pipe_name: None,
            wsl_distro: None,
            allow_remote: false,
        }));
        assert!(command_requires_desktop_entitlement(&Commands::Forward {
            state_file: None,
            json: false,
            command: ForwardCommands::List,
        }));
        assert!(command_requires_desktop_entitlement(&Commands::Vm {
            state_file: None,
            command: Box::new(VmCommands::Status { json: true }),
        }));
        assert!(command_requires_desktop_entitlement(
            &Commands::BackendSmoke {
                start: true,
                json: true,
            }
        ));
        assert!(!command_requires_desktop_entitlement(&Commands::Doctor {
            wsl_distro: None,
        }));
        assert!(!command_requires_desktop_entitlement(
            &Commands::Phase0Check {
                wsl_distro: None,
                json: false,
            }
        ));
    }

    #[test]
    fn phase0_check_runs_on_current_host() {
        let result = gather_phase0_check(None).expect("phase0 check");
        assert!(!result.host_os.is_empty());
    }

    #[test]
    fn detects_ferrocrate_program_names() {
        assert!(command_targets_ferrocrate(&["ferrocrate".to_string()]));
        assert!(command_targets_ferrocrate(&[
            "/usr/local/bin/ferro-cli".to_string()
        ]));
        assert!(!command_targets_ferrocrate(&[
            "echo".to_string(),
            "ok".to_string()
        ]));
    }

    #[test]
    fn guest_routing_mode_logic_is_stable() {
        let fc = vec!["ferrocrate".to_string(), "run".to_string()];
        let echo = vec!["echo".to_string(), "ok".to_string()];
        assert!(should_route_to_macos_guest(&fc, ExecMode::Auto));
        assert!(!should_route_to_macos_guest(&echo, ExecMode::Auto));
        assert!(should_route_to_macos_guest(&echo, ExecMode::Guest));
        assert!(!should_route_to_macos_guest(&fc, ExecMode::Host));
    }

    #[test]
    fn vm_state_running_accepts_status_or_live_pid() {
        let mut state = VmState {
            config: VmConfig {
                backend: "qemu-hvf".to_string(),
                vm_name: "FerroCrateDesktopVM".to_string(),
                cpus: 2,
                memory_mb: 4096,
                disk_path: "/tmp/vm.qcow2".to_string(),
                host_share_path: ".".to_string(),
                fs_backend: "9p".to_string(),
                virtiofs_socket_path: None,
                hyperv_switch: None,
                ssh_port: 2222,
                api_port: 4288,
                guest_user: None,
                ssh_private_key_path: None,
                cloud_init_image_path: None,
            },
            pid: None,
            auxiliary_pids: Vec::new(),
            status: "running".to_string(),
            current_version: None,
            last_error: None,
        };
        assert!(vm_state_running(&state));
        state.status = "stopped".to_string();
        assert!(!vm_state_running(&state));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ensure_ssh_key_creates_an_unencrypted_key_on_macos() {
        let directory = tempfile::tempdir().expect("temp vm directory");
        let (private_key, public_key) = ensure_ssh_key(directory.path()).expect("generate key");
        assert!(private_key.is_file());
        assert!(public_key.is_file());
    }

    #[test]
    fn ssh_keygen_generation_uses_an_empty_passphrase_argument() {
        assert_eq!(
            ssh_keygen_generate_args(Path::new("/tmp/ferro-vm-key")),
            vec!["-t", "ed25519", "-N", "", "-f", "/tmp/ferro-vm-key"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn exec_mode_parser_handles_known_values() {
        assert_eq!(parse_exec_mode(None), ExecMode::Auto);
        assert_eq!(parse_exec_mode(Some("auto")), ExecMode::Auto);
        assert_eq!(parse_exec_mode(Some("host")), ExecMode::Host);
        assert_eq!(parse_exec_mode(Some("guest")), ExecMode::Guest);
        assert_eq!(parse_exec_mode(Some("vm")), ExecMode::Guest);
    }

    #[test]
    fn exec_mode_from_env_is_non_panicking() {
        let _ = exec_mode_from_env();
    }

    #[test]
    fn forward_entry_upsert_replaces_same_bind_and_port() {
        let mut entries = vec![ForwardEntry {
            bind_addr: "127.0.0.1".to_string(),
            listen_port: 8080,
            target_host: "127.0.0.1".to_string(),
            target_port: 80,
            enabled: true,
        }];
        upsert_forward_entry(
            &mut entries,
            ForwardEntry {
                bind_addr: "127.0.0.1".to_string(),
                listen_port: 8080,
                target_host: "127.0.0.1".to_string(),
                target_port: 8081,
                enabled: true,
            },
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].target_port, 8081);
    }

    #[test]
    fn forward_entries_roundtrip_state_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = PathBuf::from(temp.path()).join("forwards.json");
        let entries = vec![ForwardEntry {
            bind_addr: "127.0.0.1".to_string(),
            listen_port: 9000,
            target_host: "127.0.0.1".to_string(),
            target_port: 9001,
            enabled: true,
        }];
        save_forward_entries(&path, &entries).expect("save");
        let loaded = load_forward_entries(&path).expect("load");
        assert_eq!(loaded, entries);
    }

    #[test]
    fn vm_state_roundtrip_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = PathBuf::from(temp.path()).join("vm.json");
        let state = VmState {
            config: VmConfig {
                backend: "qemu-hvf".to_string(),
                vm_name: "FerroCrateDesktopVM".to_string(),
                cpus: 2,
                memory_mb: 4096,
                disk_path: "/tmp/vm.qcow2".to_string(),
                host_share_path: ".".to_string(),
                fs_backend: "9p".to_string(),
                virtiofs_socket_path: None,
                hyperv_switch: None,
                ssh_port: 2222,
                api_port: 4288,
                guest_user: None,
                ssh_private_key_path: None,
                cloud_init_image_path: None,
            },
            pid: None,
            auxiliary_pids: Vec::new(),
            status: "initialized".to_string(),
            current_version: None,
            last_error: None,
        };
        save_vm_state(&path, &state).expect("save vm state");
        let loaded = load_vm_state(&path).expect("load vm state");
        assert_eq!(loaded, state);
    }

    #[test]
    fn vm_command_builder_rejects_unknown_backend() {
        let cfg = VmConfig {
            backend: "unknown".to_string(),
            vm_name: "FerroCrateDesktopVM".to_string(),
            cpus: 2,
            memory_mb: 2048,
            disk_path: "/tmp/disk.qcow2".to_string(),
            host_share_path: ".".to_string(),
            fs_backend: "9p".to_string(),
            virtiofs_socket_path: None,
            hyperv_switch: None,
            ssh_port: 2222,
            api_port: 4288,
            guest_user: None,
            ssh_private_key_path: None,
            cloud_init_image_path: None,
        };
        let err = build_vm_command(&cfg, &[]).expect_err("must reject unknown backend");
        assert!(err.to_string().contains("unsupported vm backend"));
    }

    #[test]
    fn vm_command_builder_escapes_commas_in_option_values() {
        let cfg = VmConfig {
            backend: "qemu-x86_64".to_string(),
            vm_name: "FerroCrateDesktopVM".to_string(),
            cpus: 2,
            memory_mb: 2048,
            disk_path: "/tmp/dir,with,commas/disk.qcow2".to_string(),
            host_share_path: "/tmp/share,path".to_string(),
            fs_backend: "9p".to_string(),
            virtiofs_socket_path: Some("/tmp/sock,pet".to_string()),
            hyperv_switch: None,
            ssh_port: 2222,
            api_port: 4288,
            guest_user: None,
            ssh_private_key_path: None,
            cloud_init_image_path: Some("/tmp/seed,cloud.img".to_string()),
        };
        let forwards = vec![ForwardEntry {
            bind_addr: "127.0.0.1,evil=1".to_string(),
            listen_port: 8080,
            target_host: "localhost".to_string(),
            target_port: 80,
            enabled: true,
        }];
        let cmd = build_vm_command(&cfg, &forwards).expect("build vm command");
        let args = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        let drive = args
            .iter()
            .find(|arg| arg.contains("if=virtio,format=qcow2"))
            .expect("disk drive arg");
        assert!(
            drive.contains("file=/tmp/dir,,with,,commas/disk.qcow2"),
            "disk path commas must be doubled: {drive}"
        );

        let cloud_init = args
            .iter()
            .find(|arg| arg.contains("media=cdrom"))
            .expect("cloud-init drive arg");
        assert!(
            cloud_init.contains("file=/tmp/seed,,cloud.img"),
            "cloud-init path commas must be doubled: {cloud_init}"
        );

        let netdev = args
            .iter()
            .find(|arg| arg.contains("user,id=net0"))
            .expect("netdev arg");
        assert!(
            netdev.contains("127.0.0.1,,evil=1:8080-:80"),
            "bind address commas must be doubled: {netdev}"
        );
        assert!(
            !netdev.contains("127.0.0.1,evil"),
            "unescaped comma must not survive in netdev: {netdev}"
        );

        let virtfs = args
            .iter()
            .find(|arg| arg.starts_with("local,path="))
            .expect("virtfs arg");
        assert!(
            virtfs.contains("path=/tmp/share,,path"),
            "host share path commas must be doubled: {virtfs}"
        );
    }

    #[test]
    fn vm_command_builder_escapes_virtiofs_socket_comma() {
        let cfg = VmConfig {
            backend: "qemu-x86_64".to_string(),
            vm_name: "FerroCrateDesktopVM".to_string(),
            cpus: 2,
            memory_mb: 2048,
            disk_path: "/tmp/disk.qcow2".to_string(),
            host_share_path: "/tmp/share".to_string(),
            fs_backend: "virtiofs".to_string(),
            virtiofs_socket_path: Some("/tmp/sock,pet".to_string()),
            hyperv_switch: None,
            ssh_port: 2222,
            api_port: 4288,
            guest_user: None,
            ssh_private_key_path: None,
            cloud_init_image_path: None,
        };
        let cmd = build_vm_command(&cfg, &[]).expect("build vm command");
        let args = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        let chardev = args
            .iter()
            .find(|arg| arg.starts_with("socket,id=vfs0"))
            .expect("virtiofs chardev arg");
        assert!(
            chardev.contains("path=/tmp/sock,,pet"),
            "virtiofs socket path commas must be doubled: {chardev}"
        );
    }

    #[test]
    fn vm_command_builder_adds_forward_entries() {
        let cfg = VmConfig {
            backend: "qemu-hvf".to_string(),
            vm_name: "FerroCrateDesktopVM".to_string(),
            cpus: 2,
            memory_mb: 2048,
            disk_path: "/tmp/disk.qcow2".to_string(),
            host_share_path: ".".to_string(),
            fs_backend: "9p".to_string(),
            virtiofs_socket_path: None,
            hyperv_switch: None,
            ssh_port: 2222,
            api_port: 4288,
            guest_user: None,
            ssh_private_key_path: None,
            cloud_init_image_path: None,
        };
        let forwards = vec![ForwardEntry {
            bind_addr: "127.0.0.1".to_string(),
            listen_port: 8080,
            target_host: "localhost".to_string(),
            target_port: 80,
            enabled: true,
        }];
        let cmd = build_vm_command(&cfg, &forwards).expect("build vm command");
        let args = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        let netdev = args
            .iter()
            .find(|arg| arg.contains("user,id=net0"))
            .expect("netdev arg");
        assert!(netdev.contains("hostfwd=tcp:127.0.0.1:8080-:80"));
    }

    #[test]
    fn qemu_tcg_fallback_does_not_require_hvf() {
        let cfg = VmConfig {
            backend: "qemu-tcg-x86_64".to_string(),
            vm_name: "FerroCrateDesktopVM".to_string(),
            cpus: 2,
            memory_mb: 2048,
            disk_path: "/tmp/disk.qcow2".to_string(),
            host_share_path: "/tmp/share".to_string(),
            fs_backend: "9p".to_string(),
            virtiofs_socket_path: None,
            hyperv_switch: None,
            ssh_port: 2222,
            api_port: 4288,
            guest_user: Some("ferro".to_string()),
            ssh_private_key_path: Some("/tmp/key".to_string()),
            cloud_init_image_path: None,
        };
        let cmd = build_vm_command(&cfg, &[]).expect("build software-emulated VM command");
        let args = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert_eq!(cmd.get_program().to_string_lossy(), "qemu-system-x86_64");
        assert!(!args.windows(2).any(|pair| pair == ["-accel", "hvf"]));
        assert!(args.windows(2).any(|pair| pair == ["-accel", "tcg"]));
    }

    #[test]
    fn qemu_reserves_only_ssh_for_the_guest_socket_tunnel() {
        let cfg = VmConfig {
            backend: "qemu-x86_64".to_string(),
            vm_name: "FerroCrateDesktopVM".to_string(),
            cpus: 2,
            memory_mb: 2048,
            disk_path: "/tmp/disk.qcow2".to_string(),
            host_share_path: "/tmp/share".to_string(),
            fs_backend: "9p".to_string(),
            virtiofs_socket_path: None,
            hyperv_switch: None,
            ssh_port: 2222,
            api_port: 4288,
            guest_user: Some("ferro".to_string()),
            ssh_private_key_path: Some("/tmp/key".to_string()),
            cloud_init_image_path: None,
        };
        let cmd = build_vm_command(&cfg, &[]).expect("build VM command");
        let netdev = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .find(|arg| arg.starts_with("user,id=net0"))
            .expect("QEMU user network");

        assert!(netdev.contains("hostfwd=tcp:127.0.0.1:2222-:22"));
        assert!(
            !netdev.contains("4288"),
            "SSH owns the API tunnel: {netdev}"
        );
    }

    #[test]
    fn vm_command_builder_supports_installer_vfkit_state() {
        let cfg = VmConfig {
            backend: "vfkit".to_string(),
            vm_name: "FerroCrateDesktopVM".to_string(),
            cpus: 4,
            memory_mb: 4096,
            disk_path: "/Users/test/.ferrocrate/vm/ferrocrate-desktop.raw".to_string(),
            host_share_path: "/Users/test".to_string(),
            fs_backend: "virtiofs".to_string(),
            virtiofs_socket_path: None,
            hyperv_switch: None,
            ssh_port: 2222,
            api_port: 4288,
            guest_user: Some("ferro".to_string()),
            ssh_private_key_path: Some("/Users/test/.ferrocrate/vm/desktop_vm_ed25519".to_string()),
            cloud_init_image_path: Some(
                "/Users/test/.ferrocrate/vm/cloud-init-seed.iso".to_string(),
            ),
        };

        let command = build_vm_command(&cfg, &[]).expect("vfkit command from persisted state");
        assert_eq!(command.get_program().to_string_lossy(), "vfkit");
    }

    #[test]
    fn renders_macos_launch_agent_with_daemon_args() {
        let plist = render_macos_launch_agent_plist(
            "io.ferrocrate.desktop",
            "/usr/local/bin/ferro-desktop",
            "127.0.0.1:4288",
        );
        assert!(plist.contains("<string>io.ferrocrate.desktop</string>"));
        assert!(plist.contains("<string>/usr/local/bin/ferro-desktop</string>"));
        assert!(plist.contains("<string>daemon</string>"));
        assert!(plist.contains("<string>127.0.0.1:4288</string>"));
    }

    #[test]
    fn renders_windows_service_script_with_service_details() {
        let script = render_windows_service_script(
            "FerroDesktop",
            "C:\\Program Files\\FerroCrate\\ferro-desktop.exe",
            "127.0.0.1:4288",
        );
        assert!(script.contains("$serviceName = \"FerroDesktop\""));
        assert!(script.contains("daemon --addr 127.0.0.1:4288"));
        assert!(script.contains("sc.exe create $serviceName"));
    }

    #[test]
    fn daemon_refuses_the_port_reserved_for_the_web_bridge() {
        let error = validate_daemon_addr("127.0.0.1:4190", false)
            .expect_err("the web bridge exclusively owns port 4190");
        assert!(error.to_string().contains("reserved for the web bridge"));
    }

    #[test]
    fn loads_channel_manifest_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = PathBuf::from(temp.path()).join("channels.json");
        std::fs::write(
            &path,
            r#"{"channels":{"stable":{"version":"1.0.0","image_path":"/tmp/a.qcow2","sha256":"abc"}}}"#,
        )
        .expect("write");
        let manifest = load_channel_manifest(&path).expect("manifest");
        let stable = manifest.channels.get("stable").expect("stable");
        assert_eq!(stable.version, "1.0.0");
    }

    #[test]
    fn backup_path_suffix_is_appended() {
        let path = backup_path_for_disk(PathBuf::from("/tmp/disk.qcow2").as_path());
        assert_eq!(path.to_string_lossy(), "/tmp/disk.qcow2.bak");
    }
}

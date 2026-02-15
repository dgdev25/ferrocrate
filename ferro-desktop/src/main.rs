use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use thiserror::Error;

const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Parser)]
#[command(name = "ferro-desktop", version, about = "FerroCrate desktop daemon/proxy")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Daemon {
        #[arg(long, default_value = "127.0.0.1:4288")]
        addr: String,
        #[arg(long)]
        pipe_name: Option<String>,
        #[arg(long)]
        wsl_distro: Option<String>,
        #[arg(long, default_value_t = false)]
        allow_remote: bool,
    },
    Exec {
        #[arg(long, default_value = "127.0.0.1:4288")]
        addr: String,
        #[arg(long)]
        pipe_name: Option<String>,
        #[arg(long)]
        wsl: bool,
        #[arg(long)]
        wsl_distro: Option<String>,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    Doctor {
        #[arg(long)]
        wsl_distro: Option<String>,
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
        command: VmCommands,
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

#[derive(Debug, Subcommand)]
enum VmCommands {
    Init {
        #[arg(long, default_value = "qemu-hvf")]
        backend: String,
        #[arg(long, default_value_t = 2)]
        cpus: u8,
        #[arg(long, default_value_t = 4096)]
        memory_mb: u32,
        #[arg(long)]
        disk_path: Option<String>,
        #[arg(long)]
        host_share_path: Option<String>,
        #[arg(long, default_value_t = 2222)]
        ssh_port: u16,
        #[arg(long, default_value_t = 4288)]
        api_port: u16,
    },
    Start {
        #[arg(long, default_value_t = false)]
        foreground: bool,
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
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecRequest {
    cmd: Vec<String>,
    use_wsl: bool,
    wsl_distro: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecResponse {
    status: i32,
    stdout: String,
    stderr: String,
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
    cpus: u8,
    memory_mb: u32,
    disk_path: String,
    host_share_path: String,
    ssh_port: u16,
    api_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VmState {
    config: VmConfig,
    pid: Option<u32>,
    status: String,
    last_error: Option<String>,
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
    let result = match cli.command {
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
            cmd,
        } => run_client_exec(&addr, pipe_name.as_deref(), cmd, wsl, wsl_distro),
        Commands::Doctor { wsl_distro } => run_doctor(wsl_distro),
        Commands::Phase0Check { wsl_distro, json } => run_phase0_check(wsl_distro, json),
        Commands::Forward {
            state_file,
            json,
            command,
        } => run_forward_command(state_file.as_deref(), json, command),
        Commands::Vm { state_file, command } => run_vm_command(state_file.as_deref(), command),
    };
    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
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
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let _ = handle_client(&mut stream, default_wsl_distro.as_deref());
    }
    Ok(())
}

fn validate_daemon_addr(addr: &str, allow_remote: bool) -> Result<(), DesktopError> {
    if allow_remote {
        return Ok(());
    }
    if addr.starts_with("127.0.0.1:") || addr.starts_with("localhost:") || addr.starts_with("[::1]:") {
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
    let response = process_exec_request(request, default_wsl_distro)?;
    let payload = serde_json::to_string(&response)? + "\n";
    stream.write_all(payload.as_bytes())?;
    Ok(())
}

fn process_exec_request(
    mut request: ExecRequest,
    default_wsl_distro: Option<&str>,
) -> Result<ExecResponse, DesktopError> {
    if request.cmd.is_empty() {
        return Err(DesktopError::Invalid("command is required".to_string()));
    }
    if request.wsl_distro.is_none() {
        request.wsl_distro = default_wsl_distro.map(ToOwned::to_owned);
    }

    let output = run_request(&request)?;
    Ok(ExecResponse {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn read_exec_request<R: Read>(stream: &mut R) -> Result<ExecRequest, DesktopError> {
    let mut buf = Vec::new();
    {
        let mut reader = BufReader::new(&mut *stream);
        let bytes = reader.read_until(b'\n', &mut buf)?;
        if bytes == 0 {
            return Err(DesktopError::Invalid("empty request".to_string()));
        }
    }
    if buf.len() > MAX_REQUEST_BYTES {
        return Err(DesktopError::Invalid("request too large".to_string()));
    }
    if matches!(buf.last(), Some(b'\n')) {
        buf.pop();
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
) -> Result<(), DesktopError> {
    if cmd.is_empty() {
        return Err(DesktopError::Invalid("command is required".to_string()));
    }
    let request = ExecRequest {
        cmd,
        use_wsl: wsl,
        wsl_distro,
    };
    if let Some(pipe_name) = pipe_name {
        return run_client_exec_pipe(pipe_name, request);
    }
    let mut stream = TcpStream::connect(addr)?;
    let payload = serde_json::to_string(&request)? + "\n";
    stream.write_all(payload.as_bytes())?;

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
    use std::fs::File;
    use std::os::windows::io::FromRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_ACCESS_DUPLEX,
        PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    let full_name = normalize_pipe_name(pipe_name);
    let wide = utf16_null(&full_name);
    loop {
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                MAX_REQUEST_BYTES as u32,
                MAX_REQUEST_BYTES as u32,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(DesktopError::Io(std::io::Error::last_os_error()));
        }

        let connected = unsafe { ConnectNamedPipe(handle, null_mut()) };
        if connected == 0 {
            unsafe {
                CloseHandle(handle);
            }
            continue;
        }

        let mut file = unsafe { File::from_raw_handle(handle as *mut _) };
        let request = read_exec_request(&mut file)?;
        let response = process_exec_request(request, default_wsl_distro.as_deref())?;
        let payload = serde_json::to_string(&response)? + "\n";
        file.write_all(payload.as_bytes())?;
        file.flush()?;
        std::mem::forget(file);
        unsafe {
            DisconnectNamedPipe(handle);
            CloseHandle(handle);
        }
    }
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

#[cfg(windows)]
fn utf16_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
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
                println!("forward: added {} entries={}", state_path.display(), entries.len());
            }
        }
        ForwardCommands::Remove {
            bind_addr,
            listen_port,
        } => {
            let before = entries.len();
            entries.retain(|entry| !(entry.bind_addr == bind_addr && entry.listen_port == listen_port));
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
        return PathBuf::from(home).join(".ferrocrate").join("desktop-forwards.json");
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
    if let Some(existing) = entries
        .iter_mut()
        .find(|existing| existing.bind_addr == entry.bind_addr && existing.listen_port == entry.listen_port)
    {
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
        VmCommands::Init {
            backend,
            cpus,
            memory_mb,
            disk_path,
            host_share_path,
            ssh_port,
            api_port,
        } => {
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
            let state = VmState {
                config: VmConfig {
                    backend,
                    cpus,
                    memory_mb,
                    disk_path,
                    host_share_path,
                    ssh_port,
                    api_port,
                },
                pid: None,
                status: "initialized".to_string(),
                last_error: None,
            };
            save_vm_state(&state_path, &state)?;
            println!("vm: initialized {}", state_path.display());
            Ok(())
        }
        VmCommands::Start { foreground } => {
            let mut state = load_vm_state(&state_path)?;
            if let Some(pid) = state.pid {
                if pid_alive(pid) {
                    println!("vm: already running pid={pid}");
                    return Ok(());
                }
            }
            if !cfg!(target_os = "macos") {
                return Err(DesktopError::Invalid(
                    "vm start is currently supported on macOS hosts only".to_string(),
                ));
            }
            let mut command = build_vm_command(&state.config)?;
            if foreground {
                let status = command.status()?;
                if !status.success() {
                    return Err(DesktopError::Invalid(format!(
                        "vm process exited with status {status}"
                    )));
                }
                return Ok(());
            }
            let child = command.spawn()?;
            let pid = child.id();
            state.pid = Some(pid);
            state.status = "running".to_string();
            state.last_error = None;
            save_vm_state(&state_path, &state)?;
            println!("vm: started pid={pid}");
            Ok(())
        }
        VmCommands::Stop => {
            let mut state = load_vm_state(&state_path)?;
            let Some(pid) = state.pid else {
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
            #[cfg(unix)]
            {
                let status = Command::new("kill")
                    .arg("-TERM")
                    .arg(pid.to_string())
                    .status()?;
                if !status.success() {
                    return Err(DesktopError::Invalid(format!(
                        "failed to stop vm pid={pid}"
                    )));
                }
            }
            #[cfg(not(unix))]
            {
                return Err(DesktopError::Invalid(
                    "vm stop is supported on unix-like hosts only".to_string(),
                ));
            }
            state.pid = None;
            state.status = "stopped".to_string();
            save_vm_state(&state_path, &state)?;
            println!("vm: stopped");
            Ok(())
        }
        VmCommands::Status { json } => {
            let mut state = load_vm_state(&state_path)?;
            if let Some(pid) = state.pid {
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
                println!(
                    "vm: backend={} cpus={} memory_mb={} api_port={} ssh_port={} disk={} host_share={}",
                    state.config.backend,
                    state.config.cpus,
                    state.config.memory_mb,
                    state.config.api_port,
                    state.config.ssh_port,
                    state.config.disk_path,
                    state.config.host_share_path
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
    }
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
        return PathBuf::from(home).join(".ferrocrate").join("desktop-vm.json");
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

fn build_vm_command(config: &VmConfig) -> Result<Command, DesktopError> {
    let qemu_bin = match config.backend.as_str() {
        "qemu-hvf" => "qemu-system-aarch64",
        "qemu-x86_64" => "qemu-system-x86_64",
        other => {
            return Err(DesktopError::Invalid(format!(
                "unsupported vm backend: {other}"
            )))
        }
    };
    let mut cmd = Command::new(qemu_bin);
    if config.backend == "qemu-hvf" {
        cmd.arg("-accel").arg("hvf");
    }
    cmd.arg("-machine")
        .arg("virt")
        .arg("-cpu")
        .arg("host")
        .arg("-smp")
        .arg(config.cpus.to_string())
        .arg("-m")
        .arg(config.memory_mb.to_string())
        .arg("-drive")
        .arg(format!("file={},if=virtio,format=qcow2", config.disk_path))
        .arg("-netdev")
        .arg(format!(
            "user,id=net0,hostfwd=tcp::{}-:22,hostfwd=tcp::{}-:4288",
            config.ssh_port, config.api_port
        ))
        .arg("-device")
        .arg("virtio-net-pci,netdev=net0")
        .arg("-virtfs")
        .arg(format!(
            "local,path={},mount_tag=ferrohost,security_model=none",
            config.host_share_path
        ));
    Ok(cmd)
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

fn gather_phase0_check(wsl_distro: Option<String>) -> Result<Phase0CheckResult, DesktopError> {
    #[cfg(windows)]
    {
        let output = Command::new("wsl.exe").args(["-l", "-q"]).output()?;
        let status = output.status.code();
        let distros = String::from_utf8_lossy(&output.stdout)
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
            let text = String::from_utf8_lossy(&probe.stdout);
            let mut lines = text.lines();
            check.guest_kernel = lines.next().map(ToOwned::to_owned);
            let found = lines.any(|line| line.trim() == "FC_PRESENT=1");
            check.ferrocrate_present_in_guest = Some(found);
            if !found {
                check.notes.push("ferrocrate binary not found in selected WSL distro".to_string());
            }
        } else {
            check.notes.push("no WSL distro available; install/import distro first".to_string());
        }

        return Ok(check);
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

fn run_request(request: &ExecRequest) -> Result<std::process::Output, DesktopError> {
    if request.use_wsl {
        return run_wsl_command(request);
    }
    let (program, args) = request
        .cmd
        .split_first()
        .ok_or_else(|| DesktopError::Invalid("command is required".to_string()))?;
    Ok(Command::new(program).args(args).output()?)
}

fn run_wsl_command(request: &ExecRequest) -> Result<std::process::Output, DesktopError> {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("wsl.exe");
        if let Some(distro) = request.wsl_distro.as_deref() {
            cmd.arg("--distribution").arg(distro);
        }
        cmd.arg("--");
        for arg in &request.cmd {
            cmd.arg(arg);
        }
        return Ok(cmd.output()?);
    }

    #[cfg(not(windows))]
    {
        let _ = request;
        Err(DesktopError::Invalid(
            "WSL execution is only available on Windows hosts".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExecRequest, ForwardEntry, VmConfig, VmState, build_vm_command, gather_phase0_check,
        load_forward_entries, load_vm_state, run_request, save_forward_entries, save_vm_state,
        upsert_forward_entry, validate_daemon_addr,
    };
    use std::path::PathBuf;

    #[test]
    fn executes_local_command() {
        let req = ExecRequest {
            cmd: vec!["sh".to_string(), "-c".to_string(), "echo ok".to_string()],
            use_wsl: false,
            wsl_distro: None,
        };
        let out = run_request(&req).expect("run command");
        assert!(out.status.success());
    }

    #[test]
    fn rejects_empty_local_command() {
        let req = ExecRequest {
            cmd: vec![],
            use_wsl: false,
            wsl_distro: None,
        };
        let err = run_request(&req).expect_err("should fail");
        assert!(err.to_string().contains("command is required"));
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
    fn daemon_addr_remote_allowed_with_flag() {
        assert!(validate_daemon_addr("0.0.0.0:4288", true).is_ok());
    }

    #[test]
    fn phase0_check_runs_on_current_host() {
        let result = gather_phase0_check(None).expect("phase0 check");
        assert!(!result.host_os.is_empty());
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
                cpus: 2,
                memory_mb: 4096,
                disk_path: "/tmp/vm.qcow2".to_string(),
                host_share_path: ".".to_string(),
                ssh_port: 2222,
                api_port: 4288,
            },
            pid: None,
            status: "initialized".to_string(),
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
            cpus: 2,
            memory_mb: 2048,
            disk_path: "/tmp/disk.qcow2".to_string(),
            host_share_path: ".".to_string(),
            ssh_port: 2222,
            api_port: 4288,
        };
        let err = build_vm_command(&cfg).expect_err("must reject unknown backend");
        assert!(err.to_string().contains("unsupported vm backend"));
    }
}

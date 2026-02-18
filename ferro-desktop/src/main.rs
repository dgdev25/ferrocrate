use clap::{Parser, Subcommand};
use ferro_core::entitlements::{self, Feature};
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
use std::thread;
use std::time::Duration;
use thiserror::Error;

const MAX_REQUEST_BYTES: usize = 64 * 1024;

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
    Autostart {
        #[command(subcommand)]
        command: AutostartCommands,
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

#[derive(Debug, Subcommand)]
enum VmCommands {
    Init {
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
    },
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
    status: String,
    #[serde(default)]
    current_version: Option<String>,
    last_error: Option<String>,
}

fn default_vm_name() -> String {
    "FerroCrateDesktopVM".to_string()
}

fn command_exists(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin} >/dev/null 2>&1"))
        .status()
        .map(|status| status.success())
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
        return Ok((key_path, pub_path));
    }
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&key_path)
        .status()?;
    if !status.success() {
        return Err(DesktopError::Invalid(
            "failed to generate vm ssh key".to_string(),
        ));
    }
    Ok((key_path, pub_path))
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
        Commands::Vm {
            state_file,
            command,
        } => run_vm_command(state_file.as_deref(), command),
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
            | Commands::Exec { .. }
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
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let default_wsl_distro = default_wsl_distro.clone();
        thread::spawn(move || {
            let _ = handle_client(&mut stream, default_wsl_distro.as_deref());
        });
    }
    Ok(())
}

fn validate_daemon_addr(addr: &str, allow_remote: bool) -> Result<(), DesktopError> {
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
        VmCommands::Init {
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
            let vm_dir = state_path.parent().unwrap_or_else(|| Path::new("."));
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
            let guest_user = guest_user.unwrap_or_else(|| "ferro".to_string());
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
                "qemu-hvf" | "qemu-x86_64" => {
                    if !cfg!(target_os = "macos") {
                        return Err(DesktopError::Invalid(
                            "qemu vm backend is currently supported on macOS hosts only"
                                .to_string(),
                        ));
                    }
                    if state.config.fs_backend == "virtiofs" {
                        start_virtiofs_daemon(&state.config)?;
                    }
                    let mut command = build_vm_command(&state.config, &forwards)?;
                    if foreground {
                        command.arg("-serial").arg("mon:stdio");
                        let status = command.status()?;
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
                    command.arg("-serial").arg(format!("file:{}", log_path.display()));
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
                        state.last_error = Some(format!(
                            "vm exited early; see {}",
                            log_path.display()
                        ));
                        save_vm_state(&state_path, &state)?;
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

fn start_virtiofs_daemon(config: &VmConfig) -> Result<(), DesktopError> {
    let socket_path = config.virtiofs_socket_path.as_deref().ok_or_else(|| {
        DesktopError::Invalid("virtiofs backend requires virtiofs_socket_path".to_string())
    })?;
    if fs::metadata(socket_path).is_ok() {
        let _ = fs::remove_file(socket_path);
    }
    let status = Command::new("virtiofsd")
        .arg("--socket-path")
        .arg(socket_path)
        .arg("--shared-dir")
        .arg(&config.host_share_path)
        .arg("--cache")
        .arg("auto")
        .spawn();
    match status {
        Ok(_) => Ok(()),
        Err(err) => Err(DesktopError::Invalid(format!(
            "failed to start virtiofsd: {err}"
        ))),
    }
}

fn start_hyperv_vm(config: &VmConfig) -> Result<(), DesktopError> {
    #[cfg(windows)]
    {
        if hyperv_vm_running(config)? {
            return Ok(());
        }
        let switch_clause = if let Some(sw) = config.hyperv_switch.as_deref() {
            format!(" -SwitchName '{}'", sw)
        } else {
            String::new()
        };
        let script = format!(
            "$name = '{name}'; if (-not (Get-VM -Name $name -ErrorAction SilentlyContinue)) {{ New-VM -Name $name -Generation 2 -MemoryStartupBytes {mem}MB -VHDPath '{vhd}'{switch_clause} | Out-Null; Set-VMProcessor -VMName $name -Count {cpus}; }}; Start-VM -Name $name | Out-Null",
            name = config.vm_name,
            mem = config.memory_mb,
            vhd = config.disk_path,
            cpus = config.cpus,
            switch_clause = switch_clause
        );
        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &script])
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
        let script = format!(
            "$name = '{name}'; $vm = Get-VM -Name $name -ErrorAction SilentlyContinue; if ($null -eq $vm) {{ exit 2 }}; if ($vm.State -eq 'Running') {{ exit 0 }} else {{ exit 1 }}",
            name = config.vm_name
        );
        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &script])
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
        let script = format!(
            "$name = '{name}'; if (Get-VM -Name $name -ErrorAction SilentlyContinue) {{ Stop-VM -Name $name -TurnOff -Force -ErrorAction SilentlyContinue | Out-Null; }}",
            name = config.vm_name
        );
        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &script])
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

fn build_vm_command(config: &VmConfig, forwards: &[ForwardEntry]) -> Result<Command, DesktopError> {
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
    if cfg!(target_os = "macos")
        && (config.backend == "qemu-hvf" || config.backend == "qemu-x86_64")
    {
        cmd.arg("-accel").arg("hvf");
    }
    if cfg!(target_os = "macos") {
        cmd.arg("-display").arg("none");
    }
    let machine = if config.backend == "qemu-x86_64" {
        "q35"
    } else {
        "virt"
    };
    if let Some((code, vars)) = find_uefi_firmware(config.backend.as_str()) {
        if let Some(vars_path) = vars {
            cmd.arg("-drive")
                .arg(format!(
                    "if=pflash,format=raw,readonly=on,file={}",
                    code.display()
                ))
                .arg("-drive")
                .arg(format!("if=pflash,format=raw,file={}", vars_path.display()));
        } else if config.backend != "qemu-x86_64" {
            cmd.arg("-bios").arg(code);
        }
    }
    let mut host_forward_specs = vec![
        format!("hostfwd=tcp:127.0.0.1:{}-:22", config.ssh_port),
        format!("hostfwd=tcp:127.0.0.1:{}-:4288", config.api_port),
    ];
    let mut used_bind_ports = HashSet::new();
    used_bind_ports.insert(("127.0.0.1".to_string(), config.ssh_port));
    used_bind_ports.insert(("127.0.0.1".to_string(), config.api_port));
    for entry in forwards {
        if !is_loopback_host(&entry.target_host) {
            continue;
        }
        let bind_addr = if entry.bind_addr.trim().is_empty() {
            "127.0.0.1".to_string()
        } else {
            entry.bind_addr.clone()
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
        .arg("host")
        .arg("-smp")
        .arg(config.cpus.to_string())
        .arg("-m")
        .arg(config.memory_mb.to_string())
        .arg("-drive")
        .arg(format!("file={},if=virtio,format=qcow2", config.disk_path))
        .arg("-netdev")
        .arg(netdev)
        .arg("-device")
        .arg("virtio-net-pci,netdev=net0");
    if let Some(cloud_init) = config.cloud_init_image_path.as_deref() {
        cmd.arg("-drive").arg(format!(
            "file={cloud_init},if=virtio,media=cdrom,readonly=on,format=raw"
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
                .arg(format!("socket,id=vfs0,path={socket_path}"))
                .arg("-device")
                .arg("vhost-user-fs-pci,chardev=vfs0,tag=ferrohost");
        }
        "9p" => {
            cmd.arg("-virtfs").arg(format!(
                "local,path={},mount_tag=ferrohost,security_model=none",
                config.host_share_path
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

fn find_uefi_firmware(backend: &str) -> Option<(PathBuf, Option<PathBuf>)> {
    let candidates = if backend == "qemu-x86_64" {
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
                check
                    .notes
                    .push("ferrocrate binary not found in selected WSL distro".to_string());
            }
        } else {
            check
                .notes
                .push("no WSL distro available; install/import distro first".to_string());
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
    #[cfg(target_os = "macos")]
    {
        if should_route_to_macos_guest(&request.cmd, exec_mode_from_env()) {
            return run_macos_guest_command(request);
        }
    }
    let (program, args) = request
        .cmd
        .split_first()
        .ok_or_else(|| DesktopError::Invalid("command is required".to_string()))?;
    let mut command = Command::new(program);
    command.args(args);
    // Prevent recursive host-desktop forwarding loops when daemon executes `ferrocrate`.
    command.env("FERROCRATE_DESKTOP_FORWARD", "0");
    Ok(command.output()?)
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

#[cfg(target_os = "macos")]
fn run_macos_guest_command(request: &ExecRequest) -> Result<std::process::Output, DesktopError> {
    let state_path = default_vm_state_path();
    let state = load_vm_state(&state_path).map_err(|err| {
        DesktopError::Invalid(format!(
            "cannot route to guest runtime: failed to load vm state {}: {err}",
            state_path.display()
        ))
    })?;
    if !vm_state_running(&state) {
        return Err(DesktopError::Invalid(format!(
            "cannot route to guest runtime: vm is not running (state={})",
            state.status
        )));
    }
    let mut cmd = build_guest_ssh_command(request, &state)?;
    cmd.output().map_err(DesktopError::Io)
}

#[allow(dead_code)]
fn vm_state_running(state: &VmState) -> bool {
    if state.status.eq_ignore_ascii_case("running") {
        return true;
    }
    state.pid.map(pid_alive).unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn build_guest_ssh_command(
    request: &ExecRequest,
    state: &VmState,
) -> Result<Command, DesktopError> {
    if request.cmd.is_empty() {
        return Err(DesktopError::Invalid("command is required".to_string()));
    }

    let guest_host = std::env::var("FERROCRATE_DESKTOP_VM_HOST")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let guest_user = std::env::var("FERROCRATE_DESKTOP_VM_USER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| state.config.guest_user.clone())
        .unwrap_or_else(|| "root".to_string());
    let ssh_key = std::env::var("FERROCRATE_DESKTOP_VM_SSH_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| state.config.ssh_private_key_path.clone());

    let mut cmd = Command::new("ssh");
    cmd.arg("-p")
        .arg(state.config.ssh_port.to_string())
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=10");
    if let Some(key_path) = ssh_key {
        cmd.arg("-i").arg(key_path);
    }
    cmd.arg(format!("{guest_user}@{guest_host}")).arg("--");
    for arg in &request.cmd {
        cmd.arg(arg);
    }
    Ok(cmd)
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
        backup_path_for_disk, build_vm_command, command_requires_desktop_entitlement,
        command_targets_ferrocrate, exec_mode_from_env, gather_phase0_check, load_channel_manifest,
        load_forward_entries, load_vm_state, parse_exec_mode, render_macos_launch_agent_plist,
        render_windows_service_script, run_request, save_forward_entries, save_vm_state,
        should_route_to_macos_guest, upsert_forward_entry, validate_daemon_addr, vm_state_running,
        Commands, ExecMode, ExecRequest, ForwardCommands, ForwardEntry, VmCommands, VmConfig,
        VmState,
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
            command: VmCommands::Status { json: true },
        }));
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
            status: "running".to_string(),
            current_version: None,
            last_error: None,
        };
        assert!(vm_state_running(&state));
        state.status = "stopped".to_string();
        assert!(!vm_state_running(&state));
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

    #[cfg(target_os = "macos")]
    #[test]
    fn builds_guest_ssh_command_with_vm_port() {
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
            status: "running".to_string(),
            current_version: None,
            last_error: None,
        };
        let req = ExecRequest {
            cmd: vec!["ferrocrate".to_string(), "images".to_string()],
            use_wsl: false,
            wsl_distro: None,
        };
        let cmd = super::build_guest_ssh_command(&req, &state).expect("ssh command");
        assert_eq!(cmd.get_program().to_string_lossy(), "ssh");
        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"2222".to_string()));
        assert!(args.contains(&"--".to_string()));
        assert!(args.contains(&"ferrocrate".to_string()));
        assert!(args.contains(&"images".to_string()));
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

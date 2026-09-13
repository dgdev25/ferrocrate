use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecOutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Error)]
pub enum ContainerExecError {
    #[error("command must not be empty")]
    EmptyCommand,
    #[error("failed to execute command: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid mount target: {0}")]
    InvalidMountTarget(String),
}

/// Execute a command in a rootless container's bubblewrap boundary.
///
/// Rootless containers cannot reliably be re-entered with `nsenter`: the
/// workload owns a private user namespace and an unprivileged caller cannot
/// join its mount namespace after the fact. Recreating the same rootfs/mount
/// boundary is the supported rootless exec path and keeps the operation
/// unprivileged.
#[allow(clippy::too_many_arguments)]
pub fn exec_in_rootless_rootfs(
    rootfs: &Path,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    tmpfs_mounts: &[(String, Option<String>)],
    readonly_rootfs: bool,
    timeout: Option<Duration>,
) -> Result<ExecResult, ContainerExecError> {
    let command = build_rootless_bwrap(
        rootfs,
        command,
        env,
        workdir,
        mounts,
        tmpfs_mounts,
        readonly_rootfs,
    )?;
    execute_process(command, timeout)
}

/// Execute a rootless command and close its stdin after forwarding `input`.
#[allow(clippy::too_many_arguments)]
pub fn exec_in_rootless_rootfs_with_input(
    rootfs: &Path,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    tmpfs_mounts: &[(String, Option<String>)],
    readonly_rootfs: bool,
    input: &[u8],
) -> Result<ExecResult, ContainerExecError> {
    let command = build_rootless_bwrap(
        rootfs,
        command,
        env,
        workdir,
        mounts,
        tmpfs_mounts,
        readonly_rootfs,
    )?;
    execute_process_with_input(command, input)
}

/// Execute a rootless command while forwarding stdin and emitting output as
/// soon as the child writes it.
#[allow(clippy::too_many_arguments)]
pub fn exec_in_rootless_rootfs_streaming(
    rootfs: &Path,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    tmpfs_mounts: &[(String, Option<String>)],
    readonly_rootfs: bool,
    input: Option<Box<dyn Read + Send>>,
    tty: bool,
    tty_ready: &mut dyn FnMut(&Path) -> std::io::Result<()>,
    output: &mut dyn FnMut(ExecOutputStream, &[u8]) -> std::io::Result<()>,
) -> Result<ExecResult, ContainerExecError> {
    let command = build_rootless_bwrap(
        rootfs,
        command,
        env,
        workdir,
        mounts,
        tmpfs_mounts,
        readonly_rootfs,
    )?;
    execute_process_streaming(command, input, tty, tty_ready, output)
}

/// Execute a rootless command with stdout/stderr attached to one PTY.
///
/// Bubblewrap recreates the same rootfs and mount boundary as ordinary
/// rootless exec; the PTY only changes the transport semantics.
#[allow(clippy::too_many_arguments)]
pub fn exec_in_rootless_rootfs_tty(
    rootfs: &Path,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    tmpfs_mounts: &[(String, Option<String>)],
    readonly_rootfs: bool,
) -> Result<ExecResult, ContainerExecError> {
    let mut command = build_rootless_bwrap(
        rootfs,
        command,
        env,
        workdir,
        mounts,
        tmpfs_mounts,
        readonly_rootfs,
    )?;
    let pty = crate::pty::PtyPair::new(24, 80).map_err(ContainerExecError::Io)?;
    let (master, slave) = pty.into_parts();
    let slave = File::from(slave);
    command.stdin(Stdio::from(slave.try_clone()?));
    command.stdout(Stdio::from(slave.try_clone()?));
    command.stderr(Stdio::from(slave));
    crate::pty::configure_command(&mut command)?;
    let mut child = command.spawn()?;
    let master = File::from(master);
    let mut output = Vec::new();
    if let Err(error) = master.take(MAX_OUTPUT_SIZE).read_to_end(&mut output) {
        if error.raw_os_error() != Some(nix::libc::EIO) {
            return Err(ContainerExecError::Io(error));
        }
    }
    let status = child.wait()?;
    Ok(ExecResult {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output).into_owned(),
        stderr: String::new(),
    })
}

/// Execute a rootless TTY command with caller-provided terminal input.
#[allow(clippy::too_many_arguments)]
pub fn exec_in_rootless_rootfs_tty_with_input(
    rootfs: &Path,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    tmpfs_mounts: &[(String, Option<String>)],
    readonly_rootfs: bool,
    input: &[u8],
) -> Result<ExecResult, ContainerExecError> {
    let mut command = build_rootless_bwrap(
        rootfs,
        command,
        env,
        workdir,
        mounts,
        tmpfs_mounts,
        readonly_rootfs,
    )?;
    execute_tty_process(&mut command, input)
}

#[allow(clippy::too_many_arguments)]
fn build_rootless_bwrap(
    rootfs: &Path,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    tmpfs_mounts: &[(String, Option<String>)],
    readonly_rootfs: bool,
) -> Result<Command, ContainerExecError> {
    if command.is_empty() {
        return Err(ContainerExecError::EmptyCommand);
    }
    if !rootfs.is_dir() {
        return Err(ContainerExecError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("rootfs does not exist: {}", rootfs.display()),
        )));
    }
    let bwrap_path = crate::rootless::trusted_executable_path("bwrap").ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "bwrap is unavailable or not a trusted root-owned executable",
        ))
    })?;
    let mut bwrap = Command::new(bwrap_path);
    bwrap
        .arg("--bind")
        .arg(rootfs)
        .arg("/")
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        .arg("--setenv")
        .arg("PATH")
        .arg("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    for (source, target, read_only) in mounts {
        crate::mounts::normalize_mount_target(Path::new(target))
            .map_err(|error| ContainerExecError::InvalidMountTarget(error.to_string()))?;
        // Bubblewrap does not create a bind destination. Docker permits a
        // volume target that is absent from the image, so create it inside the
        // sandbox before applying the bind.
        bwrap.arg("--dir").arg(format!("/{target}"));
        bwrap
            .arg(if *read_only { "--ro-bind" } else { "--bind" })
            .arg(source)
            .arg(format!("/{target}"));
    }
    for (target, size) in tmpfs_mounts {
        crate::mounts::normalize_mount_target(Path::new(target))
            .map_err(|error| ContainerExecError::InvalidMountTarget(error.to_string()))?;
        if size.is_some() {
            return Err(ContainerExecError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "rootless exec cannot apply sized tmpfs mounts",
            )));
        }
        bwrap.arg("--tmpfs").arg(format!("/{target}"));
    }
    if readonly_rootfs {
        bwrap.arg("--remount-ro").arg("/");
    }
    if let Some(workdir) = workdir {
        bwrap.arg("--chdir").arg(workdir);
    } else {
        bwrap.arg("--chdir").arg("/");
    }
    for entry in env {
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            ContainerExecError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "env var missing key",
            ))
        })?;
        bwrap.arg("--setenv").arg(key).arg(value);
    }
    bwrap.arg(&command[0]).args(&command[1..]);
    Ok(bwrap)
}

/// Build nsenter arguments for executing a command in all namespaces of target pid.
pub fn build_nsenter_args(
    target_pid: u32,
    command: &[String],
) -> Result<Vec<String>, ContainerExecError> {
    build_nsenter_args_with_options(target_pid, command, &[], None, None)
}

/// Build namespace-entering arguments while applying Docker exec overrides.
///
/// `nsenter` performs the uid/gid change after it has joined the target user
/// namespace, and `/usr/bin/env` applies only the explicitly requested exec
/// variables without mutating the daemon's environment.
pub fn build_nsenter_args_with_options(
    target_pid: u32,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    user: Option<&str>,
) -> Result<Vec<String>, ContainerExecError> {
    if command.is_empty() {
        return Err(ContainerExecError::EmptyCommand);
    }

    // Security: Validate command to prevent basic injection attacks
    // The first element should be a binary name (not a path with special chars)
    if command[0].contains('\0') || command[0].contains('|') || command[0].contains(';') {
        return Err(ContainerExecError::EmptyCommand);
    }

    let mut args = vec!["-t".to_string(), target_pid.to_string()];
    // BusyBox's Alpine nsenter lacks util-linux's `-a` shorthand. Spell out
    // the same namespace set there while leaving the glibc argv unchanged.
    #[cfg(target_env = "musl")]
    args.extend(["-m", "-u", "-i", "-n", "-p"].map(str::to_string));
    #[cfg(not(target_env = "musl"))]
    args.push("-a".to_string());
    if let Some(workdir) = workdir.filter(|value| !value.is_empty()) {
        #[cfg(target_env = "musl")]
        args.extend(["-w".to_string(), workdir.to_string()]);
        #[cfg(not(target_env = "musl"))]
        args.extend(["--wd".to_string(), workdir.to_string()]);
    }
    if let Some(user) = user.filter(|value| !value.is_empty()) {
        let (uid, gid) = user
            .split_once(':')
            .map_or((user, None), |(uid, gid)| (uid, Some(gid)));
        if uid.is_empty() || !uid.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ContainerExecError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "exec user must be a numeric uid or uid:gid",
            )));
        }
        #[cfg(target_env = "musl")]
        args.extend(["-S".to_string(), uid.to_string()]);
        #[cfg(not(target_env = "musl"))]
        args.extend(["--setuid".to_string(), uid.to_string()]);
        if let Some(gid) = gid {
            if gid.is_empty() || !gid.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ContainerExecError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "exec user group must be numeric",
                )));
            }
            #[cfg(target_env = "musl")]
            args.extend(["-G".to_string(), gid.to_string()]);
            #[cfg(not(target_env = "musl"))]
            args.extend(["--setgid".to_string(), gid.to_string()]);
        }
    }
    if !env.is_empty() {
        if env.iter().any(|entry| entry.split_once('=').is_none()) {
            return Err(ContainerExecError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "exec environment entry must use KEY=VALUE",
            )));
        }
        args.push("/usr/bin/env".to_string());
        args.extend(env.iter().cloned());
    }
    args.extend(command.iter().cloned());
    Ok(args)
}

/// Execute command inside an existing container process namespace set via `nsenter`.
pub fn exec_in_container(
    target_pid: u32,
    command: &[String],
) -> Result<ExecResult, ContainerExecError> {
    let args = build_nsenter_args(target_pid, command)?;
    let nsenter = crate::rootless::trusted_executable_path("nsenter").ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "nsenter is unavailable or not a trusted root-owned executable",
        ))
    })?;
    execute_command(&nsenter, &args)
}

/// Execute a rootful command with Docker exec environment, user, and working
/// directory overrides.
pub fn exec_in_container_with_options(
    target_pid: u32,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    user: Option<&str>,
) -> Result<ExecResult, ContainerExecError> {
    let args = build_nsenter_args_with_options(target_pid, command, env, workdir, user)?;
    let nsenter = crate::rootless::trusted_executable_path("nsenter").ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "nsenter is unavailable or not a trusted root-owned executable",
        ))
    })?;
    execute_command(&nsenter, &args)
}

/// Execute a rootful container command with bounded caller-provided stdin.
pub fn exec_in_container_with_input(
    target_pid: u32,
    command: &[String],
    input: &[u8],
) -> Result<ExecResult, ContainerExecError> {
    let args = build_nsenter_args(target_pid, command)?;
    let nsenter = crate::rootless::trusted_executable_path("nsenter").ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "nsenter is unavailable or not a trusted root-owned executable",
        ))
    })?;
    let mut command = Command::new(nsenter);
    command.args(args);
    execute_process_with_input(command, input)
}

/// Execute a rootful container command while forwarding both directions of
/// the attached session concurrently.
pub fn exec_in_container_streaming(
    target_pid: u32,
    command: &[String],
    input: Option<Box<dyn Read + Send>>,
    tty: bool,
    tty_ready: &mut dyn FnMut(&Path) -> std::io::Result<()>,
    output: &mut dyn FnMut(ExecOutputStream, &[u8]) -> std::io::Result<()>,
) -> Result<ExecResult, ContainerExecError> {
    let args = build_nsenter_args(target_pid, command)?;
    let nsenter = crate::rootless::trusted_executable_path("nsenter").ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "nsenter is unavailable or not a trusted root-owned executable",
        ))
    })?;
    let mut command = Command::new(nsenter);
    command.args(args);
    execute_process_streaming(command, input, tty, tty_ready, output)
}

pub fn exec_in_container_with_timeout(
    target_pid: u32,
    command: &[String],
    timeout: Duration,
) -> Result<ExecResult, ContainerExecError> {
    let args = build_nsenter_args(target_pid, command)?;
    let nsenter = crate::rootless::trusted_executable_path("nsenter").ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "nsenter is unavailable or not a trusted root-owned executable",
        ))
    })?;
    execute_command_with_timeout(&nsenter, &args, timeout)
}

/// Execute a rootful container command attached to a pseudo-terminal.
///
/// The PTY intentionally merges stdout and stderr, matching Docker's TTY
/// contract. Interactive stdin forwarding and resize are layered by the
/// Docker transport; this primitive provides the terminal-backed process and
/// bounded output capture.
pub fn exec_in_container_tty(
    target_pid: u32,
    command: &[String],
) -> Result<ExecResult, ContainerExecError> {
    let args = build_nsenter_args(target_pid, command)?;
    let nsenter = crate::rootless::trusted_executable_path("nsenter").ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "nsenter is unavailable or not a trusted root-owned executable",
        ))
    })?;
    let pty = crate::pty::PtyPair::new(24, 80).map_err(ContainerExecError::Io)?;
    let (master, slave) = pty.into_parts();
    let slave = File::from(slave);
    let mut child = Command::new(nsenter);
    child
        .args(args)
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    crate::pty::configure_command(&mut child)?;
    let mut child = child.spawn()?;
    let master = File::from(master);
    let mut output = Vec::new();
    if let Err(error) = master.take(MAX_OUTPUT_SIZE).read_to_end(&mut output) {
        // Linux reports EIO when the last PTY slave closes; for a PTY this is
        // the normal end-of-stream signal rather than an execution failure.
        if error.raw_os_error() != Some(nix::libc::EIO) {
            return Err(ContainerExecError::Io(error));
        }
    }
    let status = child.wait()?;
    Ok(ExecResult {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output).into_owned(),
        stderr: String::new(),
    })
}

/// Execute a rootful TTY command with Docker exec overrides.
pub fn exec_in_container_tty_with_options(
    target_pid: u32,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    user: Option<&str>,
) -> Result<ExecResult, ContainerExecError> {
    let args = build_nsenter_args_with_options(target_pid, command, env, workdir, user)?;
    let nsenter = crate::rootless::trusted_executable_path("nsenter").ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "nsenter is unavailable or not a trusted root-owned executable",
        ))
    })?;
    let pty = crate::pty::PtyPair::new(24, 80).map_err(ContainerExecError::Io)?;
    let (master, slave) = pty.into_parts();
    let slave = File::from(slave);
    let mut child = Command::new(nsenter);
    child
        .args(args)
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    crate::pty::configure_command(&mut child)?;
    let mut child = child.spawn()?;
    let master = File::from(master);
    let mut output = Vec::new();
    if let Err(error) = master.take(MAX_OUTPUT_SIZE).read_to_end(&mut output) {
        if error.raw_os_error() != Some(nix::libc::EIO) {
            return Err(ContainerExecError::Io(error));
        }
    }
    let status = child.wait()?;
    Ok(ExecResult {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output).into_owned(),
        stderr: String::new(),
    })
}

/// Execute a rootful TTY command with caller-provided terminal input.
pub fn exec_in_container_tty_with_input(
    target_pid: u32,
    command: &[String],
    input: &[u8],
) -> Result<ExecResult, ContainerExecError> {
    let args = build_nsenter_args(target_pid, command)?;
    let nsenter = crate::rootless::trusted_executable_path("nsenter").ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "nsenter is unavailable or not a trusted root-owned executable",
        ))
    })?;
    let mut command = Command::new(nsenter);
    command.args(args);
    execute_tty_process(&mut command, input)
}

fn execute_tty_process(
    command: &mut Command,
    input: &[u8],
) -> Result<ExecResult, ContainerExecError> {
    use std::io::Write as _;

    let pty = crate::pty::PtyPair::new(24, 80).map_err(ContainerExecError::Io)?;
    let (master, slave) = pty.into_parts();
    let slave = File::from(slave);
    command
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    crate::pty::configure_command(command)?;
    let mut child = command.spawn()?;
    // Command retains its configured stdio after spawn. Release the parent's
    // slave descriptors so the master observes EOF/EIO when the child exits.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut master = File::from(master);
    let mut writer = master.try_clone()?;
    writer.write_all(input)?;
    // In canonical terminal mode, EOT after the caller's bytes communicates
    // stdin completion without becoming part of the command's input.
    writer.write_all(&[0x04])?;
    drop(writer);
    let mut output = Vec::new();
    if let Err(error) = (&mut master).take(MAX_OUTPUT_SIZE).read_to_end(&mut output) {
        if error.raw_os_error() != Some(nix::libc::EIO) {
            return Err(ContainerExecError::Io(error));
        }
    }
    let status = child.wait()?;
    Ok(ExecResult {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output).into_owned(),
        stderr: String::new(),
    })
}

fn execute_command(binary: &Path, args: &[String]) -> Result<ExecResult, ContainerExecError> {
    let output = Command::new(binary).args(args).output()?;
    Ok(ExecResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn execute_command_with_timeout(
    binary: &Path,
    args: &[String],
    timeout: Duration,
) -> Result<ExecResult, ContainerExecError> {
    let mut child = spawn_command(binary, args)?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return collect_output(child, status.code().unwrap_or(-1));
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(ExecResult {
                exit_code: 124,
                stdout: String::new(),
                stderr: "command timed out".to_string(),
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn execute_process(
    mut command: Command,
    timeout: Option<Duration>,
) -> Result<ExecResult, ContainerExecError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let Some(timeout) = timeout {
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                return collect_output(child, status.code().unwrap_or(-1));
            }
            if start.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(ExecResult {
                    exit_code: 124,
                    stdout: String::new(),
                    stderr: "command timed out".to_string(),
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let status = child.wait()?;
    collect_output(child, status.code().unwrap_or(-1))
}

fn execute_process_with_input(
    mut command: Command,
    input: &[u8],
) -> Result<ExecResult, ContainerExecError> {
    use std::io::Write as _;

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::other("exec stdin pipe is unavailable"))
    })?;
    stdin.write_all(input)?;
    drop(stdin);
    let output = child.wait_with_output()?;
    Ok(ExecResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(
            &output.stdout[..output.stdout.len().min(MAX_OUTPUT_SIZE as usize)],
        )
        .into_owned(),
        stderr: String::from_utf8_lossy(
            &output.stderr[..output.stderr.len().min(MAX_OUTPUT_SIZE as usize)],
        )
        .into_owned(),
    })
}

fn execute_process_streaming(
    mut command: Command,
    input: Option<Box<dyn Read + Send>>,
    tty: bool,
    tty_ready: &mut dyn FnMut(&Path) -> std::io::Result<()>,
    output: &mut dyn FnMut(ExecOutputStream, &[u8]) -> std::io::Result<()>,
) -> Result<ExecResult, ContainerExecError> {
    if tty {
        return execute_tty_process_streaming(&mut command, input, tty_ready, output);
    }

    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;

    if let (Some(mut source), Some(mut destination)) = (input, child.stdin.take()) {
        thread::spawn(move || {
            let _ = std::io::copy(&mut source, &mut destination);
        });
    }

    let (sender, receiver) = mpsc::channel();
    let stdout = child.stdout.take().ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::other("exec stdout pipe is unavailable"))
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        ContainerExecError::Io(std::io::Error::other("exec stderr pipe is unavailable"))
    })?;
    for (stream, mut reader) in [
        (
            ExecOutputStream::Stdout,
            Box::new(stdout) as Box<dyn Read + Send>,
        ),
        (
            ExecOutputStream::Stderr,
            Box::new(stderr) as Box<dyn Read + Send>,
        ),
    ] {
        let sender = sender.clone();
        thread::spawn(move || {
            let mut buffer = [0_u8; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        if sender.send((stream, buffer[..read].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send((stream, Vec::new()));
                        let _ = error;
                        break;
                    }
                }
            }
        });
    }
    drop(sender);

    let mut stdout_capture = Vec::new();
    let mut stderr_capture = Vec::new();
    for (stream, bytes) in receiver {
        if bytes.is_empty() {
            continue;
        }
        if let Err(error) = output(stream, &bytes) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ContainerExecError::Io(error));
        }
        let capture = match stream {
            ExecOutputStream::Stdout => &mut stdout_capture,
            ExecOutputStream::Stderr => &mut stderr_capture,
        };
        let remaining = (MAX_OUTPUT_SIZE as usize).saturating_sub(capture.len());
        capture.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
    }
    let status = child.wait()?;
    Ok(ExecResult {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout_capture).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_capture).into_owned(),
    })
}

fn execute_tty_process_streaming(
    command: &mut Command,
    input: Option<Box<dyn Read + Send>>,
    tty_ready: &mut dyn FnMut(&Path) -> std::io::Result<()>,
    output: &mut dyn FnMut(ExecOutputStream, &[u8]) -> std::io::Result<()>,
) -> Result<ExecResult, ContainerExecError> {
    let pty = crate::pty::PtyPair::new(24, 80).map_err(ContainerExecError::Io)?;
    let tty_device = pty.slave_name()?;
    let (master, slave) = pty.into_parts();
    let slave = File::from(slave);
    command
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    crate::pty::configure_command(command)?;
    let mut child = command.spawn()?;
    // Command retains its configured stdio after spawn. Release the parent's
    // slave descriptors so the master observes EOF/EIO when the child exits.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Err(error) = tty_ready(&tty_device) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(ContainerExecError::Io(error));
    }
    let mut master = File::from(master);
    if let Some(mut source) = input {
        let mut writer = master.try_clone()?;
        thread::spawn(move || {
            let _ = std::io::copy(&mut source, &mut writer);
            let _ = writer.write_all(&[0x04]);
        });
    }

    let mut capture = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match master.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                output(ExecOutputStream::Stdout, &buffer[..read])?;
                let remaining = (MAX_OUTPUT_SIZE as usize).saturating_sub(capture.len());
                capture.extend_from_slice(&buffer[..read.min(remaining)]);
            }
            Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => break,
            Err(error) => return Err(ContainerExecError::Io(error)),
        }
    }
    let status = child.wait()?;
    Ok(ExecResult {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&capture).into_owned(),
        stderr: String::new(),
    })
}

fn spawn_command(binary: &Path, args: &[String]) -> Result<Child, ContainerExecError> {
    Ok(Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?)
}

/// Maximum output capture size (1MB) to prevent OOM attacks
const MAX_OUTPUT_SIZE: u64 = 1024 * 1024;

fn collect_output(mut child: Child, exit_code: i32) -> Result<ExecResult, ContainerExecError> {
    use std::io::Read;

    let mut stdout = Vec::new();
    if let Some(out) = child.stdout.take() {
        // Security: Limit output size to prevent OOM attacks
        out.take(MAX_OUTPUT_SIZE).read_to_end(&mut stdout)?;
    }
    let mut stderr = Vec::new();
    if let Some(err) = child.stderr.take() {
        // Security: Limit output size to prevent OOM attacks
        err.take(MAX_OUTPUT_SIZE).read_to_end(&mut stderr)?;
    }
    Ok(ExecResult {
        exit_code,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_nsenter_args, build_nsenter_args_with_options, exec_in_container_tty,
        execute_command, execute_command_with_timeout,
    };
    use nix::unistd::Uid;
    use std::path::Path;
    use std::time::Duration;

    #[test]
    fn tty_streaming_finishes_after_child_exit_or_failed_shell() {
        for (script, expected_exit) in [
            ("printf completed; exit 7", 7),
            ("exec /ferro-test-missing-shell", 127),
        ] {
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut command = std::process::Command::new("/bin/sh");
                command.args(["-c", script]);
                let result = super::execute_tty_process_streaming(
                    &mut command,
                    None,
                    &mut |_| Ok(()),
                    &mut |_, _| Ok(()),
                );
                let _ = sender.send(result);
            });
            let result = receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("PTY EOF must follow child exit even while parent Command exists")
                .expect("PTY execution completes");
            assert_eq!(result.exit_code, expected_exit);
            assert!(!result.stdout.is_empty());
        }
    }

    #[test]
    fn buffered_tty_finishes_after_child_exit() {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut command = std::process::Command::new("/bin/sh");
            command.args(["-c", "printf buffered-done"]);
            let _ = sender.send(super::execute_tty_process(&mut command, &[]));
        });
        let result = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("buffered PTY EOF must follow child exit")
            .expect("PTY execution completes");
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("buffered-done"));
    }

    #[test]
    fn builds_nsenter_args_for_exec() {
        let args = build_nsenter_args(
            1234,
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hi".to_string(),
            ],
        )
        .expect("args should build");

        #[cfg(target_env = "musl")]
        let expected = vec![
            "-t", "1234", "-m", "-u", "-i", "-n", "-p", "/bin/sh", "-c", "echo hi",
        ];
        #[cfg(not(target_env = "musl"))]
        let expected = vec!["-t", "1234", "-a", "/bin/sh", "-c", "echo hi"];
        assert_eq!(args, expected);
    }

    #[test]
    fn builds_nsenter_args_with_exec_environment_user_and_workdir() {
        let args = build_nsenter_args_with_options(
            1234,
            &["/bin/sh".to_string(), "-c".to_string(), "id".to_string()],
            &["COLOR=blue".to_string()],
            Some("/workspace"),
            Some("1001:1002"),
        )
        .expect("exec arguments");

        #[cfg(target_env = "musl")]
        let expected = vec![
            "-t",
            "1234",
            "-m",
            "-u",
            "-i",
            "-n",
            "-p",
            "-w",
            "/workspace",
            "-S",
            "1001",
            "-G",
            "1002",
            "/usr/bin/env",
            "COLOR=blue",
            "/bin/sh",
            "-c",
            "id",
        ];
        #[cfg(not(target_env = "musl"))]
        let expected = vec![
            "-t",
            "1234",
            "-a",
            "--wd",
            "/workspace",
            "--setuid",
            "1001",
            "--setgid",
            "1002",
            "/usr/bin/env",
            "COLOR=blue",
            "/bin/sh",
            "-c",
            "id",
        ];
        assert_eq!(args, expected);
    }

    #[test]
    fn rejects_empty_exec_command() {
        let err = build_nsenter_args(1, &[]).expect_err("should reject empty command");
        assert!(err.to_string().contains("command must not be empty"));
    }

    #[test]
    fn captures_exit_code_and_output() {
        let args = vec!["-c".to_string(), "echo exec-ok && exit 7".to_string()];
        let result = execute_command(Path::new("/bin/sh"), &args).expect("command should run");
        assert_eq!(result.exit_code, 7);
        assert!(result.stdout.contains("exec-ok"));
    }

    #[test]
    fn times_out_long_running_command() {
        let args = vec!["-c".to_string(), "sleep 0.2".to_string()];
        let result =
            execute_command_with_timeout(Path::new("/bin/sh"), &args, Duration::from_millis(50))
                .expect("command should run");
        assert_eq!(result.exit_code, 124);
        assert!(result.stderr.contains("timed out"));
    }

    #[test]
    fn rootful_tty_exec_merges_output_and_reports_terminal() {
        if !Uid::effective().is_root() {
            return;
        }
        let result = exec_in_container_tty(
            std::process::id(),
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "test -t 1 && printf tty".to_string(),
            ],
        )
        .expect("rootful PTY exec");
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("tty"), "output={:?}", result.stdout);
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn rootless_mount_target_validation_rejects_traversal_before_bwrap() {
        if !crate::rootless::bubblewrap_available() {
            eprintln!(
                "skipping: {}",
                crate::rootless::BUBBLEWRAP_UNAVAILABLE_MESSAGE
            );
            return;
        }
        let root = tempfile::tempdir().expect("rootfs tempdir");
        let error = super::exec_in_rootless_rootfs(
            root.path(),
            &["/bin/true".to_string()],
            &[],
            None,
            &[("/tmp/source".to_string(), "../escape".to_string(), false)],
            &[],
            false,
            None,
        )
        .expect_err("traversal target must fail before helper launch");
        assert!(error.to_string().contains("invalid mount target"));
    }

    #[test]
    fn rootless_bwrap_creates_a_missing_mount_target_before_binding() {
        if !crate::rootless::bubblewrap_available() {
            return;
        }
        let root = tempfile::tempdir().expect("rootfs tempdir");
        let command = super::build_rootless_bwrap(
            root.path(),
            &["/bin/true".to_string()],
            &[],
            None,
            &[("/tmp".to_string(), "volume".to_string(), false)],
            &[],
            false,
        )
        .expect("build rootless command");
        let args = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.windows(2).any(|pair| pair == ["--dir", "/volume"]));
    }

    #[test]
    fn rootless_tty_mount_target_validation_rejects_traversal_before_bwrap() {
        if !crate::rootless::bubblewrap_available() {
            eprintln!(
                "skipping: {}",
                crate::rootless::BUBBLEWRAP_UNAVAILABLE_MESSAGE
            );
            return;
        }
        let root = tempfile::tempdir().expect("rootfs tempdir");
        let error = super::exec_in_rootless_rootfs_tty(
            root.path(),
            &["/bin/true".to_string()],
            &[],
            None,
            &[("/tmp/source".to_string(), "../escape".to_string(), false)],
            &[],
            false,
        )
        .expect_err("traversal target must fail before helper launch");
        assert!(error.to_string().contains("invalid mount target"));
    }
}

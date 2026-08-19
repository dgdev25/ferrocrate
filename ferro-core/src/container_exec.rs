use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Error)]
pub enum ContainerExecError {
    #[error("command must not be empty")]
    EmptyCommand,
    #[error("failed to execute command: {0}")]
    Io(#[from] std::io::Error),
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
        bwrap
            .arg(if *read_only { "--ro-bind" } else { "--bind" })
            .arg(source)
            .arg(format!("/{target}"));
    }
    for (target, size) in tmpfs_mounts {
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
    execute_process(bwrap, timeout)
}

/// Build nsenter arguments for executing a command in all namespaces of target pid.
pub fn build_nsenter_args(
    target_pid: u32,
    command: &[String],
) -> Result<Vec<String>, ContainerExecError> {
    if command.is_empty() {
        return Err(ContainerExecError::EmptyCommand);
    }

    // Security: Validate command to prevent basic injection attacks
    // The first element should be a binary name (not a path with special chars)
    if command[0].contains('\0') || command[0].contains('|') || command[0].contains(';') {
        return Err(ContainerExecError::EmptyCommand);
    }

    let mut args = vec!["-t".to_string(), target_pid.to_string(), "-a".to_string()];
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
    let pty = nix::pty::openpty(None, None)
        .map_err(|error| ContainerExecError::Io(std::io::Error::other(error)))?;
    let slave = File::from(pty.slave);
    let mut child = Command::new(nsenter)
        .args(args)
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave))
        .spawn()?;
    let master = File::from(pty.master);
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
        build_nsenter_args, exec_in_container_tty, execute_command, execute_command_with_timeout,
    };
    use nix::unistd::Uid;
    use std::path::Path;
    use std::time::Duration;

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

        assert_eq!(
            args,
            vec![
                "-t".to_string(),
                "1234".to_string(),
                "-a".to_string(),
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hi".to_string(),
            ]
        );
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
}

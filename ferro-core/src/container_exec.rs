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
    execute_command("nsenter", &args)
}

pub fn exec_in_container_with_timeout(
    target_pid: u32,
    command: &[String],
    timeout: Duration,
) -> Result<ExecResult, ContainerExecError> {
    let args = build_nsenter_args(target_pid, command)?;
    execute_command_with_timeout("nsenter", &args, timeout)
}

fn execute_command(binary: &str, args: &[String]) -> Result<ExecResult, ContainerExecError> {
    let output = Command::new(binary).args(args).output()?;
    Ok(ExecResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn execute_command_with_timeout(
    binary: &str,
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

fn spawn_command(binary: &str, args: &[String]) -> Result<Child, ContainerExecError> {
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
    use super::{build_nsenter_args, execute_command, execute_command_with_timeout};
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
        let result = execute_command("sh", &args).expect("command should run");
        assert_eq!(result.exit_code, 7);
        assert!(result.stdout.contains("exec-ok"));
    }

    #[test]
    fn times_out_long_running_command() {
        let args = vec!["-c".to_string(), "sleep 0.2".to_string()];
        let result = execute_command_with_timeout("sh", &args, Duration::from_millis(50))
            .expect("command should run");
        assert_eq!(result.exit_code, 124);
        assert!(result.stderr.contains("timed out"));
    }
}

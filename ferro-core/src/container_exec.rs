use std::process::Command;
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
pub fn build_nsenter_args(target_pid: u32, command: &[String]) -> Result<Vec<String>, ContainerExecError> {
    if command.is_empty() {
        return Err(ContainerExecError::EmptyCommand);
    }

    let mut args = vec!["-t".to_string(), target_pid.to_string(), "-a".to_string()];
    args.extend(command.iter().cloned());
    Ok(args)
}

/// Execute command inside an existing container process namespace set via `nsenter`.
pub fn exec_in_container(target_pid: u32, command: &[String]) -> Result<ExecResult, ContainerExecError> {
    let args = build_nsenter_args(target_pid, command)?;
    execute_command("nsenter", &args)
}

fn execute_command(binary: &str, args: &[String]) -> Result<ExecResult, ContainerExecError> {
    let output = Command::new(binary).args(args).output()?;
    Ok(ExecResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{build_nsenter_args, execute_command};

    #[test]
    fn builds_nsenter_args_for_exec() {
        let args = build_nsenter_args(1234, &["/bin/sh".to_string(), "-c".to_string(), "echo hi".to_string()])
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
}

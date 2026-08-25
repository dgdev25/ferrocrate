use std::{path::Path, process::Stdio, time::Duration};

use serde::Serialize;
use serde_json::Value;
use tokio::io::AsyncReadExt;

use super::{FleetCommand, FleetCommandResult};

const MAX_ARGUMENT_BYTES: usize = 4 * 1024;
const MAX_COMMAND_ARGUMENTS: usize = 128;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub fn build_agent_cli_args(action: &str, arguments: &Value) -> Result<Vec<String>, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "fleet command arguments must be an object".to_string())?;
    let required = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("fleet command requires {name}"))
            .and_then(validate_argument)
    };
    Ok(match action {
        "list_containers" => vec![
            "ps".into(),
            "--all".into(),
            "--format".into(),
            "json".into(),
        ],
        "container_logs" => vec![
            "logs".into(),
            required("container")?,
            "--format".into(),
            "text".into(),
        ],
        "inspect_container" => vec![
            "inspect".into(),
            required("container")?,
            "--format".into(),
            "json".into(),
        ],
        "remove_container" => vec!["rm".into(), "--force".into(), required("container")?],
        "doctor" => vec!["doctor".into(), "--json".into()],
        "run_container" => {
            let command = object
                .get("command")
                .and_then(Value::as_array)
                .ok_or_else(|| "fleet run command must be an array".to_string())?;
            if command.len() > MAX_COMMAND_ARGUMENTS {
                return Err("fleet run command has too many arguments".into());
            }
            let mut args = vec![
                "run".into(),
                "--detach".into(),
                "--name".into(),
                required("name")?,
                "--network".into(),
                "none".into(),
                required("image")?,
            ];
            for value in command {
                args.push(validate_argument(value.as_str().ok_or_else(|| {
                    "fleet run command arguments must be strings".to_string()
                })?)?);
            }
            args
        }
        _ => return Err(format!("unsupported fleet command {action}")),
    })
}

fn validate_argument(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > MAX_ARGUMENT_BYTES || value.chars().any(char::is_control) {
        return Err("fleet command argument is invalid".into());
    }
    Ok(value.into())
}

pub async fn execute_agent_command(
    runtime_executable: &Path,
    command: FleetCommand,
) -> FleetCommandResult {
    let args = match build_agent_cli_args(&command.action, &command.arguments) {
        Ok(args) => args,
        Err(error) => {
            return FleetCommandResult {
                request_id: command.request_id,
                exit_code: 125,
                stdout: String::new(),
                stderr: error,
            };
        }
    };
    match run_bounded(runtime_executable, &args).await {
        Ok((exit_code, stdout, stderr)) => FleetCommandResult {
            request_id: command.request_id,
            exit_code,
            stdout,
            stderr,
        },
        Err(error) => FleetCommandResult {
            request_id: command.request_id,
            exit_code: 125,
            stdout: String::new(),
            stderr: error,
        },
    }
}

#[derive(Debug, Serialize)]
pub struct AgentObservation {
    pub kind: &'static str,
    pub version: String,
    pub health: String,
    pub doctor_summary: String,
    pub containers: Value,
    pub observed_at: i64,
}

pub async fn collect_agent_observation(
    runtime_executable: &Path,
    observed_at: i64,
) -> AgentObservation {
    let version = run_bounded(runtime_executable, &["version".into()])
        .await
        .map(|(_, stdout, _)| reported_client_version(&stdout))
        .unwrap_or_else(|_| "unknown".into());
    let containers = run_bounded(
        runtime_executable,
        &[
            "ps".into(),
            "--all".into(),
            "--format".into(),
            "json".into(),
        ],
    )
    .await
    .ok()
    .and_then(|(code, stdout, _)| (code == 0).then_some(stdout))
    .and_then(|stdout| serde_json::from_str::<Value>(&stdout).ok())
    .filter(Value::is_array)
    .unwrap_or_else(|| Value::Array(Vec::new()));
    let doctor = run_bounded(runtime_executable, &["doctor".into(), "--json".into()]).await;
    let (health, doctor_summary) = match doctor {
        Ok((0, stdout, _)) => ("healthy".into(), stdout),
        Ok((_, stdout, stderr)) => (
            "degraded".into(),
            if stderr.is_empty() { stdout } else { stderr },
        ),
        Err(error) => ("unknown".into(), error),
    };
    AgentObservation {
        kind: "observation",
        version,
        health,
        doctor_summary,
        containers,
        observed_at,
    }
}

async fn run_bounded(executable: &Path, args: &[String]) -> Result<(i32, String, String), String> {
    let mut child = tokio::process::Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start fleet command: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "fleet command stdout unavailable".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "fleet command stderr unavailable".to_string())?;
    let stdout_reader = tokio::spawn(read_bounded(stdout));
    let stderr_reader = tokio::spawn(read_bounded(stderr));
    let status = match tokio::time::timeout(COMMAND_TIMEOUT, child.wait()).await {
        Ok(result) => {
            result.map_err(|error| format!("failed to wait for fleet command: {error}"))?
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err("fleet command timed out".into());
        }
    };
    let stdout = stdout_reader
        .await
        .map_err(|error| format!("fleet stdout task failed: {error}"))??;
    let stderr = stderr_reader
        .await
        .map_err(|error| format!("fleet stderr task failed: {error}"))??;
    Ok((status.code().unwrap_or(125), stdout, stderr))
}

async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(reader: R) -> Result<String, String> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| format!("failed to read fleet command output: {error}"))?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        bytes.truncate(MAX_OUTPUT_BYTES);
        bytes.extend_from_slice(b"\n[output truncated]\n");
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn reported_client_version(output: &str) -> String {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("Version:").map(str::trim))
        .map(|version| version.trim_matches('"'))
        .filter(|version| !version.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use serde_json::json;

    use super::{execute_agent_command, reported_client_version, FleetCommand};

    #[test]
    fn observation_extracts_the_client_version_from_docker_style_output() {
        assert_eq!(
            reported_client_version("Client:\n Version: 0.1.0\n API version: 1.43\n"),
            "0.1.0"
        );
        assert_eq!(
            reported_client_version("Client:\n Version: \"0.1.0\"\n API version: \"1.45\"\n"),
            "0.1.0"
        );
    }

    #[tokio::test]
    async fn failed_agent_commands_preserve_cli_stderr_verbatim() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("runtime");
        std::fs::write(&executable, "#!/bin/sh\nprintf 'registry denied\\n' >&2\nexit 125\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = execute_agent_command(
            &executable,
            FleetCommand {
                request_id: 7,
                action: "run_container".into(),
                arguments: json!({
                    "name":"stderr-test",
                    "image":"nosuch/image:1",
                    "command":[],
                }),
            },
        )
        .await;
        assert_eq!(result.exit_code, 125);
        assert_eq!(result.stdout, "");
        assert_eq!(result.stderr, "registry denied\n");
    }
}

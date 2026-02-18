use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct OrchestrateRequest {
    pub task: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OrchestrateResponse {
    pub raw_response: String,
    pub parsed_result: Option<Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("invalid request: task is empty")]
    EmptyTask,
    #[error("failed to spawn claude-flow command: {0}")]
    Spawn(String),
    #[error("failed to write request to claude-flow stdin: {0}")]
    StdinWrite(String),
    #[error("claude-flow exited with status {status}: {stderr}")]
    NonZeroExit { status: i32, stderr: String },
    #[error("claude-flow returned empty response")]
    EmptyResponse,
}

pub fn orchestrate_task(
    request: &OrchestrateRequest,
    timeout: Option<Duration>,
) -> Result<OrchestrateResponse, AgentError> {
    if request.task.trim().is_empty() {
        return Err(AgentError::EmptyTask);
    }

    let command =
        std::env::var("FERROCRATE_CLAUDE_FLOW_CMD").unwrap_or_else(|_| "claude-flow".to_string());
    let args_raw = std::env::var("FERROCRATE_CLAUDE_FLOW_ARGS").unwrap_or_default();
    let args = split_args(&args_raw);

    let mut child = Command::new(&command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| AgentError::Spawn(err.to_string()))?;

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "task_orchestrate",
        "params": {
            "task": request.task,
            "context": request.context.clone().unwrap_or_default(),
        }
    });
    let request_line = format!("{}\n", payload);
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| AgentError::StdinWrite("missing stdin handle".to_string()))?;
    stdin
        .write_all(request_line.as_bytes())
        .map_err(|err| AgentError::StdinWrite(err.to_string()))?;
    drop(stdin);

    let output = if let Some(timeout) = timeout {
        wait_with_timeout(child, timeout)?
    } else {
        child
            .wait_with_output()
            .map_err(|err| AgentError::Spawn(err.to_string()))?
    };

    if !output.status.success() {
        return Err(AgentError::NonZeroExit {
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(AgentError::EmptyResponse);
    }

    let parsed = serde_json::from_str::<Value>(&stdout).ok();
    let result = parsed.as_ref().and_then(|json| json.get("result").cloned());

    Ok(OrchestrateResponse {
        raw_response: stdout,
        parsed_result: result,
    })
}

fn split_args(args: &str) -> Vec<String> {
    args.split_whitespace().map(|s| s.to_string()).collect()
}

fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, AgentError> {
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|err| AgentError::Spawn(err.to_string()));
            }
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(AgentError::Spawn(format!(
                        "claude-flow timed out after {}s",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(AgentError::Spawn(err.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orchestrate_request_requires_task() {
        let req = OrchestrateRequest {
            task: String::new(),
            context: None,
        };
        let err = orchestrate_task(&req, None).expect_err("empty task should fail");
        assert!(err.to_string().contains("task is empty"));
    }

    #[test]
    fn orchestrate_task_parses_jsonrpc_result() {
        let temp = tempfile::tempdir().expect("tempdir");
        let script = temp.path().join("mock-claude-flow.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nread line\nprintf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\\n'\n",
        )
        .expect("write script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).expect("meta").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).expect("chmod");
        }
        unsafe {
            std::env::set_var("FERROCRATE_CLAUDE_FLOW_CMD", script.display().to_string());
            std::env::remove_var("FERROCRATE_CLAUDE_FLOW_ARGS");
        }
        let req = OrchestrateRequest {
            task: "diagnose high memory".to_string(),
            context: Some("container=api".to_string()),
        };
        let out =
            orchestrate_task(&req, Some(Duration::from_secs(2))).expect("mock claude-flow output");
        assert!(out.raw_response.contains("\"result\""));
        assert_eq!(
            out.parsed_result
                .and_then(|v| v.get("ok").cloned())
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        unsafe {
            std::env::remove_var("FERROCRATE_CLAUDE_FLOW_CMD");
        }
    }
}

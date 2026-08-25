//! Network command execution with transaction support.
//!
//! This module provides execution functions that actually run the commands
//! built by the other modules, with support for atomic transactions with
//! rollback on failure.

use std::io::Write;
use std::process::{Command, Stdio};
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilities {
    pub linux: bool,
    pub root: bool,
    pub cap_net_admin: bool,
    pub ip: bool,
    pub nft: bool,
    pub iptables: bool,
    pub tc: bool,
    pub wg: bool,
}

impl HostCapabilities {
    pub fn probe() -> Self {
        let cap_eff = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("CapEff:").map(str::trim))
                    .and_then(|value| u64::from_str_radix(value, 16).ok())
            });
        Self {
            linux: cfg!(target_os = "linux"),
            root: {
                #[cfg(unix)]
                {
                    nix::unistd::geteuid().as_raw() == 0
                }
                #[cfg(not(unix))]
                {
                    false
                }
            },
            cap_net_admin: cap_eff.is_some_and(|value| value & (1 << 12) != 0),
            ip: command_available("ip"),
            nft: command_available("nft"),
            iptables: command_available("iptables"),
            tc: command_available("tc"),
            wg: command_available("wg"),
        }
    }

    pub fn require_network_mutation(&self) -> Result<(), ExecError> {
        if !self.linux {
            return Err(ExecError::CapabilityRequired {
                capability: "Linux engine required".into(),
            });
        }
        if !self.root {
            return Err(ExecError::CapabilityRequired {
                capability: "root".into(),
            });
        }
        if !self.cap_net_admin {
            return Err(ExecError::CapabilityRequired {
                capability: "CAP_NET_ADMIN".into(),
            });
        }
        if !self.ip {
            return Err(ExecError::CapabilityRequired {
                capability: "iproute2 (ip)".into(),
            });
        }
        Ok(())
    }
}

fn command_available(command: &str) -> bool {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join(command))
        .any(|path| path.is_file())
}

#[derive(Debug, Error)]
pub enum ExecError {
    #[error("command failed: {cmd} — {stderr}")]
    CommandFailed { cmd: String, stderr: String },
    #[error("io error running {cmd}: {source}")]
    Io {
        cmd: String,
        #[source]
        source: std::io::Error,
    },
    #[error("required host capability is unavailable: {capability}")]
    CapabilityRequired { capability: String },
}

#[cfg(target_os = "linux")]
fn require_linux_engine() -> Result<(), ExecError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn require_linux_engine() -> Result<(), ExecError> {
    Err(ExecError::CapabilityRequired {
        capability: "Linux engine required".into(),
    })
}

/// Execute a command vector, returning Ok(()) on success or ExecError on failure.
///
/// The command vector format is `[program, arg1, arg2, ...]`.
pub fn exec_cmd(args: &[String]) -> Result<(), ExecError> {
    if args.is_empty() {
        return Err(ExecError::CommandFailed {
            cmd: String::new(),
            stderr: "empty command".to_string(),
        });
    }
    require_linux_engine()?;

    let (program, cmd_args) = args.split_first().expect("checked non-empty");
    let cmd_str = args.join(" ");

    let output = Command::new(program)
        .args(cmd_args)
        .output()
        .map_err(|e| ExecError::Io {
            cmd: cmd_str.clone(),
            source: e,
        })?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(ExecError::CommandFailed {
            cmd: cmd_str,
            stderr,
        })
    }
}

/// Execute a command vector and capture its stdout.
///
/// Returns the stdout as a string on success, or ExecError on failure.
pub fn exec_cmd_capture(args: &[String]) -> Result<String, ExecError> {
    if args.is_empty() {
        return Err(ExecError::CommandFailed {
            cmd: String::new(),
            stderr: "empty command".to_string(),
        });
    }
    require_linux_engine()?;

    let (program, cmd_args) = args.split_first().expect("checked non-empty");
    let cmd_str = args.join(" ");

    let output = Command::new(program)
        .args(cmd_args)
        .output()
        .map_err(|e| ExecError::Io {
            cmd: cmd_str.clone(),
            source: e,
        })?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(ExecError::CommandFailed {
            cmd: cmd_str,
            stderr,
        })
    }
}

/// Execute a command vector with stdin and capture stdout.
pub fn exec_cmd_with_stdin(args: &[String], input: &str) -> Result<String, ExecError> {
    if args.is_empty() {
        return Err(ExecError::CommandFailed {
            cmd: String::new(),
            stderr: "empty command".to_string(),
        });
    }
    require_linux_engine()?;
    let (program, cmd_args) = args.split_first().expect("checked non-empty");
    let cmd_str = args.join(" ");
    let mut child = Command::new(program)
        .args(cmd_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| ExecError::Io {
            cmd: cmd_str.clone(),
            source,
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| ExecError::CommandFailed {
            cmd: cmd_str.clone(),
            stderr: "failed to open command stdin".to_string(),
        })?
        .write_all(input.as_bytes())
        .map_err(|source| ExecError::Io {
            cmd: cmd_str.clone(),
            source,
        })?;
    let output = child.wait_with_output().map_err(|source| ExecError::Io {
        cmd: cmd_str.clone(),
        source,
    })?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(ExecError::CommandFailed {
            cmd: cmd_str,
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

/// Execute a command vector and return whether it exited successfully.
pub fn exec_cmd_status(args: &[String]) -> Result<bool, ExecError> {
    if args.is_empty() {
        return Err(ExecError::CommandFailed {
            cmd: String::new(),
            stderr: "empty command".to_string(),
        });
    }
    require_linux_engine()?;
    let (program, cmd_args) = args.split_first().expect("checked non-empty");
    let cmd_str = args.join(" ");
    let status = Command::new(program)
        .args(cmd_args)
        .status()
        .map_err(|source| ExecError::Io {
            cmd: cmd_str,
            source,
        })?;
    Ok(status.success())
}

/// Execute a command while treating absence of an already-owned resource as success.
pub fn exec_cmd_allow_missing(args: &[String]) -> Result<(), ExecError> {
    match exec_cmd(args) {
        Ok(()) => Ok(()),
        Err(error) => {
            let ExecError::CommandFailed { stderr, .. } = &error else {
                return Err(error);
            };
            let removable = [
                "No such file or directory",
                "No such table",
                "No such file",
                "Cannot find device",
                "Cannot find qdisc",
                "Cannot find filter",
                "does a matching rule exist",
                "No chain/target/match by that name",
            ];
            if removable.iter().any(|message| stderr.contains(message)) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

/// A sequence of commands that can be rolled back if any fails.
///
/// Each forward command has an associated rollback command.
/// If a later command fails, all previously executed commands
/// are rolled back in reverse order.
pub struct Transaction {
    /// Track executed commands with their rollbacks for potential rollback
    executed: Vec<(Vec<String>, Vec<String>)>,
}

impl Transaction {
    /// Create a new empty transaction.
    pub fn new() -> Self {
        Self {
            executed: Vec::new(),
        }
    }

    /// Execute a forward command and register its rollback.
    ///
    /// If the forward command fails, automatically rolls back all
    /// previously executed commands and returns the error.
    pub fn add(&mut self, forward: Vec<String>, rollback: Vec<String>) -> Result<(), ExecError> {
        if let Err(e) = exec_cmd(&forward) {
            // Forward command failed, rollback everything
            self.rollback();
            return Err(e);
        }
        self.executed.push((forward, rollback));
        Ok(())
    }

    /// Execute a forward command (no rollback needed).
    ///
    /// Use for commands that don't need rollback (e.g., idempotent operations).
    pub fn add_no_rollback(&mut self, forward: Vec<String>) -> Result<(), ExecError> {
        if let Err(e) = exec_cmd(&forward) {
            self.rollback();
            return Err(e);
        }
        // Empty rollback means nothing to roll back
        self.executed.push((forward, Vec::new()));
        Ok(())
    }

    /// Roll back all executed commands in reverse order.
    ///
    /// Errors during rollback are logged but don't stop the rollback process.
    pub fn rollback(&self) {
        // Execute rollbacks in reverse order
        for (_forward, rollback) in self.executed.iter().rev() {
            if !rollback.is_empty() {
                if let Err(e) = exec_cmd(rollback) {
                    warn!(error = %e, "transaction rollback failed");
                }
            }
        }
    }

    /// Commit the transaction (no-op, just consume self).
    ///
    /// After commit, rollback is no longer possible.
    pub fn commit(self) {
        // Intentionally consume self without rollback
        drop(self);
    }

    /// Get the number of executed commands.
    pub fn len(&self) -> usize {
        self.executed.len()
    }

    /// Check if no commands have been executed.
    pub fn is_empty(&self) -> bool {
        self.executed.is_empty()
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn network_execution_requires_linux_engine() {
        let error = exec_cmd(&["ip".to_string()]).expect_err("non-Linux execution must fail");
        assert!(error.to_string().contains("Linux engine required"));
    }

    #[test]
    fn exec_empty_command_fails() {
        let result = exec_cmd(&[]);
        assert!(result.is_err());
        assert!(matches!(result, Err(ExecError::CommandFailed { .. })));
    }

    #[test]
    fn exec_invalid_command_fails() {
        let result = exec_cmd(&["nonexistent_command_12345".to_string()]);
        assert!(result.is_err());
        assert!(matches!(result, Err(ExecError::Io { .. })));
    }

    #[test]
    fn exec_true_succeeds() {
        let result = exec_cmd(&["true".to_string()]);
        assert!(result.is_ok());
    }

    #[test]
    fn exec_false_fails() {
        let result = exec_cmd(&["false".to_string()]);
        assert!(result.is_err());
        assert!(matches!(result, Err(ExecError::CommandFailed { .. })));
    }

    #[test]
    fn exec_stdin_capture_and_status_share_typed_boundary() {
        let output = exec_cmd_with_stdin(&["cat".to_string()], "wireguard-config")
            .expect("stdin command should succeed");
        assert_eq!(output, "wireguard-config");
        assert!(exec_cmd_status(&["true".to_string()]).expect("status command"));
        assert!(!exec_cmd_status(&["false".to_string()]).expect("status command"));
    }

    #[test]
    fn capability_gate_reports_missing_privilege_without_running_a_command() {
        let capabilities = HostCapabilities {
            linux: true,
            root: false,
            cap_net_admin: false,
            ip: true,
            nft: false,
            iptables: false,
            tc: false,
            wg: false,
        };
        assert!(matches!(
            capabilities.require_network_mutation(),
            Err(ExecError::CapabilityRequired { capability }) if capability == "root"
        ));
    }

    #[test]
    fn command_probe_uses_path_resolution_not_version_exit_status() {
        assert!(command_available("true"));
        assert!(!command_available("ferrocrate-command-that-does-not-exist"));
    }

    #[test]
    fn exec_echo_capture() {
        let result = exec_cmd_capture(&["echo".to_string(), "hello".to_string()]);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("hello"));
    }

    #[test]
    fn transaction_commits_on_success() {
        let mut txn = Transaction::new();
        let result = txn.add(vec!["true".to_string()], vec!["true".to_string()]);
        assert!(result.is_ok());
        assert_eq!(txn.len(), 1);
        txn.commit();
    }

    #[test]
    fn transaction_rollback_on_failure() {
        let mut txn = Transaction::new();
        // First command succeeds
        let result = txn.add(vec!["true".to_string()], vec!["true".to_string()]);
        assert!(result.is_ok());
        // Second command fails
        let result = txn.add(vec!["false".to_string()], vec!["true".to_string()]);
        assert!(result.is_err());
        // Transaction should be rolled back (executed cleared or rolled back)
    }

    #[test]
    fn transaction_no_rollback() {
        let mut txn = Transaction::new();
        let result = txn.add_no_rollback(vec!["true".to_string()]);
        assert!(result.is_ok());
        assert_eq!(txn.len(), 1);
    }

    #[test]
    fn allow_missing_classifies_absent_resource_stderr_without_shell_interpretation() {
        // Cleanup commands treat "resource already absent" stderr as success.
        let missing = exec_cmd_allow_missing(&[
            "sh".into(),
            "-c".into(),
            "echo 'ip: Cannot find device \"veth-gone\"' >&2; exit 1".into(),
        ]);
        assert!(missing.is_ok());
        let table = exec_cmd_allow_missing(&[
            "sh".into(),
            "-c".into(),
            "echo 'Error: No such file or directory' >&2; exit 1".into(),
        ]);
        assert!(table.is_ok());
        // Any other failure stays a failure.
        let hard = exec_cmd_allow_missing(&[
            "sh".into(),
            "-c".into(),
            "echo 'permission denied' >&2; exit 1".into(),
        ]);
        assert!(
            matches!(&hard, Err(ExecError::CommandFailed { stderr, .. }) if stderr.contains("permission denied"))
        );
        // Spawn failures are never silently swallowed.
        assert!(matches!(
            exec_cmd_allow_missing(&["nonexistent_command_12345".to_string()]),
            Err(ExecError::Io { .. })
        ));
    }

    #[test]
    fn transaction_rollback_undoes_executed_commands_in_reverse_order() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        let log = directory.path().join("rollback-order");
        let mut txn = Transaction::new();
        assert!(txn
            .add(
                vec!["touch".into(), first.to_str().expect("utf-8 path").into()],
                vec![
                    "sh".into(),
                    "-c".into(),
                    format!(
                        "rm {} && echo first >> {}",
                        first.to_str().expect("utf-8 path"),
                        log.to_str().expect("utf-8 path")
                    )
                ],
            )
            .is_ok());
        assert!(txn
            .add(
                vec!["touch".into(), second.to_str().expect("utf-8 path").into()],
                vec![
                    "sh".into(),
                    "-c".into(),
                    format!(
                        "rm {} && echo second >> {}",
                        second.to_str().expect("utf-8 path"),
                        log.to_str().expect("utf-8 path")
                    )
                ],
            )
            .is_ok());
        // Third command fails; both earlier commands must be rolled back,
        // newest first.
        assert!(txn.add(vec!["false".into()], vec![]).is_err());
        assert!(!first.exists());
        assert!(!second.exists());
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "second\nfirst\n",
            "rollback must run in reverse execution order"
        );
    }
}

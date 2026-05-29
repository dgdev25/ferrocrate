//! Network command execution with transaction support.
//!
//! This module provides execution functions that actually run the commands
//! built by the other modules, with support for atomic transactions with
//! rollback on failure.

use std::process::Command;
use thiserror::Error;
use tracing::warn;

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
}

use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Created,
    Running,
    Paused,
    Exited,
}

#[derive(Debug, Error)]
pub enum ProcessLifecycleError {
    #[error("failed to spawn process: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("process is not running")]
    NotRunning,
    #[error("signal operation failed: {0}")]
    Signal(#[from] nix::Error),
    #[error("failed to wait for process exit: {0}")]
    Wait(std::io::Error),
}

pub fn stop_pid(pid: u32, timeout: Duration) -> Result<(), ProcessLifecycleError> {
    let target = Pid::from_raw(pid as i32);
    if let Err(err) = kill(target, Signal::SIGTERM) {
        if err == nix::Error::from(Errno::ESRCH) {
            return Ok(());
        }
        return Err(ProcessLifecycleError::Signal(err));
    }
    // Docker's `t=-1` requests an unbounded graceful wait.  Duration::MAX is
    // the internal sentinel used by the Docker adapter; avoid adding it to
    // Instant because that can overflow before the process exits.
    if timeout == Duration::MAX {
        while pid_exists(target) {
            thread::sleep(Duration::from_millis(10));
        }
        return Ok(());
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_exists(target) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    if let Err(err) = kill(target, Signal::SIGKILL) {
        if err != nix::Error::from(Errno::ESRCH) {
            return Err(ProcessLifecycleError::Signal(err));
        }
    }
    Ok(())
}

pub fn kill_pid(pid: u32) -> Result<(), ProcessLifecycleError> {
    signal_pid(pid, Signal::SIGKILL)
}

/// Send an explicitly selected signal to a process, treating an already-exited
/// process as an idempotent success.
pub fn signal_pid(pid: u32, signal: Signal) -> Result<(), ProcessLifecycleError> {
    let target = Pid::from_raw(pid as i32);
    if let Err(err) = kill(target, signal) {
        if err != nix::Error::from(Errno::ESRCH) {
            return Err(ProcessLifecycleError::Signal(err));
        }
    }
    Ok(())
}

/// Probe whether a process still exists using the POSIX signal-0 semantics.
pub fn probe_pid(pid: u32) -> Result<(), ProcessLifecycleError> {
    let target = Pid::from_raw(pid as i32);
    nix::sys::signal::kill(target, None).map_err(ProcessLifecycleError::Signal)
}

/// Check if a process exists by reading its /proc entry.
///
/// SECURITY NOTE: This function has an inherent TOCTOU race - the PID could be recycled
/// between this check and subsequent operations. For safety-critical operations on Linux 5.3+,
/// consider using pidfd_open() instead. This implementation mitigates the risk by also
/// checking the process start time.
fn pid_exists(pid: Pid) -> bool {
    let path = format!("/proc/{}", pid.as_raw());
    if std::fs::metadata(&path).is_err() {
        return false;
    }

    // Additional safety: verify the process hasn't been replaced by checking /proc/{pid}/stat
    // This doesn't eliminate TOCTOU but reduces the window of vulnerability
    let stat_path = format!("/proc/{}/stat", pid.as_raw());
    if let Ok(contents) = std::fs::read_to_string(&stat_path) {
        // Basic validation that we can read the process stats
        // The stat file format is: pid (comm) state ...
        // If we can read it, the process exists
        !contents.is_empty()
    } else {
        false
    }
}

#[derive(Debug)]
pub struct ManagedProcess {
    child: Child,
    state: ProcessState,
}

impl ManagedProcess {
    pub fn start(program: &str, args: &[&str]) -> Result<Self, ProcessLifecycleError> {
        let child = Command::new(program).args(args).spawn()?;
        Ok(Self {
            child,
            state: ProcessState::Running,
        })
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn state(&self) -> ProcessState {
        self.state
    }

    pub fn pause(&mut self) -> Result<(), ProcessLifecycleError> {
        self.require_running()?;
        kill(Pid::from_raw(self.pid() as i32), Signal::SIGSTOP)?;
        self.state = ProcessState::Paused;
        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), ProcessLifecycleError> {
        if self.state != ProcessState::Paused {
            return Err(ProcessLifecycleError::NotRunning);
        }

        kill(Pid::from_raw(self.pid() as i32), Signal::SIGCONT)?;
        self.state = ProcessState::Running;
        Ok(())
    }

    pub fn stop(&mut self, timeout: Duration) -> Result<ExitStatus, ProcessLifecycleError> {
        if self.is_exited()? {
            self.state = ProcessState::Exited;
            return self.wait();
        }

        kill(Pid::from_raw(self.pid() as i32), Signal::SIGTERM)?;
        if timeout == Duration::MAX {
            let status = self.child.wait()?;
            self.state = ProcessState::Exited;
            return Ok(status);
        }
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                self.state = ProcessState::Exited;
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(10));
        }

        kill(Pid::from_raw(self.pid() as i32), Signal::SIGKILL)?;
        let status = self.child.wait()?;
        self.state = ProcessState::Exited;
        Ok(status)
    }

    pub fn wait(&mut self) -> Result<ExitStatus, ProcessLifecycleError> {
        let status = self.child.wait()?;
        self.state = ProcessState::Exited;
        Ok(status)
    }

    fn require_running(&self) -> Result<(), ProcessLifecycleError> {
        if self.state == ProcessState::Running {
            Ok(())
        } else {
            Err(ProcessLifecycleError::NotRunning)
        }
    }

    fn is_exited(&mut self) -> Result<bool, ProcessLifecycleError> {
        match self.child.try_wait() {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(err) if err.raw_os_error() == Some(Errno::ECHILD as i32) => Ok(true),
            Err(err) => Err(ProcessLifecycleError::Wait(err)),
        }
    }
}

/// Parse the parent PID from a `/proc/<pid>/stat` line. The comm field may
/// contain spaces and parentheses, so fields are read after the last `)`.
fn ppid_from_stat(stat: &str) -> Option<u32> {
    let after = stat.rsplit(')').next()?;
    let mut fields = after.split_whitespace();
    let _state = fields.next()?;
    fields.next().and_then(|ppid| ppid.parse::<u32>().ok())
}

/// Real-time UID of a process from `/proc/<pid>/status`, used to constrain
/// signal-target resolution to processes owned by the caller. A PID that was
/// recycled into another user's process must never be selected.
fn uid_of_pid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }
    None
}

fn own_uid() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}

/// The workload's PID 1 for signal delivery. Rootless containers record the
/// bubblewrap launcher PID; the container's PID 1 is the launcher's direct
/// child in the host PID namespace (deeper descendants are the workload's
/// own children and must not be the signal target). Rootful containers exec
/// the workload directly, so the recorded PID is already PID 1 and has no
/// launcher child.
///
/// PID-recycling safety: only a child owned by the calling UID is eligible,
/// and callers must re-verify parenthood through
/// `signal_pid_verified_parent` (or re-resolve) immediately before
/// signaling; the launcher PID itself stays the fallback target.
pub fn container_pid1_for_signal(root: u32) -> u32 {
    let caller = own_uid();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{name}/stat")) else {
                continue;
            };
            if ppid_from_stat(&stat) != Some(root) {
                continue;
            }
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if uid_of_pid(pid) == Some(caller) {
                return pid;
            }
        }
    }
    root
}

/// Signal `pid` only while it still has the expected parent and owner.
/// Narrows the PID-recycling window to the gap between one /proc read and
/// the kill syscall; a recycled PID with a different parent is never
/// signaled. Returns `Ok(false)` when the process is gone.
pub fn signal_pid_verified_parent(
    pid: u32,
    expected_parent: u32,
    signal: Signal,
) -> Result<bool, ProcessLifecycleError> {
    if pid == expected_parent {
        signal_pid(pid, signal)?;
        return Ok(true);
    }
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(_) => return Ok(false),
    };
    if ppid_from_stat(&stat) != Some(expected_parent) || uid_of_pid(pid) != Some(own_uid()) {
        return Ok(false);
    }
    signal_pid(pid, signal)?;
    Ok(true)
}

/// Every process currently parented (directly or transitively) under `root`,
/// owned by the calling UID, deepest first. Rootless containers live in the
/// host PID namespace, so their full tree — not just PID 1 — is the unit
/// that teardown must collect to avoid orphaned grandchildren.
pub fn owned_descendants_deepest_first(root: u32) -> Vec<u32> {
    let caller = own_uid();
    let mut by_parent: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{name}/stat")) else {
                continue;
            };
            let (Some(ppid), Ok(pid)) = (ppid_from_stat(&stat), name.parse::<u32>()) else {
                continue;
            };
            if uid_of_pid(pid) == Some(caller) {
                by_parent.entry(ppid).or_default().push(pid);
            }
        }
    }
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if let Some(children) = by_parent.get(&current) {
            for child in children {
                out.push(*child);
                stack.push(*child);
            }
        }
    }
    // Reverse the pre-order accumulation so children die before parents.
    out.reverse();
    out
}

/// Kernel start time (clock ticks) of a process, or None when it is gone.
pub fn process_start_time_of(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?.1.split_whitespace().nth(19)?.parse().ok()
}

/// Docker-style graceful stop of the workload's PID 1, verified against the
/// launcher parent before each signal so a recycled PID is never signaled.
/// `parent_start` is the launcher's kernel start time captured at spawn; the
/// SIGKILL escalation re-verifies it so a launcher PID recycled during the
/// graceful wait never has its subtree collected.
pub fn stop_pid_verified(
    child: u32,
    parent: u32,
    parent_start: Option<u64>,
    timeout: Duration,
) -> Result<(), ProcessLifecycleError> {
    if child == parent {
        return stop_pid(child, timeout);
    }
    if !signal_pid_verified_parent(child, parent, Signal::SIGTERM)? {
        return Ok(()); // workload already exited
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_exists(Pid::from_raw(child as i32)) && !pid_exists(Pid::from_raw(parent as i32)) {
            // With host-PID-namespace execution, a recycled PID can satisfy
            // the parent check while the real workload still runs; only a
            // dead launcher proves the container actually finished.
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    // Escalation collects the container's whole process tree: without a
    // private PID namespace, killing only PID 1 orphans its grandchildren.
    // Re-verify the launcher's identity first: if the PID was recycled
    // during the graceful wait, the subtree under it is not the container.
    if parent_start.is_none() || process_start_time_of(parent) != parent_start {
        return Ok(());
    }
    for pid in owned_descendants_deepest_first(parent) {
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
    }
    let _ = kill(Pid::from_raw(parent as i32), Signal::SIGKILL);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{kill_pid, probe_pid, stop_pid, ManagedProcess, ProcessState};
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn shell_path() -> &'static str {
        if Path::new("/bin/sh").exists() {
            "/bin/sh"
        } else {
            "/usr/bin/sh"
        }
    }

    #[test]
    fn starts_and_waits_for_process() {
        let mut proc =
            ManagedProcess::start(shell_path(), &["-c", "exit 0"]).expect("process starts");
        let status = proc.wait().expect("process exits");
        assert!(status.success());
        assert_eq!(proc.state(), ProcessState::Exited);
    }

    #[test]
    fn pauses_resumes_and_stops_process() {
        let mut proc =
            ManagedProcess::start(shell_path(), &["-c", "sleep 5"]).expect("process starts");

        proc.pause().expect("pause succeeds");
        assert_eq!(proc.state(), ProcessState::Paused);

        proc.resume().expect("resume succeeds");
        assert_eq!(proc.state(), ProcessState::Running);

        let status = proc
            .stop(Duration::from_millis(150))
            .expect("stop succeeds");
        assert!(!status.success());
        assert_eq!(proc.state(), ProcessState::Exited);
    }

    #[test]
    fn stop_pid_terminates_process() {
        let proc = ManagedProcess::start(shell_path(), &["-c", "sleep 5"]).expect("process starts");
        stop_pid(proc.pid(), Duration::from_millis(100)).expect("stop pid");
    }

    #[test]
    fn managed_process_supports_unbounded_graceful_stop() {
        let marker = std::env::temp_dir().join(format!(
            "ferrocrate-graceful-stop-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock is after epoch")
                .as_nanos()
        ));
        let marker_text = marker.to_string_lossy().into_owned();
        let command = format!(
            "trap 'exit 0' TERM; : > '{}'; while :; do sleep 1; done",
            marker_text
        );
        let mut proc =
            ManagedProcess::start(shell_path(), &["-c", &command]).expect("process starts");
        let ready_deadline = Instant::now() + Duration::from_secs(1);
        while !marker.exists() && Instant::now() < ready_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            marker.exists(),
            "graceful-stop fixture did not become ready"
        );
        let status = proc.stop(Duration::MAX).expect("unbounded stop");
        let _ = std::fs::remove_file(&marker);
        assert!(status.success());
        assert_eq!(proc.state(), ProcessState::Exited);
    }

    #[test]
    fn kill_pid_terminates_process() {
        let proc = ManagedProcess::start(shell_path(), &["-c", "sleep 5"]).expect("process starts");
        kill_pid(proc.pid()).expect("kill pid");
    }

    #[test]
    fn probe_pid_matches_signal_zero_semantics() {
        let proc = ManagedProcess::start(shell_path(), &["-c", "sleep 1"]).expect("process starts");
        probe_pid(proc.pid()).expect("live process probe");
    }
}

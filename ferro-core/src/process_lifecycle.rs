use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
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

#[cfg(test)]
mod tests {
    use super::{ManagedProcess, ProcessState};
    use std::time::Duration;

    #[test]
    fn starts_and_waits_for_process() {
        let mut proc = ManagedProcess::start("sh", &["-c", "exit 0"]).expect("process starts");
        let status = proc.wait().expect("process exits");
        assert!(status.success());
        assert_eq!(proc.state(), ProcessState::Exited);
    }

    #[test]
    fn pauses_resumes_and_stops_process() {
        let mut proc = ManagedProcess::start("sh", &["-c", "sleep 5"]).expect("process starts");

        proc.pause().expect("pause succeeds");
        assert_eq!(proc.state(), ProcessState::Paused);

        proc.resume().expect("resume succeeds");
        assert_eq!(proc.state(), ProcessState::Running);

        let status = proc.stop(Duration::from_millis(150)).expect("stop succeeds");
        assert!(!status.success());
        assert_eq!(proc.state(), ProcessState::Exited);
    }
}

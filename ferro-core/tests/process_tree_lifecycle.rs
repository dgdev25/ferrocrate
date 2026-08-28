#![cfg(target_os = "linux")]

use ferro_core::process_lifecycle::{
    process_start_time_of, signal_process_group_verified, stop_pid_verified,
};
use nix::sys::signal::Signal;
use std::fs;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct LauncherTree {
    launcher: Child,
    child_pid: u32,
    progress: std::path::PathBuf,
    _temp: TempDir,
}

impl LauncherTree {
    fn spawn() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let child_pid_file = temp.path().join("child.pid");
        let progress = temp.path().join("progress");
        let script = format!(
            "sh -c 'trap \"\" TERM; while :; do echo tick >> {}; sleep 0.02; done' & echo $! > {}; wait",
            progress.display(),
            child_pid_file.display()
        );
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if nix::libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let launcher = command.spawn().expect("spawn launcher");
        let deadline = Instant::now() + Duration::from_secs(2);
        let child_pid = loop {
            if let Ok(raw) = fs::read_to_string(&child_pid_file) {
                if let Ok(pid) = raw.trim().parse() {
                    break pid;
                }
            }
            assert!(Instant::now() < deadline, "child pid was not published");
            thread::sleep(Duration::from_millis(10));
        };
        Self {
            launcher,
            child_pid,
            progress,
            _temp: temp,
        }
    }

    fn progress_len(&self) -> u64 {
        fs::metadata(&self.progress)
            .map(|meta| meta.len())
            .unwrap_or(0)
    }
}

impl Drop for LauncherTree {
    fn drop(&mut self) {
        unsafe {
            nix::libc::kill(-(self.launcher.id() as i32), nix::libc::SIGKILL);
        }
        let _ = self.launcher.wait();
        unsafe {
            nix::libc::kill(self.child_pid as i32, nix::libc::SIGKILL);
        }
    }
}

fn pid_is_live(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| stat.rsplit_once(')').map(|(_, fields)| fields.to_string()))
        .and_then(|fields| fields.split_whitespace().next().map(str::to_string))
        .is_some_and(|state| state != "Z")
}

#[test]
fn verified_stop_collects_launcher_child_in_its_owned_process_group() {
    let mut tree = LauncherTree::spawn();
    let launcher_pid = tree.launcher.id();
    let launcher_start = process_start_time_of(launcher_pid);

    stop_pid_verified(
        launcher_pid,
        launcher_pid,
        launcher_start,
        Duration::from_millis(100),
    )
    .expect("verified stop");
    let _ = tree.launcher.wait();
    let deadline = Instant::now() + Duration::from_secs(1);
    while pid_is_live(tree.child_pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        !pid_is_live(tree.child_pid),
        "container child {} survived launcher stop",
        tree.child_pid
    );
}

#[test]
fn verified_stop_prevents_orphaned_child_from_continuing_work() {
    let tree = LauncherTree::spawn();
    let launcher_pid = tree.launcher.id();
    let launcher_start = process_start_time_of(launcher_pid);
    thread::sleep(Duration::from_millis(80));

    stop_pid_verified(
        launcher_pid,
        launcher_pid,
        launcher_start,
        Duration::from_millis(100),
    )
    .expect("verified stop");
    let before = tree.progress_len();
    thread::sleep(Duration::from_millis(120));
    let after = tree.progress_len();

    assert_eq!(before, after, "orphaned workload continued making progress");
}

#[test]
fn verified_group_pause_blocks_child_progress_until_resume() {
    let tree = LauncherTree::spawn();
    let launcher_pid = tree.launcher.id();
    let launcher_start = process_start_time_of(launcher_pid);
    thread::sleep(Duration::from_millis(80));

    assert!(
        signal_process_group_verified(launcher_pid, launcher_start, Signal::SIGSTOP)
            .expect("pause group")
    );
    thread::sleep(Duration::from_millis(40));
    let paused = tree.progress_len();
    thread::sleep(Duration::from_millis(120));
    assert_eq!(paused, tree.progress_len(), "paused child made progress");

    assert!(
        signal_process_group_verified(launcher_pid, launcher_start, Signal::SIGCONT)
            .expect("resume group")
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    while tree.progress_len() == paused && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        tree.progress_len() > paused,
        "resumed child made no progress"
    );
}

#[test]
fn mismatched_leader_identity_does_not_signal_process_group() {
    let tree = LauncherTree::spawn();
    let launcher_pid = tree.launcher.id();
    let wrong_start = process_start_time_of(launcher_pid).map(|value| value.saturating_add(1));

    assert!(
        !signal_process_group_verified(launcher_pid, wrong_start, Signal::SIGSTOP)
            .expect("reject mismatched identity")
    );
    let before = tree.progress_len();
    thread::sleep(Duration::from_millis(100));
    assert!(
        tree.progress_len() > before,
        "unrelated group was signalled"
    );
}

#![cfg(target_os = "linux")]

//! Opt-in rootless cgroup-v2 qualification.
//!
//! Run on a delegated-user-cgroup host with:
//! `FERROCRATE_RUN_ROOTLESS_LIMITS_E2E=1 cargo test -p ferro-cli --test
//! rootless_limits_integration -- --nocapture`.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

#[test]
fn rootless_run_attaches_before_workload_and_applies_limits() {
    if std::env::var("FERROCRATE_RUN_ROOTLESS_LIMITS_E2E").as_deref() != Ok("1") {
        return;
    }
    assert!(
        !nix::unistd::Uid::effective().is_root(),
        "run this fixture as a non-root user"
    );

    let root = tempfile::tempdir().expect("runtime tempdir");
    let runtime = root.path().join("runtime");
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    let pull = Command::new(binary)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .args(["pull", "alpine:3.20"])
        .output()
        .expect("pull alpine");
    assert!(
        pull.status.success(),
        "rootless pull failed: {}",
        String::from_utf8_lossy(&pull.stderr)
    );

    let mut run = Command::new(binary)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--name",
            "rootless-limits",
            "--memory-max",
            "16777216",
            "--pids-max",
            "32",
            "alpine:3.20",
            "sh",
            "-c",
            "sleep 30",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rootless run");

    let stdout = run.stdout.take().expect("run stdout");
    let mut lines = BufReader::new(stdout).lines();
    let line = lines
        .next()
        .expect("run output line")
        .expect("read run output");
    let pid = line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("pid=")?.parse::<u32>().ok())
        .expect("container pid in run output");

    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .expect("container cgroup membership");
    let relative = cgroup
        .lines()
        .find_map(|entry| entry.strip_prefix("0::"))
        .expect("unified cgroup membership")
        .trim_start_matches('/');
    let path = std::path::Path::new("/sys/fs/cgroup").join(relative);
    assert!(
        path.starts_with("/sys/fs/cgroup/"),
        "unsafe cgroup path: {path:?}"
    );
    assert_eq!(
        std::fs::read_to_string(path.join("memory.max"))
            .expect("memory.max")
            .trim(),
        "16777216"
    );
    assert_eq!(
        std::fs::read_to_string(path.join("pids.max"))
            .expect("pids.max")
            .trim(),
        "32"
    );
    let procs = std::fs::read_to_string(path.join("cgroup.procs")).expect("cgroup.procs");
    assert!(
        procs.lines().any(|entry| entry.trim() == pid.to_string()),
        "container pid {pid} was not attached to {path:?}: {procs}"
    );

    run.kill().expect("stop rootless run");
    let _ = run.wait();
}

#![cfg(target_os = "linux")]

//! Opt-in rootless cgroup-v2 qualification.
//!
//! Run on a delegated-user-cgroup host with:
//! `FERROCRATE_RUN_ROOTLESS_LIMITS_E2E=1 cargo test -p ferro-cli --test
//! rootless_limits_integration -- --nocapture`.

use std::io::{BufRead, BufReader, Read};
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
    let image = std::env::var("FERROCRATE_ROOTLESS_TEST_IMAGE")
        .unwrap_or_else(|_| "alpine:3.20".to_string());
    let pull = Command::new(binary)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .args(["pull", &image])
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
            &image,
            "sh",
            "-c",
            "sleep 30",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rootless run");

    let stdout = run.stdout.take().expect("run stdout");
    let mut stderr = run.stderr.take().expect("run stderr");
    let mut lines = BufReader::new(stdout).lines();
    let line = match lines.next() {
        Some(line) => line.expect("read run output"),
        None => {
            let mut error = String::new();
            stderr.read_to_string(&mut error).expect("read run error");
            panic!("run output line missing: {error}");
        }
    };
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

#[test]
fn rootless_run_reports_pid_limit_exhaustion() {
    if std::env::var("FERROCRATE_RUN_ROOTLESS_LIMITS_E2E").as_deref() != Ok("1") {
        return;
    }
    assert!(!nix::unistd::Uid::effective().is_root());

    let root = tempfile::tempdir().expect("runtime tempdir");
    let runtime = root.path().join("runtime");
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    let image = std::env::var("FERROCRATE_ROOTLESS_TEST_IMAGE")
        .unwrap_or_else(|_| "alpine:3.20".to_string());
    let pull = Command::new(binary)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .args(["pull", &image])
        .output()
        .expect("pull rootless test image");
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
            "rootless-pid-exhaustion",
            "--pids-max",
            "64",
            &image,
            "sh",
            "-c",
            r#"i=0; while [ "$i" -lt 128 ]; do sleep 30 & i=$((i+1)); done; wait"#,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rootless exhaustion run");

    let stdout = run.stdout.take().expect("run stdout");
    let mut stderr = run.stderr.take().expect("run stderr");
    let mut lines = BufReader::new(stdout).lines();
    let line = match lines.next() {
        Some(line) => line.expect("read run output"),
        None => {
            let mut error = String::new();
            stderr.read_to_string(&mut error).expect("read run error");
            panic!("run output line missing: {error}");
        }
    };
    let pid = line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("pid=")?.parse::<u32>().ok())
        .expect("container pid in run output");
    let relative = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .expect("container cgroup membership")
        .lines()
        .find_map(|entry| entry.strip_prefix("0::"))
        .expect("unified cgroup membership")
        .trim_start_matches('/')
        .to_string();
    let cgroup = std::path::Path::new("/sys/fs/cgroup").join(relative);
    let events = cgroup.join("pids.events");
    let mut exhausted = false;
    for _ in 0..100 {
        if std::fs::read_to_string(&events)
            .ok()
            .and_then(|value| {
                value.lines().find_map(|line| {
                    let mut fields = line.split_whitespace();
                    (fields.next() == Some("max")).then(|| fields.next()?.parse::<u64>().ok())?
                })
            })
            .is_some_and(|count| count > 0)
        {
            exhausted = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        exhausted,
        "pids.max exhaustion was not observed in {}: {}",
        events.display(),
        std::fs::read_to_string(&events).unwrap_or_else(|error| error.to_string())
    );
    run.kill().expect("stop rootless exhaustion run");
    let _ = run.wait();
}

#[test]
fn rootless_run_reports_memory_oom_event() {
    if std::env::var("FERROCRATE_RUN_ROOTLESS_LIMITS_E2E").as_deref() != Ok("1") {
        return;
    }
    assert!(!nix::unistd::Uid::effective().is_root());

    let root = tempfile::tempdir().expect("runtime tempdir");
    let runtime = root.path().join("runtime");
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    let image = std::env::var("FERROCRATE_ROOTLESS_TEST_IMAGE")
        .unwrap_or_else(|_| "alpine:3.20".to_string());
    let pull = Command::new(binary)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .args(["pull", &image])
        .output()
        .expect("pull rootless test image");
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
            "rootless-memory-oom",
            "--memory-max",
            "16777216",
            &image,
            "sh",
            "-c",
            r#"( x=x; i=0; while [ "$i" -lt 28 ]; do x="$x$x"; i=$((i+1)); done; sleep 30 ) & sleep 30"#,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rootless OOM run");

    let stdout = run.stdout.take().expect("run stdout");
    let mut stderr = run.stderr.take().expect("run stderr");
    let mut lines = BufReader::new(stdout).lines();
    let line = match lines.next() {
        Some(line) => line.expect("read run output"),
        None => {
            let mut error = String::new();
            stderr.read_to_string(&mut error).expect("read run error");
            panic!("run output line missing: {error}");
        }
    };
    let pid = line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("pid=")?.parse::<u32>().ok())
        .expect("container pid in run output");
    let relative = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .expect("container cgroup membership")
        .lines()
        .find_map(|entry| entry.strip_prefix("0::"))
        .expect("unified cgroup membership")
        .trim_start_matches('/')
        .to_string();
    let events = std::path::Path::new("/sys/fs/cgroup")
        .join(relative)
        .join("memory.events");
    let mut oom = false;
    for _ in 0..100 {
        if std::fs::read_to_string(&events)
            .ok()
            .map(|value| {
                value.lines().any(|line| {
                    let mut fields = line.split_whitespace();
                    matches!(fields.next(), Some("oom" | "oom_kill"))
                        && fields
                            .next()
                            .and_then(|count| count.parse::<u64>().ok())
                            .is_some_and(|count| count > 0)
                })
            })
            .unwrap_or(false)
        {
            oom = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        oom,
        "memory OOM event was not observed in {}: {}",
        events.display(),
        std::fs::read_to_string(&events).unwrap_or_else(|error| error.to_string())
    );
    run.kill().expect("stop rootless OOM run");
    let _ = run.wait();
}

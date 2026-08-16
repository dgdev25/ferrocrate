#![cfg(target_os = "linux")]

use ferro_core::container_exec::build_nsenter_args;
use ferro_core::process_lifecycle::{ManagedProcess, ProcessState};
use std::time::Duration;

#[test]
fn lifecycle_start_stop_flow_works() {
    let mut proc = ManagedProcess::start("sh", &["-c", "sleep 3"]).expect("process starts");
    assert_eq!(proc.state(), ProcessState::Running);

    let status = proc
        .stop(Duration::from_millis(200))
        .expect("process should stop");

    assert!(!status.success());
    assert_eq!(proc.state(), ProcessState::Exited);
}

#[test]
fn lifecycle_pause_resume_stop_flow_works() {
    let mut proc = ManagedProcess::start("sh", &["-c", "sleep 3"]).expect("process starts");

    proc.pause().expect("pause works");
    assert_eq!(proc.state(), ProcessState::Paused);

    proc.resume().expect("resume works");
    assert_eq!(proc.state(), ProcessState::Running);

    proc.stop(Duration::from_millis(200))
        .expect("stop works after resume");
    assert_eq!(proc.state(), ProcessState::Exited);
}

#[test]
fn lifecycle_exec_command_builder_targets_process() {
    let mut proc = ManagedProcess::start("sh", &["-c", "sleep 3"]).expect("process starts");
    let args = build_nsenter_args(
        proc.pid(),
        &[
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo hi".to_string(),
        ],
    )
    .expect("args build");

    assert_eq!(args[0], "-t");
    assert_eq!(args[1], proc.pid().to_string());
    assert_eq!(args[2], "-a");

    proc.stop(Duration::from_millis(200))
        .expect("process cleanup should succeed");
}

#[test]
#[ignore = "sustained reliability gate"]
fn lifecycle_handles_100_concurrent_processes() {
    let count = std::env::var("FERROCRATE_SUSTAINED_COUNT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 256);
    let mut processes = Vec::with_capacity(count);
    for _ in 0..count {
        processes
            .push(ManagedProcess::start("sleep", &["5"]).expect("sustained process should start"));
    }
    assert!(processes
        .iter()
        .all(|process| process.state() == ProcessState::Running));
    for process in &mut processes {
        process
            .stop(Duration::from_millis(500))
            .expect("sustained process should stop");
        assert_eq!(process.state(), ProcessState::Exited);
    }
}

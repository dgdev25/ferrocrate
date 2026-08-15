#![cfg(target_os = "linux")]

use ferro_core::container_store::{ContainerRecord, LocalContainerStore};
use std::process::Command;

#[test]
fn compose_down_stop_failure_explicitly_skips_dependent_delete() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("compose.yml"),
        "services:\n  web:\n    image: example/web:latest\n",
    )
    .unwrap();
    let record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id": "00112233445566778899aabbccddeeff",
        "name": "web",
        "pid": 1,
        "image": "example/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "command": ["sleep", "60"],
        "created_at_unix": 1,
        "stdout_path": root.path().join("stdout.log"),
        "stderr_path": root.path().join("stderr.log"),
        "status": "running",
        "mutation_generation": 1
    }))
    .unwrap();
    let store = LocalContainerStore::open(root.path().join("containers.db")).unwrap();
    store.put(&record).unwrap();
    drop(store);

    let output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .current_dir(&project)
        .env("FERROCRATE_RUNTIME_DIR", root.path())
        .args(["compose", "--file", "compose.yml", "down"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("stop failed; delete skipped"));
    let store = LocalContainerStore::open(root.path().join("containers.db")).unwrap();
    assert!(store.get(&record.id).unwrap().is_some());
}

#[test]
fn compose_down_stops_then_deletes_using_post_stop_record() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("compose.yml"),
        "services:\n  web:\n    image: example/web:latest\n",
    )
    .unwrap();
    let child = Command::new("sleep").arg("60").spawn().unwrap();
    let pid = child.id();
    // Reap SIGTERM promptly. Otherwise the child remains a zombie owned by this
    // test process and the independent CLI correctly treats /proc/<pid> as live.
    let reaper = std::thread::spawn(move || {
        let mut child = child;
        child.wait().unwrap()
    });
    let record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id": "00112233445566778899aabbccddeeff",
        "name": "web",
        "pid": pid,
        "image": "example/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "command": ["sleep", "60"],
        "created_at_unix": 1,
        "stdout_path": root.path().join("stdout.log"),
        "stderr_path": root.path().join("stderr.log"),
        "status": "running",
        "mutation_generation": 1
    }))
    .unwrap();
    let store = LocalContainerStore::open(root.path().join("containers.db")).unwrap();
    store.put(&record).unwrap();
    drop(store);

    let output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .current_dir(&project)
        .env("FERROCRATE_RUNTIME_DIR", root.path())
        .args(["compose", "--file", "compose.yml", "down"])
        .output()
        .unwrap();
    reaper.join().unwrap();
    assert!(
        output.status.success(),
        "compose down failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let store = LocalContainerStore::open(root.path().join("containers.db")).unwrap();
    assert!(store.get(&record.id).unwrap().is_none());
}

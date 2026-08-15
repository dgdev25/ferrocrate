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
    let mut child = Command::new("sleep").arg("60").spawn().unwrap();
    let record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id": "00112233445566778899aabbccddeeff",
        "name": "web",
        "pid": child.id(),
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
    let _ = child.wait();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("stop failed; delete skipped"));
    let store = LocalContainerStore::open(root.path().join("containers.db")).unwrap();
    assert!(store.get(&record.id).unwrap().is_some());
}

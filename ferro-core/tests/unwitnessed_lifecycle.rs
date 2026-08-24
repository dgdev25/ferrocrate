#![cfg(target_os = "linux")]
#![cfg(target_os = "linux")]

use ferro_core::authorization::RequestOrigin;
use ferro_core::container_store::ContainerRecord;
use ferro_core::runtime::ContainerRuntime;
use ferro_core::sqlite_container_store::SqliteContainerStore;
use std::process::Command;
use std::time::Duration;

fn process_start_time(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    stat.rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn unwitnessed_lifecycle_consumes_its_durable_reservation() {
    let root = tempfile::tempdir().unwrap();
    let child = Command::new("sleep").arg("60").spawn().unwrap();
    let pid = child.id();
    let reaper = std::thread::spawn(move || {
        let mut child = child;
        child.wait().unwrap()
    });
    let mut record: ContainerRecord = serde_json::from_value(serde_json::json!({
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
    record.process_start_time = Some(process_start_time(pid));
    SqliteContainerStore::open(root.path().join("containers.db"))
        .unwrap()
        .put(&record)
        .unwrap();
    let runtime = ContainerRuntime::new(root.path())
        .unwrap()
        .with_request_origin(RequestOrigin::cli_current().unwrap());
    runtime.stop(&record.id, Duration::from_secs(2)).unwrap();
    reaper.join().unwrap();
    let stopped = runtime.inspect(&record.id).unwrap();
    assert_eq!(stopped.status, "stopped");
    assert_eq!(stopped.mutation_generation, 2);
    assert!(stopped.pending_mutation.is_none());
    runtime.remove(&record.id).unwrap();
    assert!(runtime.list().unwrap().is_empty());
}

#![cfg(target_os = "linux")]

#[path = "cli_integration.rs"]
mod cli_fixture;

use ferro_core::container_store::{ContainerRecord, CreationProvenance};
use ferro_core::sqlite_container_store::SqliteContainerStore;
use std::process::Command;

fn compose_project(root: &std::path::Path) -> std::path::PathBuf {
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("compose.yml"),
        "services:\n  web:\n    image: example/web:latest\n",
    )
    .unwrap();
    project
}

/// Kernel start time (clock ticks) of a live process, read the same way the
/// runtime's identity check reads it. Test-local because the core helper is
/// crate-private.
fn start_time_of(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn live_web_record(
    root: &std::path::Path,
    witnessed: bool,
) -> (
    ContainerRecord,
    std::thread::JoinHandle<std::process::ExitStatus>,
) {
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
            "stdout_path": root.join("stdout.log"),
            "stderr_path": root.join("stderr.log"),
            "status": "running",
            "mutation_generation": 1
        }))
        .unwrap();
    // A live workload must carry the identity the runtime verifies before
    // signaling; without it, stop treats the PID as recycled and no-ops.
    record.process_start_time = start_time_of(pid);
    assert!(
        record.process_start_time.is_some(),
        "live fixture process must have a readable start time"
    );
    if witnessed {
        // Initialize through the production loader, then bind the persisted
        // record to that runtime's durable identity. This models a record
        // previously created by the same runtime; enabled cleanup refuses a
        // legacy record without this persisted provenance.
        ferro_core::runtime::ContainerRuntime::new(root).unwrap();
        let runtime_id: [u8; 16] = std::fs::read(root.join("runtime-instance-id"))
            .unwrap()
            .try_into()
            .unwrap();
        let compact = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
            .replace('-', "");
        let mut boot_id = [0; 16];
        for (index, slot) in boot_id.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).unwrap();
        }
        record.creation_provenance = CreationProvenance {
            runtime_instance_id: Some(runtime_id),
            boot_id: Some(boot_id),
            journal_id: Some([0x44; 16]),
            resource_uuid: Some("00112233-4455-6677-8899-aabbccddeeff".into()),
            resource_generation: 1,
            creator_operation_id: Some([0x61; 16]),
            image_digest: None,
        };
    }
    (record, reaper)
}

#[test]
fn compose_down_treats_unverifiable_pid_as_exited_and_deletes() {
    // The record carries a live PID (host init) with no stored process
    // identity, so the runtime can prove the PID is not the container's
    // workload and must send no signal at all. Down publishes the stop and
    // deletes the record. The previous version of this test asserted the
    // opposite ("stop fails, delete skipped"): stopping this fixture made
    // the runtime signal a caller-owned child of PID 1 and, on timeout,
    // escalate to SIGKILL of every process the test user owns — which is
    // why broad test runs killed the operator's desktop session. A real
    // stop-failure path needs a fault-injection fixture, not a foreign PID.
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
        // PID 1 is live but owned by the host init process. An unprivileged
        // caller cannot signal it, so the stop phase fails before deletion;
        // unlike an absent PID, it is not converted to an exited record by
        // startup reconciliation.
        "pid": 1u64,
        "image": "example/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "command": ["sleep", "60"],
        "created_at_unix": 1,
        "stdout_path": root.path().join("stdout.log"),
        "stderr_path": root.path().join("stderr.log"),
        "status": "running",
        "mutation_generation": 1
    }))
    .unwrap();
    let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
    store.put(&record).unwrap();
    drop(store);

    let output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .current_dir(&project)
        .env("FERROCRATE_RUNTIME_DIR", root.path())
        .args(["compose", "--file", "compose.yml", "down"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "down must succeed for an unverifiable PID: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
    assert!(
        store.get(&record.id).unwrap().is_none(),
        "record must be deleted once the workload is provably gone"
    );
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
    let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
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
    let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
    assert!(store.get(&record.id).unwrap().is_none());
}

/// Exercises the public Compose command against the production active-policy
/// and signed-admission loader in every rollout mode.  Disabled and shadow
/// retain the actual stop/delete effect; enforce rejects before that effect.
#[test]
fn public_compose_down_preserves_disabled_shadow_and_enforce_contracts() {
    for mode in ["disabled", "shadow"] {
        let root = cli_fixture::configured_runtime(mode);
        let project = compose_project(root.path());
        let (record, reaper) = live_web_record(root.path(), mode != "disabled");
        let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
        store.put(&record).unwrap();
        drop(store);

        let output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
            .current_dir(&project)
            .env("FERROCRATE_RUNTIME_DIR", root.path())
            .env(
                "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
                format!("compose-{mode}"),
            )
            .args(["compose", "--file", "compose.yml", "down"])
            .output()
            .unwrap();
        reaper.join().unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
        assert!(
            store.get(&record.id).unwrap().is_none(),
            "{mode} retained record"
        );
    }

    let root = cli_fixture::configured_runtime("enforce");
    let project = compose_project(root.path());
    let (record, reaper) = live_web_record(root.path(), true);
    let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
    store.put(&record).unwrap();
    drop(store);
    let output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .current_dir(&project)
        .env("FERROCRATE_RUNTIME_DIR", root.path())
        .env(
            "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
            "compose-enforce",
        )
        .args(["compose", "--file", "compose.yml", "down"])
        .output()
        .unwrap();
    if nix::unistd::geteuid().is_root() {
        // Root is the native administrator and is intentionally allowed by
        // the enforce policy; assert that administrator success contract.
        reaper.join().unwrap();
        assert!(
            output.status.success(),
            "root administrator must be allowed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
        assert!(store.get(&record.id).unwrap().is_none());
        return;
    }
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("PolicyDenied"),
        "stable enforce response: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let store = SqliteContainerStore::open(root.path().join("containers.db")).unwrap();
    assert!(
        store.get(&record.id).unwrap().is_some(),
        "enforce changed state"
    );
    // The rejected mutation must not stop the real process either.
    assert!(std::path::Path::new(&format!("/proc/{}", record.pid)).exists());
    let _ = Command::new("kill")
        .args(["-TERM", &record.pid.to_string()])
        .status();
    reaper.join().unwrap();
}

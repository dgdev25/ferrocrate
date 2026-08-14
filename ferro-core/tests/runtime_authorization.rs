use ferro_core::authorization::{gate::AuthorizationGate, policy::PolicyStore};
use ferro_core::container_store::CreationProvenance;
use ferro_core::container_store::{ContainerRecord, LocalContainerStore};
use ferro_core::runtime::{
    ContainerRuntime, LifecyclePhaseHook, LifecyclePhasePoint, RuntimeError,
};
use ferro_core::witness::{
    decode_record, JournalConfig, JournalMode, WitnessJournal, WitnessStage,
};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::{MutexGuard, OnceLock};

fn runtime_test_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

#[derive(Default)]
struct RecordingPhaseHook(Mutex<Vec<LifecyclePhasePoint>>);
impl LifecyclePhaseHook for RecordingPhaseHook {
    fn reached(&self, _action: &str, phase: LifecyclePhasePoint) -> Result<(), RuntimeError> {
        self.0.lock().unwrap().push(phase);
        Ok(())
    }
}

#[test]
fn exec_exposes_every_durable_crash_boundary_in_order() {
    let _guard = runtime_test_guard();
    let root = tempfile::tempdir().unwrap();
    let policy_path = root.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        "schema_version = 1\ngeneration = 1\nmode = \"disabled\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let gate = Arc::new(AuthorizationGate::new(Arc::new(
        PolicyStore::load(&policy_path).unwrap(),
    )));
    let journal = Arc::new(
        WitnessJournal::open(JournalConfig::new(
            root.path().join("witness"),
            [61; 16],
            JournalMode::Required,
        ))
        .unwrap(),
    );
    let store = LocalContainerStore::open(root.path().join("containers.db")).unwrap();
    let record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id":"00112233445566778899aabbccddeeff", "pid":std::process::id(),
        "image":"example.invalid/app:latest", "command":["true"],
        "created_at_unix":1, "stdout_path":"", "stderr_path":"", "status":"running"
    }))
    .unwrap();
    store.put(&record).unwrap();
    drop(store);
    let hook = Arc::new(RecordingPhaseHook::default());
    let runtime = ContainerRuntime::new_with_authorization_and_phase_hook(
        root.path(),
        gate,
        Some(journal),
        hook.clone(),
    )
    .unwrap();
    runtime.exec(&record.id, &["true".into()]).unwrap();
    assert_eq!(
        *hook.0.lock().unwrap(),
        [
            LifecyclePhasePoint::DecisionDurable,
            LifecyclePhasePoint::ReservationDurable,
            LifecyclePhasePoint::EffectObserved,
            LifecyclePhasePoint::TerminalDurable,
            LifecyclePhasePoint::ReservationCleared,
        ]
    );
}

#[test]
fn creation_provenance_is_absent_for_legacy_records() {
    let value: CreationProvenance = serde_json::from_str("null").unwrap_or_default();
    assert!(!value.is_verifiable());
}

#[test]
fn denied_exec_is_witnessed_once_and_has_no_side_effect() {
    let _guard = runtime_test_guard();
    let root = tempfile::tempdir().unwrap();
    let policy_path = root.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        "schema_version = 1\ngeneration = 1\nmode = \"enforce\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let gate = Arc::new(AuthorizationGate::new(Arc::new(
        PolicyStore::load(&policy_path).unwrap(),
    )));
    let witness_root = root.path().join("witness");
    let journal = Arc::new(
        WitnessJournal::open(JournalConfig::new(
            &witness_root,
            [9; 16],
            JournalMode::Required,
        ))
        .unwrap(),
    );
    let store = LocalContainerStore::open(root.path().join("containers.db")).unwrap();
    let record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id":"00112233445566778899aabbccddeeff", "pid":4294967295u32,
        "image":"example.invalid/app:latest", "command":["true"],
        "created_at_unix":1, "stdout_path":"", "stderr_path":"", "status":"stopped"
    }))
    .unwrap();
    store.put(&record).unwrap();
    drop(store);
    let runtime =
        ContainerRuntime::new_with_authorization(root.path(), gate, Some(journal.clone())).unwrap();

    let secret_canary = "SUPER_SECRET_RUNTIME_CANARY";
    let error = runtime
        .exec(
            &record.id,
            &[
                secret_canary.into(),
                root.path().join("forbidden").display().to_string(),
            ],
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("authorization denied"),
        "{error}"
    );
    assert!(!root.path().join("forbidden").exists());
    let records = journal.records().unwrap();
    assert!(records.iter().all(|bytes| !bytes
        .windows(secret_canary.len())
        .any(|window| window == secret_canary.as_bytes())));
    assert_eq!(records.len(), 3);
    let decoded = records
        .iter()
        .map(|bytes| decode_record(bytes).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(decoded[0].stage(), WitnessStage::RequestReceived);
    assert_eq!(decoded[1].stage(), WitnessStage::Decision);
    assert_eq!(decoded[2].stage(), WitnessStage::Denied);
}

#[test]
fn runtime_instance_identity_survives_same_directory_restart() {
    let root = tempfile::tempdir().unwrap();
    let runtime = ContainerRuntime::new(root.path()).unwrap();
    drop(runtime);
    let first = std::fs::read(root.path().join("runtime-instance-id")).unwrap();
    assert_eq!(first.len(), 16);
    let runtime = ContainerRuntime::new(root.path()).unwrap();
    drop(runtime);
    assert_eq!(
        std::fs::read(root.path().join("runtime-instance-id")).unwrap(),
        first
    );
}

#[test]
fn every_lifecycle_method_denies_once_before_executor_side_effects() {
    let _guard = runtime_test_guard();
    for action in [
        "run", "exec", "pause", "resume", "stop", "kill", "restart", "remove",
    ] {
        let root = tempfile::tempdir().unwrap();
        let policy_path = root.path().join("policy.toml");
        std::fs::write(
            &policy_path,
            "schema_version = 1\ngeneration = 1\nmode = \"enforce\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let gate = Arc::new(AuthorizationGate::new(Arc::new(
            PolicyStore::load(&policy_path).unwrap(),
        )));
        let journal = Arc::new(
            WitnessJournal::open(JournalConfig::new(
                root.path().join("witness"),
                [action.as_bytes()[0]; 16],
                JournalMode::Required,
            ))
            .unwrap(),
        );
        let id = "00112233445566778899aabbccddeeff";
        if action != "run" {
            let store = LocalContainerStore::open(root.path().join("containers.db")).unwrap();
            let mut record: ContainerRecord = serde_json::from_value(serde_json::json!({
                "id":id, "pid":std::process::id(), "image":"example.invalid/app:latest",
                "command":["true"], "created_at_unix":1, "stdout_path":"", "stderr_path":"",
                "status": if action == "resume" { "paused" } else { "running" }
            }))
            .unwrap();
            record.mutation_generation = 1;
            store.put(&record).unwrap();
            drop(store);
        }
        let runtime =
            ContainerRuntime::new_with_authorization(root.path(), gate, Some(journal.clone()))
                .unwrap();
        let result = match action {
            "run" => runtime
                .run(
                    "example.invalid/app:latest",
                    &["true".into()],
                    &[],
                    &Default::default(),
                    &Default::default(),
                    None,
                    Default::default(),
                    &[],
                    None,
                    &[],
                    &[],
                    false,
                    true,
                    None,
                    None,
                    None,
                    &[],
                    "none",
                    ferro_core::runtime::NetworkBackend::Iptables,
                    None,
                )
                .map(|_| ()),
            "exec" => runtime.exec(id, &["true".into()]).map(|_| ()),
            "pause" => runtime.pause(id),
            "resume" => runtime.resume(id),
            "stop" => runtime.stop(id, std::time::Duration::ZERO),
            "kill" => runtime.kill(id),
            "restart" => runtime.restart(id, std::time::Duration::ZERO),
            "remove" => runtime.remove(id),
            _ => unreachable!(),
        };
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authorization denied"),
            "{action}"
        );
        if action != "run" {
            let expected = if action == "resume" {
                "paused"
            } else {
                "running"
            };
            assert_eq!(runtime.inspect(id).unwrap().status, expected, "{action}");
        }
        let stages = journal
            .records()
            .unwrap()
            .iter()
            .map(|bytes| decode_record(bytes).unwrap().stage())
            .collect::<Vec<_>>();
        assert_eq!(
            stages,
            [
                WitnessStage::RequestReceived,
                WitnessStage::Decision,
                WitnessStage::Denied
            ],
            "{action}"
        );
        drop(runtime);
        drop(journal);
    }
}

#[test]
fn every_allowed_lifecycle_method_has_one_decision_and_terminal_receipt() {
    let _guard = runtime_test_guard();
    for action in [
        "run", "exec", "pause", "resume", "stop", "kill", "restart", "remove",
    ] {
        let root = tempfile::tempdir().unwrap();
        let cgroup = root.path().join("cgroup");
        std::fs::create_dir_all(&cgroup).unwrap();
        std::fs::write(cgroup.join("cgroup.controllers"), "memory cpu pids").unwrap();
        std::env::set_var("FERROCRATE_CGROUP_ROOT", &cgroup);
        let policy_path = root.path().join("policy.toml");
        std::fs::write(
            &policy_path,
            "schema_version = 1\ngeneration = 1\nmode = \"disabled\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let gate = Arc::new(AuthorizationGate::new(Arc::new(
            PolicyStore::load(&policy_path).unwrap(),
        )));
        let journal = Arc::new(
            WitnessJournal::open(JournalConfig::new(
                root.path().join("witness"),
                [action.as_bytes()[0].wrapping_add(1); 16],
                JournalMode::Required,
            ))
            .unwrap(),
        );
        let id = "00112233445566778899aabbccddeeff";
        let mut child = None;
        if action != "run" {
            let spawned = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let pid = spawned.id();
            child = Some(spawned);
            let store = LocalContainerStore::open(root.path().join("containers.db")).unwrap();
            let record: ContainerRecord = serde_json::from_value(serde_json::json!({
                "id":id, "pid":pid, "image":"example.invalid/app:latest",
                "command": if action == "restart" { Vec::<String>::new() } else { vec![String::from("true")] },
                "created_at_unix":1, "stdout_path":"", "stderr_path":"",
                "status": if action == "resume" { "paused" } else if action == "restart" || action == "remove" { "stopped" } else { "running" }
            })).unwrap();
            store.put(&record).unwrap();
            drop(store);
        }
        let runtime =
            ContainerRuntime::new_with_authorization(root.path(), gate, Some(journal.clone()))
                .unwrap();
        let _ = match action {
            "run" => runtime
                .run(
                    "example.invalid/app:latest",
                    &["true".into()],
                    &[],
                    &Default::default(),
                    &Default::default(),
                    None,
                    Default::default(),
                    &[],
                    None,
                    &[],
                    &[],
                    false,
                    true,
                    None,
                    None,
                    None,
                    &[],
                    "none",
                    ferro_core::runtime::NetworkBackend::Iptables,
                    None,
                )
                .map(|_| ()),
            "exec" => runtime.exec(id, &["false".into()]).map(|_| ()),
            "pause" => runtime.pause(id),
            "resume" => runtime.resume(id),
            "stop" => runtime.stop(id, std::time::Duration::ZERO),
            "kill" => runtime.kill(id),
            "restart" => runtime.restart(id, std::time::Duration::ZERO),
            "remove" => runtime.remove(id),
            _ => unreachable!(),
        };
        if action == "remove" {
            assert_eq!(runtime.inspect(id).unwrap().status, "quarantined");
        }
        if let Some(mut child) = child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let stages = journal
            .records()
            .unwrap()
            .iter()
            .map(|bytes| decode_record(bytes).unwrap().stage())
            .collect::<Vec<_>>();
        assert_eq!(
            stages,
            [
                WitnessStage::RequestReceived,
                WitnessStage::Decision,
                WitnessStage::Outcome
            ],
            "{action}"
        );
        drop(runtime);
        drop(journal);
        std::env::remove_var("FERROCRATE_CGROUP_ROOT");
    }
}

#[test]
fn disabled_journal_is_exactly_compatibility_absent() {
    let _guard = runtime_test_guard();
    let root = tempfile::tempdir().unwrap();
    let policy_path = root.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        "schema_version = 1\ngeneration = 1\nmode = \"disabled\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let store = LocalContainerStore::open(root.path().join("containers.db")).unwrap();
    let record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id":"00112233445566778899aabbccddeeff", "pid":u32::MAX,
        "image":"example.invalid/app:latest", "command":["true"],
        "created_at_unix":1, "stdout_path":"", "stderr_path":"", "status":"stopped"
    }))
    .unwrap();
    store.put(&record).unwrap();
    drop(store);
    let gate = Arc::new(AuthorizationGate::new(Arc::new(
        PolicyStore::load(&policy_path).unwrap(),
    )));
    let journal = Arc::new(
        WitnessJournal::open(JournalConfig::new(
            root.path().join("witness"),
            [44; 16],
            JournalMode::Disabled,
        ))
        .unwrap(),
    );
    let runtime =
        ContainerRuntime::new_with_authorization(root.path(), gate, Some(journal.clone())).unwrap();
    let result = runtime.exec(&record.id, &["true".into()]);
    assert!(!result
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("journal is disabled")));
    assert!(journal.records().unwrap().is_empty());
}

#[test]
fn creation_provenance_requires_every_identity_binding() {
    let mut value = CreationProvenance::default();
    assert!(!value.is_verifiable());
    value.runtime_instance_id = Some([1; 16]);
    value.boot_id = Some([2; 16]);
    value.journal_id = Some([4; 16]);
    value.resource_uuid = Some("00112233-4455-6677-8899-aabbccddeeff".into());
    value.resource_generation = 1;
    value.creator_operation_id = Some([3; 16]);
    value.image_digest = Some(format!("sha256:{}", "a".repeat(64)));
    assert!(value.is_verifiable());
}

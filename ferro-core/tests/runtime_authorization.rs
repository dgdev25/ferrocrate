use ferro_core::authorization::{gate::AuthorizationGate, policy::PolicyStore};
use ferro_core::container_store::CreationProvenance;
use ferro_core::container_store::{ContainerRecord, LocalContainerStore};
use ferro_core::runtime::ContainerRuntime;
use ferro_core::witness::{
    decode_record, JournalConfig, JournalMode, WitnessJournal, WitnessStage,
};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

#[test]
fn creation_provenance_is_absent_for_legacy_records() {
    let value: CreationProvenance = serde_json::from_str("null").unwrap_or_default();
    assert!(!value.is_verifiable());
}

#[test]
fn denied_exec_is_witnessed_once_and_has_no_side_effect() {
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

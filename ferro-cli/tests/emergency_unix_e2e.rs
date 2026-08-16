#![cfg(target_os = "linux")]

use ed25519_dalek::{Signer, SigningKey};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Output},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn protected(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run(runtime: &Path, args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .args(args)
        .env("FERROCRATE_RUNTIME_DIR", runtime)
        .env("FERROCRATE_TEST_CONSOLE", "1")
        .output()
        .unwrap()
}

fn provision_admission(auth: &Path, id: [u8; 16]) {
    use sha2::Digest;
    let key = SigningKey::from_bytes(&[0x77; 32]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let checkpoint = ferro_core::witness::Checkpoint::sign(
        ferro_core::witness::FlushedHead::new(id, 1, 0, [0; 32]),
        now.saturating_sub(1),
        &key,
        ferro_core::witness::CheckpointKind::Periodic,
    )
    .unwrap();
    let admission = auth.join("admission");
    fs::create_dir(&admission).unwrap();
    fs::set_permissions(&admission, fs::Permissions::from_mode(0o700)).unwrap();
    let checkpoint_bytes = checkpoint.encode();
    protected(&admission.join("minimum.bin"), &checkpoint_bytes);
    protected(&admission.join("checkpoint-0001.bin"), &checkpoint_bytes);
    let trust = serde_json::to_vec(&serde_json::json!({
        "schema": 1, "journal_id": hex(&id),
        "initial_public_key": hex(key.verifying_key().as_bytes()), "starting_epoch": 1
    }))
    .unwrap();
    protected(&admission.join("trust.json"), &trust);
    let digest = |bytes: &[u8]| hex(&sha2::Sha256::digest(bytes));
    let manifest = ferro_core::authorization::admission::AdmissionSnapshotManifest {
        schema: 1,
        generation: 1,
        journal_id: hex(&id),
        trust_bundle: ferro_core::authorization::admission::AdmissionArtifact {
            file: "trust.json".into(),
            sha256: digest(&trust),
        },
        minimum_checkpoint: ferro_core::authorization::admission::AdmissionArtifact {
            file: "minimum.bin".into(),
            sha256: digest(&checkpoint_bytes),
        },
        checkpoint_chain: vec![ferro_core::authorization::admission::AdmissionArtifact {
            file: "checkpoint-0001.bin".into(),
            sha256: digest(&checkpoint_bytes),
        }],
        trust_key_ids: vec![digest(key.verifying_key().as_bytes())],
        latest_checkpoint: "checkpoint-0001.bin".into(),
        latest_created_at_secs: now.saturating_sub(1),
    };
    protected(
        &admission.join("manifest.json"),
        &serde_json::to_vec(&manifest).unwrap(),
    );
}

fn start_sink(
    runtime: &Path,
    socket: &Path,
    store: &Path,
    key: &Path,
    journal: &str,
    requests: u64,
) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .args([
            "emergency",
            "sink-serve",
            "--socket",
            socket.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--signing-key",
            key.to_str().unwrap(),
            "--journal-id",
            journal,
            "--expected-uid",
            &nix::unistd::geteuid().as_raw().to_string(),
            "--requests",
            &requests.to_string(),
        ])
        .env("FERROCRATE_RUNTIME_DIR", runtime)
        .spawn()
        .unwrap()
}

fn wait_socket(path: &Path) {
    for _ in 0..300 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("sink subprocess did not publish its socket");
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn production_cli_unix_sink_lifecycle_survives_every_process_restart() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = temp.path().join("runtime");
    let auth = runtime.join("authorization");
    fs::create_dir_all(&auth).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o700)).unwrap();
    let main_journal_id = [0x41; 16];
    protected(
        &auth.join("active-policy.toml"),
        b"schema_version = 1\ngeneration = 1\nmode = \"enforce\"\n",
    );
    protected(
        &auth.join("journal-id"),
        format!("{}\n", hex(&main_journal_id)).as_bytes(),
    );
    provision_admission(&auth, main_journal_id);
    ferro_core::witness::WitnessJournal::open(ferro_core::witness::JournalConfig::new(
        auth.join("witness-journal"),
        main_journal_id,
        ferro_core::witness::JournalMode::Required,
    ))
    .unwrap();

    let mut sleeper = Command::new("sleep").arg("60").spawn().unwrap();
    let record: ferro_core::container_store::ContainerRecord =
        serde_json::from_value(serde_json::json!({
            "id": "e2e", "pid": sleeper.id(), "image": "fixture:latest", "command": ["sleep", "60"],
            "created_at_unix": 1, "stdout_path": temp.path().join("stdout").display().to_string(),
            "stderr_path": temp.path().join("stderr").display().to_string(), "status": "running",
            "mutation_generation": 1
        }))
        .unwrap();
    ferro_core::sqlite_container_store::SqliteContainerStore::open(runtime.join("containers.db"))
        .unwrap()
        .put(&record)
        .unwrap();

    let socket = temp.path().join("sink.sock");
    let store = temp.path().join("sink.store");
    let signing = temp.path().join("sink.key");
    let receipt_public = temp.path().join("sink.pub");
    let sink_key = SigningKey::from_bytes(&[0x61; 32]);
    protected(&store, b"");
    protected(&signing, sink_key.as_bytes());
    protected(&receipt_public, sink_key.verifying_key().as_bytes());
    let journal = hex(&[0x71; 16]);

    let ordinary_denial = run(&runtime, &["stop".into(), "e2e".into()]);
    assert!(!ordinary_denial.status.success());
    assert!(
        !String::from_utf8_lossy(&ordinary_denial.stderr).contains("reconciliation is required")
    );

    let recovery = SigningKey::from_bytes(&[0x31; 32]);
    let recovery_public = temp.path().join("recovery.pub");
    protected(
        &recovery_public,
        hex(recovery.verifying_key().as_bytes()).as_bytes(),
    );
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .to_owned();
    let uptime: f64 = fs::read_to_string("/proc/uptime")
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    // The real stop waits ten seconds before SIGKILL. This deadline is valid
    // before first execution and naturally expires after the effect, proving
    // recovery does not re-apply admission freshness checks.
    let deadline = (uptime * 1_000_000_000.0) as u64 + 5_000_000_000;
    let nonce = "process-e2e-0123456789";
    let payload = format!("FERROCRATE-EMERGENCY-APPROVAL-V1\n{boot}\ncontainer.stop\ncontainer:e2e\n{nonce}\n{deadline}\n");
    let approval = temp.path().join("approval.json");
    protected(
        &approval,
        &serde_json::to_vec(&serde_json::json!({
            "payload": payload,
            "signature": hex(&recovery.sign(payload.as_bytes()).to_bytes()),
        }))
        .unwrap(),
    );

    let activate_args = vec![
        "emergency".into(),
        "activate".into(),
        "--origin".into(),
        "test-console".into(),
        "--sink-backend".into(),
        "unix".into(),
        "--sink".into(),
        format!("unix:{}", socket.display()),
        "--sink-receipt-key".into(),
        receipt_public.display().to_string(),
        "--sink-journal-id".into(),
        journal.clone(),
        "--sink-server-uid".into(),
        nix::unistd::geteuid().as_raw().to_string(),
        "--recovery-public-key".into(),
        recovery_public.display().to_string(),
        "--recovery-approval".into(),
        approval.display().to_string(),
        "--action".into(),
        "container.stop".into(),
        "--resource".into(),
        "container:e2e".into(),
        "--nonce".into(),
        nonce.into(),
        "--deadline-uptime-ns".into(),
        deadline.to_string(),
    ];

    let forged_store = temp.path().join("forged.store");
    let forged_key_path = temp.path().join("forged.key");
    let forged_key = SigningKey::from_bytes(&[0x62; 32]);
    protected(&forged_store, b"");
    protected(&forged_key_path, forged_key.as_bytes());
    let mut forged_server = start_sink(
        &runtime,
        &socket,
        &forged_store,
        &forged_key_path,
        &journal,
        1,
    );
    wait_socket(&socket);
    let forged = run(&runtime, &activate_args);
    assert!(!forged.status.success());
    assert!(String::from_utf8_lossy(&forged.stderr).contains("invalid sink receipt signature"));
    assert!(forged_server.wait().unwrap().success());
    assert!(!auth.join("emergency-active.json").exists());
    let restored_gate = run(&runtime, &["stop".into(), "e2e".into()]);
    assert!(!restored_gate.status.success());
    assert!(!String::from_utf8_lossy(&restored_gate.stderr).contains("reconciliation is required"));

    let mut server = start_sink(&runtime, &socket, &store, &signing, &journal, 2);
    wait_socket(&socket);
    let activate = run(&runtime, &activate_args);
    assert!(activate.status.success(), "{}", output_text(&activate));
    assert!(server.wait().unwrap().success());

    let blocked = run(&runtime, &["ps".into()]);
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("reconciliation is required"));

    let unavailable = run(
        &runtime,
        &[
            "emergency".into(),
            "execute".into(),
            "--sink-backend".into(),
            "unix".into(),
            "--action".into(),
            "container.stop".into(),
            "--resource".into(),
            "container:e2e".into(),
        ],
    );
    assert!(!unavailable.status.success());

    let mut server = start_sink(&runtime, &socket, &store, &signing, &journal, 1);
    wait_socket(&socket);
    let execute = run(
        &runtime,
        &[
            "emergency".into(),
            "execute".into(),
            "--sink-backend".into(),
            "unix".into(),
            "--action".into(),
            "container.stop".into(),
            "--resource".into(),
            "container:e2e".into(),
        ],
    );
    assert!(
        !execute.status.success(),
        "outcome sink outage must leave a recoverable unknown state"
    );
    assert!(server.wait().unwrap().success());
    assert!(
        !sleeper.wait().unwrap().success(),
        "real runtime stop must terminate the fixture process"
    );
    let mut server = start_sink(&runtime, &socket, &store, &signing, &journal, 1);
    wait_socket(&socket);
    let recovered = run(
        &runtime,
        &[
            "emergency".into(),
            "execute".into(),
            "--sink-backend".into(),
            "unix".into(),
            "--action".into(),
            "container.stop".into(),
            "--resource".into(),
            "container:e2e".into(),
        ],
    );
    assert!(recovered.status.success(), "{}", output_text(&recovered));
    assert!(server.wait().unwrap().success());

    let mut server = start_sink(&runtime, &socket, &store, &signing, &journal, 1);
    wait_socket(&socket);
    let reconcile = run(
        &runtime,
        &[
            "emergency".into(),
            "reconcile".into(),
            "--sink-backend".into(),
            "unix".into(),
        ],
    );
    assert!(reconcile.status.success(), "{}", output_text(&reconcile));
    assert!(server.wait().unwrap().success());
    assert!(!auth.join("emergency-active.json").exists());

    // A second production lifecycle reuses the authenticated durable sink
    // head instead of incorrectly restarting the chain at sequence zero.
    let mut second_sleeper = Command::new("sleep").arg("60").spawn().unwrap();
    let second_record: ferro_core::container_store::ContainerRecord =
        serde_json::from_value(serde_json::json!({
            "id": "e2e-second", "pid": second_sleeper.id(), "image": "fixture:latest",
            "command": ["sleep", "60"], "created_at_unix": 2,
            "stdout_path": temp.path().join("stdout-second").display().to_string(),
            "stderr_path": temp.path().join("stderr-second").display().to_string(),
            "status": "running", "mutation_generation": 1
        }))
        .unwrap();
    ferro_core::sqlite_container_store::SqliteContainerStore::open(runtime.join("containers.db"))
        .unwrap()
        .put(&second_record)
        .unwrap();
    let second_uptime: f64 = fs::read_to_string("/proc/uptime")
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let second_deadline = (second_uptime * 1_000_000_000.0) as u64 + 30_000_000_000;
    let second_nonce = "process-e2e-second-012345";
    let second_payload = format!(
        "FERROCRATE-EMERGENCY-APPROVAL-V1\n{boot}\ncontainer.kill\ncontainer:e2e-second\n{second_nonce}\n{second_deadline}\n"
    );
    let second_approval = temp.path().join("approval-second.json");
    protected(
        &second_approval,
        &serde_json::to_vec(&serde_json::json!({
            "payload": second_payload,
            "signature": hex(&recovery.sign(second_payload.as_bytes()).to_bytes()),
        }))
        .unwrap(),
    );
    let second_activate = vec![
        "emergency".into(),
        "activate".into(),
        "--origin".into(),
        "test-console".into(),
        "--sink-backend".into(),
        "unix".into(),
        "--sink".into(),
        format!("unix:{}", socket.display()),
        "--sink-receipt-key".into(),
        receipt_public.display().to_string(),
        "--sink-journal-id".into(),
        journal.clone(),
        "--sink-server-uid".into(),
        nix::unistd::geteuid().as_raw().to_string(),
        "--recovery-public-key".into(),
        recovery_public.display().to_string(),
        "--recovery-approval".into(),
        second_approval.display().to_string(),
        "--action".into(),
        "container.kill".into(),
        "--resource".into(),
        "container:e2e-second".into(),
        "--nonce".into(),
        second_nonce.into(),
        "--deadline-uptime-ns".into(),
        second_deadline.to_string(),
    ];
    let mut server = start_sink(&runtime, &socket, &store, &signing, &journal, 2);
    wait_socket(&socket);
    let output = run(&runtime, &second_activate);
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(server.wait().unwrap().success());
    let mut server = start_sink(&runtime, &socket, &store, &signing, &journal, 2);
    wait_socket(&socket);
    let output = run(
        &runtime,
        &[
            "emergency".into(),
            "execute".into(),
            "--sink-backend".into(),
            "unix".into(),
            "--action".into(),
            "container.kill".into(),
            "--resource".into(),
            "container:e2e-second".into(),
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(server.wait().unwrap().success());
    assert!(!second_sleeper.wait().unwrap().success());
    let mut server = start_sink(&runtime, &socket, &store, &signing, &journal, 1);
    wait_socket(&socket);
    let output = run(
        &runtime,
        &[
            "emergency".into(),
            "reconcile".into(),
            "--sink-backend".into(),
            "unix".into(),
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(server.wait().unwrap().success());
    assert!(!auth.join("emergency-active.json").exists());

    let reopened = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .open(&store)
        .unwrap();
    ferro_cli::authorization_admin::emergency_sink::UnixSinkStore::open(
        reopened, [0x71; 16], sink_key,
    )
    .unwrap();
}

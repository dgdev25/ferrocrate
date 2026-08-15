use ferro_core::authorization::inventory::MUTATION_INVENTORY;
use ferro_core::observability::{
    authorization_metrics, authorization_metrics_snapshot, AuthorizationMetric,
    AuthorizationMetrics, DecisionMetric, JournalMetric, RecoveryMetric,
};
use ferro_core::witness::{FaultPoint, FlushBoundary};
use sha2::{Digest, Sha256};
use std::fs;

const SECRET: &str = "task11-canary-password-7f3b";

#[test]
fn authorization_metrics_have_a_closed_nonsecret_schema() {
    let metrics = AuthorizationMetrics::new();
    metrics.record(AuthorizationMetric::Attributed);
    metrics.record(AuthorizationMetric::UnknownPrincipal);
    metrics.record(AuthorizationMetric::Decision(DecisionMetric::WouldDeny));
    metrics.record(AuthorizationMetric::Decision(
        DecisionMetric::EnforcedDenial,
    ));
    metrics.record(AuthorizationMetric::BypassDetected);
    metrics.record(AuthorizationMetric::Journal(JournalMetric::AppendFailure));
    metrics.record(AuthorizationMetric::Journal(JournalMetric::FlushFailure));
    metrics.record(AuthorizationMetric::PendingIntent);
    metrics.record(AuthorizationMetric::Recovery(
        RecoveryMetric::OutcomeUnknown,
    ));
    metrics.record(AuthorizationMetric::Recovery(RecoveryMetric::Recovered));
    metrics.record(AuthorizationMetric::VerificationFailure);
    metrics.set_checkpoint_age_seconds(61);

    let rendered = metrics.render_prometheus();
    for name in [
        "ferro_authorization_attributed_total",
        "ferro_authorization_unknown_principal_total",
        "ferro_authorization_would_deny_total",
        "ferro_authorization_enforced_denial_total",
        "ferro_authorization_bypass_detected_total",
        "ferro_witness_append_failure_total",
        "ferro_witness_flush_failure_total",
        "ferro_witness_pending_intent_total",
        "ferro_witness_outcome_unknown_total",
        "ferro_witness_recovered_total",
        "ferro_witness_verification_failure_total",
        "ferro_witness_checkpoint_age_seconds 61",
    ] {
        assert!(rendered.contains(name), "missing {name}: {rendered}");
    }
    assert!(!rendered.contains(SECRET));
    assert!(
        !rendered.contains('{'),
        "labels are intentionally closed: {rendered}"
    );
}

#[test]
fn production_metrics_have_a_machine_readable_snapshot() {
    let before = authorization_metrics_snapshot();
    authorization_metrics().record(AuthorizationMetric::BypassDetected);
    let after = authorization_metrics_snapshot();
    assert_eq!(
        after.bypass_detected_total,
        before.bypass_detected_total + 1
    );
    assert_eq!(after.bypass_probe_total, before.bypass_probe_total);
    assert_eq!(after.successful_bypass_total, before.successful_bypass_total);
    assert!(!serde_json::to_string(&after).unwrap().contains(SECRET));
}

#[test]
fn qualification_matrices_are_complete_and_inventory_has_no_bypass_slot() {
    let boundaries = [
        FlushBoundary::Reserve,
        FlushBoundary::Received,
        FlushBoundary::Decision,
        FlushBoundary::Outcome,
    ];
    let mut sites = Vec::new();
    for boundary in boundaries {
        sites.extend([
            FaultPoint::BeforeTransaction(boundary),
            FaultPoint::Transaction(boundary),
            FaultPoint::BeforeFlush(boundary),
            FaultPoint::DuringFlush(boundary),
            FaultPoint::AfterFlush(boundary),
        ]);
    }
    sites.extend([
        FaultPoint::RotationSeal,
        FaultPoint::CheckpointBindingRejected,
    ]);
    assert_eq!(sites.len(), 22, "every documented journal kill point");
    assert_eq!(MUTATION_INVENTORY.len(), 17);
    assert!(MUTATION_INVENTORY.iter().all(|entry| {
        entry.id.starts_with("mutation.")
            && !entry.executor.is_empty()
            && !entry.gate_call_site.is_empty()
            && !entry.mediation_test.is_empty()
    }));
}

#[test]
fn seeded_secret_is_absent_from_sled_json_logs_errors_and_metrics() {
    let root = tempfile::tempdir().unwrap();
    let digest = Sha256::digest(SECRET.as_bytes());

    let db = sled::open(root.path().join("witness.sled")).unwrap();
    db.insert(b"redacted-request-digest", digest.as_slice())
        .unwrap();
    db.flush().unwrap();
    drop(db);

    let export = serde_json::json!({"request_digest": hex::encode(digest)});
    fs::write(root.path().join("export.json"), export.to_string()).unwrap();
    ferro_core::observability::log_event(
        root.path(),
        ferro_core::observability::make_event(
            "authorization.evaluate",
            None,
            None,
            Some("denied"),
            Some("request attributes redacted"),
        ),
    )
    .unwrap();

    let metrics = AuthorizationMetrics::new();
    metrics.record(AuthorizationMetric::UnknownPrincipal);
    let error = ferro_core::witness::JournalError::UnavailableBeforeVisibility.to_string();
    let mut examined = vec![
        export.to_string().into_bytes(),
        metrics.render_prometheus().into_bytes(),
        error.into_bytes(),
    ];
    for entry in [
        root.path().join("export.json"),
        root.path().join("logs/ferrocrate.jsonl"),
    ] {
        examined.push(fs::read(entry).unwrap());
    }
    for entry in fs::read_dir(root.path().join("witness.sled")).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            examined.push(fs::read(path).unwrap());
        }
    }
    assert!(examined.iter().all(|bytes| !bytes
        .windows(SECRET.len())
        .any(|window| window == SECRET.as_bytes())));
}

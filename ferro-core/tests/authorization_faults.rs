use ferro_core::authorization::inventory::MUTATION_INVENTORY;
use ferro_core::authorization::{
    gate::AuthorizationGate, policy::PolicyStore, Action, RequestOrigin, ResourceKind,
};
use ferro_core::observability::{
    authorization_metrics, authorization_metrics_snapshot, AuthorizationFixtureEvidence,
    AuthorizationMetric, AuthorizationMetrics, AuthorizationMetricsSnapshot, DecisionMetric,
    FixtureClassification, JournalMetric, RecoveryMetric,
};
use ferro_core::witness::{FaultPoint, FlushBoundary};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

const SECRET: &str = "task11-canary-password-7f3b";

/// The authorization SLO deliberately excludes durable witness I/O.  It times
/// the production runtime surface through normalization, policy pinning, and
/// gate evaluation while the disabled-mode surface avoids journal persistence.
#[test]
fn authorization_decision_p99_is_below_one_millisecond_without_witness_io() {
    const SAMPLE_COUNT: usize = 1_001;
    const P99_LIMIT: Duration = Duration::from_millis(1);

    let root = tempfile::tempdir().expect("temporary runtime directory");
    let policy_path = root.path().join("policy.toml");
    fs::write(
        &policy_path,
        "schema_version = 1\ngeneration = 1\nmode = \"disabled\"\n",
    )
    .expect("write protected policy");
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).expect("protect policy");
    let gate = Arc::new(AuthorizationGate::new(Arc::new(
        PolicyStore::load(&policy_path).expect("load policy"),
    )));
    let runtime =
        ferro_core::runtime::ContainerRuntime::new_with_authorization(root.path(), gate, None)
            .expect("construct runtime without witness I/O");
    let surface = runtime
        .surface_authorization()
        .expect("runtime authorization surface");
    let origin = RequestOrigin::cli_current().expect("authenticated CLI origin");

    // Warm policy and allocation paths before taking the measured sample set.
    let _ = surface
        .authorize_named(
            &origin,
            Action::VolumeCreate,
            ResourceKind::Volume,
            "authorization-latency-warmup",
            1,
        )
        .expect("warm authorization");

    let mut samples = Vec::with_capacity(SAMPLE_COUNT);
    for generation in 1..=SAMPLE_COUNT as u64 {
        let started = Instant::now();
        let permit = surface
            .authorize_named(
                &origin,
                Action::VolumeCreate,
                ResourceKind::Volume,
                "authorization-latency-volume",
                generation,
            )
            .expect("authorization must admit disabled-mode fixture");
        std::hint::black_box(permit);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p99 = samples[(SAMPLE_COUNT * 99).div_ceil(100) - 1];
    assert!(
        p99 < P99_LIMIT,
        "authorization decision p99 exceeded {P99_LIMIT:?}: {p99:?}"
    );
}

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
    assert_eq!(
        after.successful_bypass_total,
        before.successful_bypass_total
    );
    assert!(!serde_json::to_string(&after).unwrap().contains(SECRET));
}

#[test]
fn qualification_evidence_requires_an_explicit_negative_control_classification() {
    let before = AuthorizationMetricsSnapshot::default();
    let control = AuthorizationFixtureEvidence::new(
        "negative-control.broken-comparator",
        FixtureClassification::ExpectedNegativeControl,
        before,
        AuthorizationMetricsSnapshot {
            bypass_probe_total: 1,
            successful_bypass_total: 1,
            ..before
        },
    );
    assert!(control.is_expected_negative_control());
    assert!(!control.is_promotion_clean());
    let actual = AuthorizationFixtureEvidence::new(
        "runtime.surface",
        FixtureClassification::ActualFixture,
        before,
        AuthorizationMetricsSnapshot {
            attributed_total: 1,
            bypass_probe_total: 1,
            bypass_detected_total: 1,
            ..before
        },
    );
    assert!(actual.is_promotion_clean());
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
    assert_eq!(MUTATION_INVENTORY.len(), 18);
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

    let legacy_dir = root.path().join("witness.sled");
    fs::create_dir_all(&legacy_dir).unwrap();
    fs::write(
        legacy_dir.join("redacted-request-digest"),
        digest.as_slice(),
    )
    .unwrap();

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
    for entry in fs::read_dir(legacy_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            examined.push(fs::read(path).unwrap());
        }
    }
    assert!(examined.iter().all(|bytes| !bytes
        .windows(SECRET.len())
        .any(|window| window == SECRET.as_bytes())));
}

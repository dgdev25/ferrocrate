use ferro_core::witness::{
    decode_record, encode_record, hash_record, verify_stream, DisclosureClass, Invocation,
    PrincipalSummary, ReasonCode, RecordBytes, ResourceSummary, RuleSummary, StreamTrust,
    WitnessAction, WitnessOutcome, WitnessRecord, WitnessResourceKind, WitnessStage,
    FORMAT_VERSION,
};

const JOURNAL: [u8; 16] = [6; 16];

fn record(sequence: u64, previous_hash: [u8; 32], stage: WitnessStage) -> WitnessRecord {
    WitnessRecord {
        sequence,
        previous_hash,
        event_id: [sequence as u8; 16],
        request_id: [7; 16],
        runtime_instance_id: [8; 16],
        boot_id: [9; 16],
        principal: PrincipalSummary::pseudonymize(&[21; 32], b"uid:1000").unwrap(),
        invocation: Invocation::Cli,
        action: WitnessAction::ContainerCreate,
        resource_kind: WitnessResourceKind::Container,
        resource: ResourceSummary::pseudonymize(&[22; 32], b"container:018f").unwrap(),
        resource_generation: 3,
        policy_version: 12,
        policy_digest: [10; 32],
        decision_id: None,
        rule: None,
        decision: None,
        reason: None,
        request_digest: [12; 32],
        result_digest: None,
        wall_time_ns: 1_725_000_000_000_000_000,
        monotonic_ns: sequence * 10,
        stage,
        outcome: WitnessOutcome::None,
        recovery_link: None,
        path_class: Some(DisclosureClass::RuntimeManaged),
        device_class: None,
        correlation_digest: None,
    }
}

fn decision(sequence: u64, allowed: bool) -> WitnessRecord {
    let mut value = record(sequence, [0; 32], WitnessStage::Decision);
    value.decision_id = Some([11; 16]);
    value.rule = Some(RuleSummary::from_id([13; 16]));
    value.decision = Some(allowed);
    value.reason = (!allowed).then_some(ReasonCode::PolicyDenied);
    value
}

fn terminal_denied(sequence: u64) -> WitnessRecord {
    let mut value = record(sequence, [0; 32], WitnessStage::Denied);
    value.decision_id = Some([11; 16]);
    value.reason = Some(ReasonCode::PolicyDenied);
    value.outcome = WitnessOutcome::Denied;
    value
}

fn terminal_outcome(sequence: u64, outcome: WitnessOutcome) -> WitnessRecord {
    let mut value = record(sequence, [0; 32], WitnessStage::Outcome);
    value.decision_id = Some([11; 16]);
    value.result_digest = Some([14; 32]);
    value.reason = (outcome != WitnessOutcome::Succeeded).then_some(ReasonCode::ExecutionFailed);
    value.outcome = outcome;
    value
}

fn encoded_chain(mut records: Vec<WitnessRecord>) -> Vec<RecordBytes> {
    let mut previous = [0; 32];
    for record in &mut records {
        record.previous_hash = previous;
        let bytes = encode_record(JOURNAL, record).unwrap();
        previous = hash_record(&bytes);
    }
    records
        .iter()
        .map(|record| encode_record(JOURNAL, record).unwrap())
        .collect()
}

fn genesis_trust() -> StreamTrust {
    StreamTrust::new(JOURNAL, 1, [0; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn golden_scalar_vector_is_stable_and_round_trips_exact_bytes() {
    let bytes = encode_record(JOURNAL, &record(1, [0; 32], WitnessStage::RequestReceived)).unwrap();
    assert_eq!(bytes.as_ref()[0], FORMAT_VERSION);
    assert_eq!(&bytes.as_ref()[2..18], &JOURNAL);
    assert_eq!(&bytes.as_ref()[18..26], &1_u64.to_be_bytes());
    assert_eq!(
        hex(bytes.as_ref()),
        concat!(
            "0101060606060606060606060606060606060000000000000001000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101",
            "070707070707070707070707070707070808080808080808080808080808080809090909090909090909090909090909ff51c4845ca485ee1e9642a76dbbc48e376aaf16a330df6af513404b9805f1dd",
            "0101016f2850d3d4282c13868c8f7d227dacb2774977d426fffbe3fd1912c32e1809a20000000000000003000000000000000c0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "000000000c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0017f06e5c4d8c8000000000000000000a01000001010000"
        )
    );
    let decoded = decode_record(bytes.as_ref()).unwrap();
    assert_eq!(decoded.journal_id(), &JOURNAL);
    assert_eq!(
        decoded.record(),
        &record(1, [0; 32], WitnessStage::RequestReceived)
    );
    assert_eq!(decoded.bytes().as_ref(), bytes.as_ref());
    assert_eq!(
        hash_record(&bytes),
        [
            15, 155, 91, 27, 64, 165, 185, 60, 157, 224, 61, 144, 44, 124, 130, 34, 183, 47, 201,
            74, 170, 168, 81, 44, 30, 99, 202, 216, 226, 210, 63, 134
        ]
    );
}

#[test]
fn decoder_rejects_unknown_enum_discriminants_and_noncanonical_bytes() {
    let bytes = encode_record(JOURNAL, &record(1, [0; 32], WitnessStage::RequestReceived)).unwrap();
    for offset in [1, 154, 155, 156, 290, 291, 294] {
        // hash algorithm, invocation, action, resource kind, stage, outcome,
        // and the present path disclosure class.
        let mut unknown = bytes.as_ref().to_vec();
        unknown[offset] = 99;
        assert!(decode_record(&unknown).is_err(), "offset {offset}");
    }

    let decision = encode_record(JOURNAL, &decision(1, false)).unwrap();
    let mut unknown_reason = decision.as_ref().to_vec();
    unknown_reason[273] = 99;
    assert!(decode_record(&unknown_reason).is_err());
    let mut trailing = bytes.as_ref().to_vec();
    trailing.push(0);
    assert!(decode_record(&trailing).is_err());
}

#[test]
fn persisted_schema_has_no_public_raw_text_payloads() {
    let value = record(1, [0; 32], WitnessStage::RequestReceived);
    let debug = format!("{value:?}");
    for secret in ["/srv/private", "--password", "TOKEN=secret", "/dev/nvidia0"] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn verifier_rejects_truncated_prefixes_and_wrong_predecessors() {
    let chain = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        decision(2, false),
        terminal_denied(3),
    ]);
    assert!(verify_stream(chain[1..].iter().map(AsRef::as_ref), &genesis_trust()).is_err());
    assert!(verify_stream(
        chain.iter().map(AsRef::as_ref),
        &StreamTrust::new(JOURNAL, 1, [99; 32])
    )
    .is_err());
}

#[test]
fn denied_and_allowed_lifecycles_are_accepted() {
    let denied = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        decision(2, false),
        terminal_denied(3),
    ]);
    assert_eq!(
        verify_stream(denied.iter().map(AsRef::as_ref), &genesis_trust())
            .unwrap()
            .terminal_denied,
        1
    );
    let allowed = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        decision(2, true),
        terminal_outcome(3, WitnessOutcome::Succeeded),
    ]);
    assert!(verify_stream(allowed.iter().map(AsRef::as_ref), &genesis_trust()).is_ok());
}

#[test]
fn verifier_rejects_changed_immutable_request_correlation() {
    let mut changed = decision(2, true);
    changed.principal = PrincipalSummary::pseudonymize(&[99; 32], b"uid:1000").unwrap();
    let chain = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        changed,
        terminal_outcome(3, WitnessOutcome::Succeeded),
    ]);
    assert!(verify_stream(chain.iter().map(AsRef::as_ref), &genesis_trust()).is_err());

    let mut changed_terminal = terminal_outcome(3, WitnessOutcome::Succeeded);
    changed_terminal.request_digest = [98; 32];
    let chain = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        decision(2, true),
        changed_terminal,
    ]);
    assert!(verify_stream(chain.iter().map(AsRef::as_ref), &genesis_trust()).is_err());
}

#[test]
fn verifier_enforces_required_and_forbidden_stage_fields() {
    let mut missing_id = decision(2, true);
    missing_id.decision_id = None;
    assert!(encode_record(JOURNAL, &missing_id).is_err());

    let mut denied_without_reason = decision(2, false);
    denied_without_reason.reason = None;
    assert!(encode_record(JOURNAL, &denied_without_reason).is_err());

    let mut denied_with_wrong_reason = decision(2, false);
    denied_with_wrong_reason.reason = Some(ReasonCode::ExecutionFailed);
    assert!(encode_record(JOURNAL, &denied_with_wrong_reason).is_err());

    let mut polluted_received = record(1, [0; 32], WitnessStage::RequestReceived);
    polluted_received.result_digest = Some([1; 32]);
    assert!(encode_record(JOURNAL, &polluted_received).is_err());

    let mut polluted_outcome = terminal_outcome(3, WitnessOutcome::Succeeded);
    polluted_outcome.rule = Some(RuleSummary::from_id([4; 16]));
    assert!(encode_record(JOURNAL, &polluted_outcome).is_err());

    let received =
        encode_record(JOURNAL, &record(1, [0; 32], WitnessStage::RequestReceived)).unwrap();
    let mut invalid_decision = received.as_ref().to_vec();
    invalid_decision[290] = WitnessStage::Decision as u8;
    assert!(decode_record(&invalid_decision).is_err());
}

#[test]
fn principal_and_resource_pseudonyms_are_keyed_and_purpose_separated() {
    let key = [42; 32];
    let canary = b"/srv/private/SECRET_CANARY";
    let principal = PrincipalSummary::pseudonymize(&key, canary).unwrap();
    let resource = ResourceSummary::pseudonymize(&key, canary).unwrap();
    assert_ne!(format!("{principal:?}"), format!("{resource:?}"));

    let mut value = record(1, [0; 32], WitnessStage::RequestReceived);
    value.principal = principal;
    value.resource = resource;
    let bytes = encode_record(JOURNAL, &value).unwrap();
    assert!(!bytes
        .as_ref()
        .windows(canary.len())
        .any(|window| window == canary));
    assert!(PrincipalSummary::pseudonymize(&[1; 16], canary).is_err());
    assert!(ResourceSummary::pseudonymize(&[1; 16], canary).is_err());
}

#[test]
fn recovery_links_unknown_outcome_and_preserves_decision() {
    let unknown = terminal_outcome(3, WitnessOutcome::OutcomeUnknown);
    let mut recovery = record(4, [0; 32], WitnessStage::Recovery);
    recovery.decision_id = Some([11; 16]);
    recovery.result_digest = Some([15; 32]);
    recovery.reason = Some(ReasonCode::RecoveryCompleted);
    recovery.outcome = WitnessOutcome::Recovered;
    recovery.recovery_link = Some(unknown.event_id);
    let legal = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        decision(2, true),
        unknown,
        recovery,
    ]);
    assert!(verify_stream(legal.iter().map(AsRef::as_ref), &genesis_trust()).is_ok());
}

#[test]
fn seeded_secrets_never_enter_encoded_records_or_errors() {
    let secret = "SECRET_SEED_DO_NOT_STORE";
    let mut value = record(1, [0; 32], WitnessStage::RequestReceived);
    value.correlation_digest = Some(
        ferro_core::witness::pseudonymize(b"purpose/request", &[42; 32], secret.as_bytes())
            .unwrap(),
    );
    let bytes = encode_record(JOURNAL, &value).unwrap();
    assert!(!bytes
        .as_ref()
        .windows(secret.len())
        .any(|window| window == secret.as_bytes()));
    assert!(!format!(
        "{:?}",
        decode_record(&bytes.as_ref()[..bytes.as_ref().len() - 1]).unwrap_err()
    )
    .contains(secret));
}

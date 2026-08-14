use ferro_core::witness::{
    decode_record, encode_record, hash_record, verify_stream, DisclosureClass, Invocation,
    RecordBytes, StreamTrust, WitnessOutcome, WitnessRecord, WitnessStage, FORMAT_VERSION,
};

fn record(sequence: u64, previous_hash: [u8; 32], stage: WitnessStage) -> WitnessRecord {
    WitnessRecord {
        sequence,
        previous_hash,
        event_id: [sequence as u8; 16],
        request_id: [7; 16],
        runtime_instance_id: [8; 16],
        boot_id: [9; 16],
        principal: "uid:1000@userns:4026531837".into(),
        invocation: Invocation::Cli,
        action: "container.create".into(),
        resource_kind: 1,
        resource_id: "container:018f".into(),
        resource_generation: 3,
        policy_version: 12,
        policy_digest: [10; 32],
        decision_id: Some([11; 16]),
        rule: Some("developer-create".into()),
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

fn encoded_chain(mut records: Vec<WitnessRecord>) -> Vec<RecordBytes> {
    let journal = [6; 16];
    let mut previous = [0; 32];
    for record in &mut records {
        record.previous_hash = previous;
        let bytes = encode_record(journal, record).unwrap();
        previous = hash_record(journal, bytes.as_ref());
    }
    records
        .iter()
        .map(|record| encode_record(journal, record).unwrap())
        .collect()
}

#[test]
fn golden_scalar_vector_is_stable_and_round_trips_exact_bytes() {
    let bytes = encode_record([6; 16], &record(1, [0; 32], WitnessStage::RequestReceived)).unwrap();
    assert_eq!(bytes.as_ref()[0], FORMAT_VERSION);
    assert_eq!(&bytes.as_ref()[2..18], &[6; 16]);
    assert_eq!(&bytes.as_ref()[18..26], &1_u64.to_be_bytes());
    assert_eq!(&bytes.as_ref()[122..124], &26_u16.to_be_bytes());
    let decoded = decode_record(bytes.as_ref()).unwrap();
    assert_eq!(decoded.journal_id(), &[6; 16]);
    assert_eq!(
        decoded.record(),
        &record(1, [0; 32], WitnessStage::RequestReceived)
    );
    assert_eq!(decoded.bytes().as_ref(), bytes.as_ref());
    assert_eq!(
        hash_record([6; 16], bytes.as_ref()),
        [
            47, 158, 240, 63, 128, 56, 133, 198, 195, 77, 242, 186, 207, 236, 246, 209, 68, 133,
            157, 244, 16, 239, 111, 98, 228, 105, 216, 56, 5, 27, 54, 241,
        ]
    );
}

#[test]
fn decoder_rejects_unknown_noncanonical_and_unbounded_values() {
    let bytes = encode_record([6; 16], &record(1, [0; 32], WitnessStage::RequestReceived)).unwrap();
    let mut unknown = bytes.as_ref().to_vec();
    unknown[1] = 99;
    assert!(decode_record(&unknown).is_err());

    let mut trailing = bytes.as_ref().to_vec();
    trailing.push(0);
    assert!(decode_record(&trailing).is_err());

    let mut invalid_utf8 = bytes.as_ref().to_vec();
    invalid_utf8[124] = 0xff;
    assert!(decode_record(&invalid_utf8).is_err());

    let mut unknown_optional_tag = bytes.as_ref().to_vec();
    // decision-id tag follows both policy u64 fields and the policy digest.
    let decision_tag =
        124 + 26 + 1 + 2 + "container.create".len() + 1 + 2 + "container:018f".len() + 8 + 8 + 32;
    unknown_optional_tag[decision_tag] = 2;
    assert!(decode_record(&unknown_optional_tag).is_err());

    let mut overlong = record(1, [0; 32], WitnessStage::RequestReceived);
    overlong.principal = "p".repeat(257);
    assert!(encode_record([6; 16], &overlong).is_err());
}

#[test]
fn denied_and_allowed_lifecycles_are_accepted() {
    let mut decision = record(2, [0; 32], WitnessStage::Decision);
    decision.decision = Some(false);
    let mut denied = record(3, [0; 32], WitnessStage::Denied);
    denied.outcome = WitnessOutcome::Denied;
    let denied_chain = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        decision,
        denied,
    ]);
    let report = verify_stream(
        denied_chain.iter().map(|bytes| bytes.as_ref()),
        &StreamTrust::new([6; 16]),
    )
    .unwrap();
    assert!(report.lifecycle_consistent);
    assert_eq!(report.terminal_denied, 1);

    let mut allow = record(2, [0; 32], WitnessStage::Decision);
    allow.decision = Some(true);
    let mut outcome = record(3, [0; 32], WitnessStage::Outcome);
    outcome.outcome = WitnessOutcome::Succeeded;
    let allowed_chain = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        allow,
        outcome,
    ]);
    assert!(verify_stream(
        allowed_chain.iter().map(|bytes| bytes.as_ref()),
        &StreamTrust::new([6; 16])
    )
    .is_ok());
}

#[test]
fn verifier_rejects_duplicate_decisions_gaps_and_cross_journal_links() {
    let mut decision = record(2, [0; 32], WitnessStage::Decision);
    decision.decision = Some(true);
    let duplicate = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        decision.clone(),
        {
            let mut duplicate = decision;
            duplicate.sequence = 3;
            duplicate
        },
    ]);
    assert!(verify_stream(
        duplicate.iter().map(|bytes| bytes.as_ref()),
        &StreamTrust::new([6; 16])
    )
    .is_err());

    let gaps = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        record(3, [0; 32], WitnessStage::Decision),
    ]);
    assert!(verify_stream(
        gaps.iter().map(|bytes| bytes.as_ref()),
        &StreamTrust::new([6; 16])
    )
    .is_err());

    let foreign =
        encode_record([5; 16], &record(1, [0; 32], WitnessStage::RequestReceived)).unwrap();
    assert!(verify_stream([foreign.as_ref()], &StreamTrust::new([6; 16])).is_err());

    let valid = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        {
            let mut value = record(2, [0; 32], WitnessStage::Decision);
            value.decision = Some(false);
            value
        },
        {
            let mut value = record(3, [0; 32], WitnessStage::Denied);
            value.outcome = WitnessOutcome::Denied;
            value
        },
    ]);
    let mut damaged = valid[1].as_ref().to_vec();
    damaged[26] ^= 1;
    assert!(verify_stream(
        [valid[0].as_ref(), damaged.as_slice(), valid[2].as_ref()],
        &StreamTrust::new([6; 16])
    )
    .is_err());
}

#[test]
fn recovery_must_link_the_unknown_outcome_from_the_same_request() {
    let mut allow = record(2, [0; 32], WitnessStage::Decision);
    allow.decision = Some(true);
    let mut unknown = record(3, [0; 32], WitnessStage::Outcome);
    unknown.outcome = WitnessOutcome::OutcomeUnknown;
    let unknown_event = unknown.event_id;
    let mut recovery = record(4, [0; 32], WitnessStage::Recovery);
    recovery.outcome = WitnessOutcome::Recovered;
    recovery.recovery_link = Some(unknown_event);
    let legal = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        allow.clone(),
        unknown.clone(),
        recovery.clone(),
    ]);
    assert!(verify_stream(
        legal.iter().map(|bytes| bytes.as_ref()),
        &StreamTrust::new([6; 16])
    )
    .is_ok());

    recovery.recovery_link = Some([99; 16]);
    let illegal = encoded_chain(vec![
        record(1, [0; 32], WitnessStage::RequestReceived),
        allow,
        unknown,
        recovery,
    ]);
    assert!(verify_stream(
        illegal.iter().map(|bytes| bytes.as_ref()),
        &StreamTrust::new([6; 16])
    )
    .is_err());
}

#[test]
fn seeded_secrets_never_enter_encoded_records_or_errors() {
    let secret = "SECRET_SEED_DO_NOT_STORE";
    let mut value = record(1, [0; 32], WitnessStage::RequestReceived);
    value.correlation_digest = Some(
        ferro_core::witness::pseudonymize(b"purpose/request", &[42; 32], secret.as_bytes())
            .unwrap(),
    );
    let bytes = encode_record([6; 16], &value).unwrap();
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

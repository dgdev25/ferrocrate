use ferro_mgr::proto::DesiredState;
use prost::Message;

#[test]
fn v1_messages_ignore_unknown_fields_without_changing_known_values() {
    let state = DesiredState {
        cluster_id: "cluster-a".into(),
        cluster_epoch: 7,
        revision: 42,
        overlays: Vec::new(),
        signature: vec![1, 2],
        lease_expires_unix: 99,
    };
    let mut encoded = state.encode_to_vec();
    encoded.extend_from_slice(&[0x38, 0x01]);
    let decoded = DesiredState::decode(encoded.as_slice()).expect("decode v1 plus unknown field");
    assert_eq!(decoded.cluster_id, state.cluster_id);
    assert_eq!(decoded.cluster_epoch, state.cluster_epoch);
    assert_eq!(decoded.revision, state.revision);
    assert_eq!(decoded.signature, state.signature);
}

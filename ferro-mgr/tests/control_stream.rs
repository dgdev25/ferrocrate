use ferro_mgr::{control::{ControlError, ControlServiceImpl}, desired_state::{DesiredStateBuilder, MAX_LEASE_SECONDS}, proto::{AgentMessage, OverlayState}};

#[test]
fn duplicate_sessions_and_revision_gaps_are_bounded() {
    let service = ControlServiceImpl::new("cluster-a", 4);
    service.publish_revision(70);
    let session = service.connect("node-a", "cluster-a", 4).unwrap();
    assert!(matches!(service.connect("node-a", "cluster-a", 4), Err(ControlError::DuplicateSession)));
    let message = AgentMessage { node_id: "node-a".into(), acknowledged_revision: 4, payload: Vec::new() };
    assert_eq!(session.receive(&message).unwrap_err(), ControlError::QueueFull);
}

#[test]
fn leases_are_capped_at_fifteen_minutes_and_identified() {
    let builder = DesiredStateBuilder::new("cluster-a", 9, vec![3; 32]);
    let state = builder.snapshot(7, vec![OverlayState { overlay_id: "ov-a".into(), routes: vec![], peers: vec![], wireguard: Some(true), addresses: vec!["10.0.0.1/24".into()] }], 100);
    assert_eq!(state.cluster_id, "cluster-a");
    assert_eq!(state.lease_expires_unix, 100 + MAX_LEASE_SECONDS);
    assert_eq!(state.signature.len(), 64);
}

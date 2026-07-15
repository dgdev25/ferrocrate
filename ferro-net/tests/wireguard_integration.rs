use ferro_net::wireguard::{WireGuardError, WireGuardPeer};

fn key() -> String {
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()
}

#[test]
fn peer_rejects_default_route_when_not_authorized() {
    let peer = WireGuardPeer::new(
        "node-a".to_string(),
        key(),
        "198.51.100.7:51820".parse().unwrap(),
        vec!["0.0.0.0/0".parse().unwrap()],
    );
    let assigned = vec!["10.44.0.0/24".parse().unwrap()];
    assert!(matches!(
        peer.validate(&assigned),
        Err(WireGuardError::RouteOutsideAllocation(_))
    ));
}

#[test]
fn peer_accepts_only_routes_inside_the_assigned_overlay() {
    let peer = WireGuardPeer::new(
        "node-a".to_string(),
        key(),
        "198.51.100.7:51820".parse().unwrap(),
        vec!["10.44.0.2/32".parse().unwrap()],
    );
    assert!(peer
        .validate(&["10.44.0.0/24".parse().unwrap()])
        .is_ok());
}

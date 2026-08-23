use super::*;
#[test]
fn exact_receipts_reject_each_partial_kernel_field() {
    use crate::{effect_receipt::EffectReceipt, protocol::NetdRequest};
    let directory = tempfile::tempdir().unwrap();
    let mut kernel = PersistentKernelOps::open(directory.path().join("kernel.json"));
    let peers = vec![PeerSpec {
        node_id: "node-b".into(),
        public_key: "peer-key".into(),
        endpoint: "127.0.0.1:51820".into(),
        allowed_ips: vec!["10.1.0.0/24".into()],
    }];
    let routes = vec!["10.1.0.0/24".into()];
    let addresses = vec!["10.1.0.1/24".into()];
    let request = NetdRequest::ApplyOverlay {
        overlay_id: "wg0".into(),
        mode: crate::protocol::OverlayMode::WireGuard,
        peers: peers.clone(),
        routes: routes.clone(),
        addresses: addresses.clone(),
    };
    let receipt = EffectReceipt::from_request(&request, 7, 1, 9);
    let interfaces = crate::interface_identity::overlay_interfaces("wg0");
    kernel.create_overlay(&interfaces.bridge).unwrap();
    kernel
        .apply_wireguard(&interfaces.wireguard, &[], &peers)
        .unwrap();
    kernel
        .apply_addresses(&interfaces.wireguard, &addresses)
        .unwrap();
    kernel.apply_routes(&interfaces.wireguard, &routes).unwrap();
    kernel.ensure_forwarding().unwrap();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Exact
    );
    kernel
        .state
        .wireguard
        .get_mut(&interfaces.wireguard)
        .unwrap()
        .1
        .clear();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Mismatch
    );
    kernel
        .state
        .wireguard
        .insert(interfaces.wireguard.clone(), (Vec::new(), peers.clone()));
    kernel
        .state
        .addresses
        .get_mut(&interfaces.wireguard)
        .unwrap()
        .clear();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Mismatch
    );
    kernel
        .state
        .wireguard
        .insert(interfaces.wireguard.clone(), (Vec::new(), peers));
    kernel
        .state
        .addresses
        .insert(interfaces.wireguard.clone(), addresses);
    kernel
        .state
        .routes
        .get_mut(&interfaces.wireguard)
        .unwrap()
        .clear();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Mismatch
    );
    let endpoint = EffectReceipt::from_request(
        &NetdRequest::AttachEndpoint {
            overlay_id: "wg0".into(),
            endpoint_id: "ep0".into(),
            netns: None,
        },
        8,
        1,
        10,
    );
    kernel.state.links.insert("ep0".into());
    kernel
        .state
        .masters
        .insert("ep0".into(), interfaces.bridge.clone());
    assert_eq!(
        kernel.observe_effect(&endpoint),
        LiveEffectObservation::Exact
    );
    kernel.state.masters.insert("ep0".into(), "wrong".into());
    assert_eq!(
        kernel.observe_effect(&endpoint),
        LiveEffectObservation::Mismatch
    );
}
#[test]
fn topology_uses_distinct_link_kinds_and_bridge_master_in_order() {
    let directory = tempfile::tempdir().unwrap();
    let mut kernel = PersistentKernelOps::open(directory.path().join("kernel.json"));
    let interfaces = crate::interface_identity::overlay_interfaces("customer-overlay");
    kernel.create_overlay("same-name").unwrap();
    assert!(kernel.apply_wireguard("same-name", &[], &[]).is_err());
    kernel.create_overlay(&interfaces.bridge).unwrap();
    kernel
        .apply_wireguard(&interfaces.wireguard, &[], &[])
        .unwrap();
    kernel.ensure_forwarding().unwrap();
    kernel
        .apply_addresses(&interfaces.bridge, &["10.9.0.1/24".into()])
        .unwrap();
    kernel
        .apply_routes(&interfaces.wireguard, &["10.9.0.0/24".into()])
        .unwrap();
    kernel
        .create_endpoint(&VethConfig {
            pair: ferro_net::veth::VethPair {
                host: "ep-topology".into(),
                container: "fc-ep-topology".into(),
            },
            mtu: None,
            host_addr: None,
            container_addr: None,
        })
        .unwrap();
    kernel
        .attach_endpoint("ep-topology", &interfaces.bridge)
        .unwrap();
    assert_eq!(kernel.state.masters["ep-topology"], interfaces.bridge);
    let ordered = kernel.state.events.join(";");
    assert!(ordered.contains(&format!(
        "type bridge;ip link add {} type wireguard;wg set {};sysctl net.ipv4.ip_forward=1;ip address replace dev {};ip route replace dev {}",
        interfaces.wireguard, interfaces.wireguard, interfaces.bridge, interfaces.wireguard
    )));
}
#[test]
fn removal_receipt_requires_both_topology_links_absent() {
    use crate::{effect_receipt::EffectReceipt, protocol::NetdRequest};
    let directory = tempfile::tempdir().unwrap();
    let mut kernel = PersistentKernelOps::open(directory.path().join("kernel.json"));
    let interfaces = crate::interface_identity::overlay_interfaces("overlay-delete");
    let receipt = EffectReceipt::from_request(
        &NetdRequest::RemoveOverlay {
            overlay_id: "overlay-delete".into(),
        },
        3,
        2,
        4,
    );
    kernel
        .apply_wireguard(&interfaces.wireguard, &[], &[])
        .unwrap();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Mismatch
    );
    kernel.remove_wireguard(&interfaces.wireguard).unwrap();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Exact
    );
}

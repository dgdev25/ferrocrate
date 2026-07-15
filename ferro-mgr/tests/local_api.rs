use ferro_mgr::agent::{ipam::{Ipam, IpamError}, local_api::{LocalApi, LocalApiError, OverlayConfig}};

#[test]
fn ipam_allocates_lowest_address_and_rejects_duplicates() {
    let pool = "10.1.0.0/29".parse().unwrap();
    let ipam = Ipam::new(pool, "10.1.0.1".parse().unwrap(), vec!["10.1.0.2".parse().unwrap()]).unwrap();
    assert_eq!(ipam.allocate("c1").unwrap().address.to_string(), "10.1.0.3");
    assert_eq!(ipam.allocate("c1"), Err(IpamError::DuplicateContainer));
}

#[test]
fn local_api_requires_uid_and_current_lease() {
    let ipam = Ipam::new("10.2.0.0/29".parse().unwrap(), "10.2.0.1".parse().unwrap(), vec![]).unwrap();
    let api = LocalApi::new(1001, 200, ipam);
    assert_eq!(api.attach(2002, "overlay", "c1", 100), Err(LocalApiError::Unauthorized));
    assert_eq!(api.attach(1001, "overlay", "c1", 200), Err(LocalApiError::Expired));
    assert!(api.attach(1001, "overlay", "c1", 100).is_ok());
    assert!(api.detach(1001, "c1", 100).unwrap().is_some());
    assert!(api.detach(1001, "c1", 100).unwrap().is_none());
}

#[test]
fn ipam_state_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ipam.json");
    let pool = "10.3.0.0/29".parse().unwrap();
    let first = Ipam::with_state(pool, "10.3.0.1".parse().unwrap(), vec![], &path).unwrap();
    assert_eq!(first.allocate("c1").unwrap().address.to_string(), "10.3.0.2");
    drop(first);
    let second = Ipam::with_state(pool, "10.3.0.1".parse().unwrap(), vec![], path).unwrap();
    assert_eq!(second.allocate("c2").unwrap().address.to_string(), "10.3.0.3");
}

#[test]
fn local_api_rejects_unknown_overlay_after_authorization_registry_is_enabled() {
    let ipam = Ipam::new("10.4.0.0/29".parse().unwrap(), "10.4.0.1".parse().unwrap(), vec![]).unwrap();
    let api = LocalApi::new(1001, 200, ipam);
    api.register_overlay("managed", OverlayConfig { bridge: "fc-managed".into(), gateway: "10.4.0.1".parse().unwrap(), prefix: 24, mtu: 1420 }).unwrap();
    assert_eq!(api.attach(1001, "other", "c1", 100), Err(LocalApiError::UnknownOverlay));
    let attachment = api.attach(1001, "managed", "c1", 100).unwrap();
    assert_eq!(attachment.bridge, "fc-managed");
    assert_eq!(attachment.mtu, 1420);
}

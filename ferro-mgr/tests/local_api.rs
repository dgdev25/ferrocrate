use ferro_mgr::agent::{ipam::{Ipam, IpamError}, local_api::{LocalApi, LocalApiError}};

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

#![cfg(target_os = "linux")]
#![cfg(target_os = "linux")]

use std::os::unix::net::UnixStream;

use ferro_core::authorization::{
    DelegatedPrincipal, DelegationPolicy, InvocationChannel, PrincipalResolver,
};

#[test]
fn peer_credentials_bind_the_host_visible_process_identity() {
    let (peer, _other_end) = UnixStream::pair().expect("Unix socket pair");

    let transport = PrincipalResolver::from_peer_credentials(&peer).expect("peer identity");
    let identity = transport.identity();

    assert_eq!(identity.pid(), std::process::id());
    assert_eq!(identity.effective_uid(), nix::unistd::geteuid().as_raw());
    assert_eq!(identity.effective_gid(), nix::unistd::getegid().as_raw());
    assert!(identity.start_time_ticks() > 0);
    assert!(!identity.boot_id().is_empty());
    assert!(identity.user_namespace_inode() > 0);
    assert!(!identity.uid_map().is_empty());
    assert!(!identity.gid_map().is_empty());
    assert_eq!(transport.channel(), InvocationChannel::DockerUnix);
}

#[test]
fn untrusted_cri_metadata_never_replaces_the_transport_principal() {
    let (peer, _other_end) = UnixStream::pair().expect("Unix socket pair");
    let transport = PrincipalResolver::from_peer_credentials(&peer).expect("transport identity");
    let transport_id = transport.principal().id().as_str().to_owned();
    let transport_role = transport.principal().role();
    let assertion = DelegatedPrincipal::from_untrusted_cri_metadata(
        "system:serviceaccount:tenant:administrator",
    );

    let effective = PrincipalResolver::resolve_proxy(
        transport,
        Some(assertion),
        &DelegationPolicy::transport_only(),
    );

    assert_eq!(effective.principal().id().as_str(), transport_id);
    assert_eq!(effective.principal().role(), transport_role);
    assert!(!effective.used_delegation());
    assert_eq!(
        effective
            .delegated()
            .expect("delegated identity remains telemetry")
            .asserted_id(),
        "system:serviceaccount:tenant:administrator"
    );
}

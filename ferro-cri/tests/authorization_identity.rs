use ferro_cri::server::{CriIdentityPolicy, DelegationAssertion, DelegationVerifier};

struct Reject;
impl DelegationVerifier for Reject {
    fn verify(&self, _: &DelegationAssertion) -> bool {
        false
    }
}
struct Accept;
impl DelegationVerifier for Accept {
    fn verify(&self, _: &DelegationAssertion) -> bool {
        true
    }
}

#[test]
fn transport_is_authoritative_by_default_and_metadata_cannot_elevate() {
    let policy = CriIdentityPolicy::transport_only("cri:kubelet");
    let effective = policy
        .resolve(Some(DelegationAssertion::untrusted("root")))
        .unwrap();
    assert_eq!(effective.transport_id(), "cri:kubelet");
    assert_eq!(effective.delegated_id(), Some("root"));
    assert_eq!(effective.effective_id(), "cri:kubelet");
    assert!(!effective.used_delegation());
}

#[test]
fn rejected_integrity_assertion_cannot_replace_transport() {
    let policy = CriIdentityPolicy::with_verifier("cri:kubelet", "root-a", Box::new(Reject));
    let effective = policy
        .resolve(Some(DelegationAssertion::protected(
            "alice",
            vec![1],
            "root-a",
        )))
        .unwrap();
    assert_eq!(effective.effective_id(), "cri:kubelet");
}

#[test]
fn authenticated_integrity_protected_configured_delegation_becomes_effective() {
    let policy = CriIdentityPolicy::with_verifier("cri:kubelet", "root-a", Box::new(Accept));
    let effective = policy
        .resolve(Some(DelegationAssertion::protected(
            "alice",
            vec![1],
            "root-a",
        )))
        .unwrap();
    assert_eq!(effective.transport_id(), "cri:kubelet");
    assert_eq!(effective.delegated_id(), Some("alice"));
    assert_eq!(effective.effective_id(), "alice");
    assert!(effective.used_delegation());
}

#[test]
fn wrong_trust_root_is_rejected_even_with_accepting_verifier() {
    let policy = CriIdentityPolicy::with_verifier("cri:kubelet", "root-a", Box::new(Accept));
    let effective = policy
        .resolve(Some(DelegationAssertion::protected(
            "alice",
            vec![1],
            "root-b",
        )))
        .unwrap();
    assert_eq!(effective.effective_id(), "cri:kubelet");
}

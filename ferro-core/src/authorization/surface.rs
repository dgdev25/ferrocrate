//! Complete-mediation adapter for non-container entry-point mutations.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::gate::{
    AuthorizationGate, AuthorizedRequest, CanonicalRequest, Denial, ExecutionBindings,
};
use super::policy::PolicyStore;
use super::{Action, RequestContext, RequestFacts, RequestOrigin, Resource, ResourceKind};

#[derive(Debug, thiserror::Error)]
pub enum SurfaceAuthorizationError {
    #[error("request transport identity is stale: {0}")]
    StaleIdentity(#[from] super::PrincipalResolutionError),
    #[error(transparent)]
    Denied(#[from] Denial),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SurfaceExecutionError {
    #[error("authorization permit action does not match executor")]
    ActionMismatch,
    #[error("authorization permit resource does not match executor")]
    ResourceMismatch,
    #[error("authorization permit generation does not match executor")]
    GenerationMismatch,
}

#[derive(Debug)]
pub struct SurfaceAuthorization {
    gate: AuthorizationGate,
}

impl SurfaceAuthorization {
    pub fn compatibility() -> Self {
        Self {
            gate: AuthorizationGate::new(Arc::new(PolicyStore::compatibility_disabled())),
        }
    }

    pub fn with_gate(gate: AuthorizationGate) -> Self {
        Self { gate }
    }

    pub fn authorize_image_binding(
        &self,
        origin: &RequestOrigin,
        action: Action,
        canonical_name: &str,
        digest: &str,
        generation: u64,
    ) -> Result<AuthorizedRequest, SurfaceAuthorizationError> {
        origin.revalidate_transport()?;
        debug_assert!(matches!(action, Action::ImagePull | Action::ImageDelete));
        let resource_id = stable_resource_id(ResourceKind::Image, canonical_name);
        let pinned_reference = format!("{canonical_name}@{digest}");
        let resource =
            Resource::canonical(ResourceKind::Image, resource_id.clone(), None, generation);
        let facts = RequestFacts {
            image_digest: Some(digest.to_owned()),
            ..RequestFacts::default()
        };
        let context = RequestContext::resolved(
            request_id(&resource_id, action),
            Some(origin.principal().clone()),
            action,
            resource,
            facts,
        );
        let binding = super::gate::ImageBinding::new(pinned_reference, digest);
        let bindings = ExecutionBindings::new(Some(binding), generation, None, None, Vec::new());
        let request = CanonicalRequest::new(context, self.gate.pin(), bindings.clone(), bindings);
        Ok(self.gate.authorize(request)?)
    }

    pub fn authorize_named(
        &self,
        origin: &RequestOrigin,
        action: Action,
        kind: ResourceKind,
        canonical_name: &str,
        generation: u64,
    ) -> Result<AuthorizedRequest, SurfaceAuthorizationError> {
        origin.revalidate_transport()?;
        let resource_id = stable_resource_id(kind, canonical_name);
        let resource = Resource::canonical(kind, resource_id.clone(), None, generation);
        let context = RequestContext::resolved(
            request_id(&resource_id, action),
            Some(origin.principal().clone()),
            action,
            resource,
            RequestFacts::default(),
        );
        let bindings = ExecutionBindings::new(None, generation, None, None, Vec::new());
        let request = CanonicalRequest::new(context, self.gate.pin(), bindings.clone(), bindings);
        Ok(self.gate.authorize(request)?)
    }

    pub fn validate_execution(
        proof: &AuthorizedRequest,
        action: Action,
        kind: ResourceKind,
        canonical_name: &str,
        generation: u64,
    ) -> Result<(), SurfaceExecutionError> {
        if proof.canonical().context().action() != action {
            return Err(SurfaceExecutionError::ActionMismatch);
        }
        if proof.canonical().context().resource().kind() != kind
            || proof.canonical().resource_id() != stable_resource_id(kind, canonical_name)
        {
            return Err(SurfaceExecutionError::ResourceMismatch);
        }
        if proof.canonical().resource_generation() != generation {
            return Err(SurfaceExecutionError::GenerationMismatch);
        }
        Ok(())
    }
}

fn stable_resource_id(kind: ResourceKind, canonical_name: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(
        [
            b"ferrocrate/surface-resource/v1".as_slice(),
            format!("{kind:?}").as_bytes(),
            canonical_name.as_bytes(),
        ]
        .concat(),
    )
    .into();
    uuid(&digest)
}

fn request_id(resource_id: &str, action: Action) -> String {
    hex(&Sha256::digest(
        [
            b"ferrocrate/surface-request/v1".as_slice(),
            resource_id.as_bytes(),
            format!("{action:?}").as_bytes(),
        ]
        .concat(),
    )[..16])
}

fn uuid(bytes: &[u8; 32]) -> String {
    let value = hex(&bytes[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &value[..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..32]
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn origin() -> RequestOrigin {
        RequestOrigin::cli_current().expect("current CLI identity")
    }

    #[test]
    fn image_authorization_binds_the_immutable_digest() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let proof = SurfaceAuthorization::compatibility()
            .authorize_image_binding(
                &origin(),
                Action::ImagePull,
                "registry.example/acme/app:latest",
                &digest,
                7,
            )
            .expect("authorized image");

        assert_eq!(proof.canonical().image_digest(), Some(digest.as_str()));
        assert_eq!(proof.canonical().resource_generation(), 7);
        assert_eq!(proof.canonical().context().action(), Action::ImagePull);
    }

    #[test]
    fn named_resources_have_kind_separated_stable_ids() {
        let auth = SurfaceAuthorization::compatibility();
        let volume = auth
            .authorize_named(
                &origin(),
                Action::VolumeCreate,
                ResourceKind::Volume,
                "data",
                3,
            )
            .expect("authorized volume");
        let volume_again = auth
            .authorize_named(
                &origin(),
                Action::VolumeDelete,
                ResourceKind::Volume,
                "data",
                3,
            )
            .expect("authorized volume");
        let network = auth
            .authorize_named(
                &origin(),
                Action::NetworkCreate,
                ResourceKind::Network,
                "data",
                3,
            )
            .expect("authorized network");

        assert_eq!(
            volume.canonical().resource_id(),
            volume_again.canonical().resource_id()
        );
        assert_ne!(
            volume.canonical().resource_id(),
            network.canonical().resource_id()
        );
        assert_eq!(volume.canonical().resource_generation(), 3);
    }

    #[test]
    fn executor_binding_rejects_a_permit_for_another_resource() {
        let auth = SurfaceAuthorization::compatibility();
        let proof = auth
            .authorize_named(
                &origin(),
                Action::VolumeCreate,
                ResourceKind::Volume,
                "other",
                1,
            )
            .expect("authorized volume");

        let error = SurfaceAuthorization::validate_execution(
            &proof,
            Action::VolumeCreate,
            ResourceKind::Volume,
            "data",
            1,
        )
        .expect_err("resource substitution must fail");
        assert_eq!(error, SurfaceExecutionError::ResourceMismatch);
    }
}

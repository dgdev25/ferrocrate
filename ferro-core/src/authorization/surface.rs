//! Complete-mediation adapter for non-container entry-point mutations.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::gate::{
    AuthorizationGate, AuthorizedRequest, CanonicalRequest, Denial, ExecutionBindings,
};
use super::policy::PolicyStore;
use super::{Action, RequestContext, RequestFacts, RequestOrigin, Resource, ResourceKind};

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

    pub fn authorize_image(
        &self,
        origin: &RequestOrigin,
        action: Action,
        canonical_name: &str,
    ) -> Result<AuthorizedRequest, Denial> {
        debug_assert!(matches!(action, Action::ImagePull | Action::ImageDelete));
        let mut digest: [u8; 32] = Sha256::digest(
            [
                b"ferrocrate/image-resource/v1".as_slice(),
                canonical_name.as_bytes(),
            ]
            .concat(),
        )
        .into();
        digest[6] = (digest[6] & 0x0f) | 0x40;
        digest[8] = (digest[8] & 0x3f) | 0x80;
        let resource = Resource::canonical(ResourceKind::Image, uuid(&digest), None, 1);
        let context = RequestContext::resolved(
            hex(&digest[..16]),
            Some(origin.principal().clone()),
            action,
            resource,
            RequestFacts::default(),
        );
        let bindings = ExecutionBindings::new(None, 1, None, None, Vec::new());
        let request = CanonicalRequest::new(context, self.gate.pin(), bindings.clone(), bindings);
        self.gate.authorize(request)
    }
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

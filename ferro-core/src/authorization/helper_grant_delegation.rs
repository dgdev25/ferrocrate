use super::helper_grant::{
    GrantAction, GrantBuildError, GrantClaims, GrantIssuer, GrantKind, GrantParameters,
    HelperGrant, ResourceBinding, VerifiedHelperGrant,
};

impl GrantIssuer {
    #[allow(clippy::too_many_arguments)]
    pub fn delegate_child(
        &self,
        parent: &VerifiedHelperGrant,
        child_request_id: &str,
        action: GrantAction,
        resource: ResourceBinding,
        parameters: &GrantParameters,
        wall_deadline_secs: u64,
        monotonic_deadline_millis: u64,
        nonce: [u8; 16],
    ) -> Result<HelperGrant, GrantBuildError> {
        let parent_claims = parent.claims();
        if parent_claims.kind != GrantKind::Mutation
            || parent_claims.action != action
            || resource != parent_claims.resource
            || wall_deadline_secs > parent_claims.wall_deadline_secs
            || monotonic_deadline_millis > parent_claims.monotonic_deadline_millis
        {
            return Err(GrantBuildError::IntentMismatch);
        }
        let mut claims = GrantClaims::new(
            child_request_id,
            action,
            resource,
            parameters.digest(),
            &parent_claims.boot_id,
            wall_deadline_secs,
            monotonic_deadline_millis,
            nonce,
            &parent_claims.issuer,
            &self.key_id,
            GrantKind::Mutation,
        )?;
        claims.operation_id = parent_claims.operation_id;
        claims.request_digest = parent_claims.request_digest;
        claims.precondition_digest = parent_claims.precondition_digest;
        claims.recovery_recipe_digest = parent_claims.recovery_recipe_digest;
        Ok(self.sign(claims))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn delegate_cleanup(
        &self,
        parent: &VerifiedHelperGrant,
        child_request_id: &str,
        action: GrantAction,
        resource: ResourceBinding,
        parameters: &GrantParameters,
        origin_request_id: &str,
        live_identity_digest: [u8; 32],
        wall_deadline_secs: u64,
        monotonic_deadline_millis: u64,
        nonce: [u8; 16],
    ) -> Result<HelperGrant, GrantBuildError> {
        let parent_claims = parent.claims();
        if !action.is_cleanup()
            || parent_claims.kind != GrantKind::Cleanup
            || parent_claims.action != action
            || resource != parent_claims.resource
            || wall_deadline_secs > parent_claims.wall_deadline_secs
            || monotonic_deadline_millis > parent_claims.monotonic_deadline_millis
        {
            return Err(GrantBuildError::InvalidCleanup);
        }
        let mut claims = GrantClaims::new(
            child_request_id,
            action,
            resource,
            parameters.digest(),
            &parent_claims.boot_id,
            wall_deadline_secs,
            monotonic_deadline_millis,
            nonce,
            &parent_claims.issuer,
            &self.key_id,
            GrantKind::Cleanup,
        )?
        .cleanup(origin_request_id, live_identity_digest)?;
        claims.operation_id = parent_claims.operation_id;
        claims.request_digest = parent_claims.request_digest;
        claims.precondition_digest = parent_claims.precondition_digest;
        claims.recovery_recipe_digest = parent_claims.recovery_recipe_digest;
        Ok(self.sign(claims))
    }
}
